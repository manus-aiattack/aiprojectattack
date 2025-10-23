"""
FastAPI application for dLNk dLNk Framework
Provides REST API for framework operations
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.orchestrator import Orchestrator
from core.logger import log
from core.data_models import Strategy
from config.settings import DEFAULT_WORKFLOW, WORKSPACE_DIR, API_DEBUG
import json

# Initialize FastAPI app
app = FastAPI(
    title="dLNk dLNk API",
    description="REST API for Autonomous Penetration Testing Framework",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global orchestrator instance
orchestrator: Optional[Orchestrator] = None


# Pydantic models
class TargetModel(BaseModel):
    """Target information model"""
    name: str
    url: str
    description: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class WorkflowExecutionRequest(BaseModel):
    """Request model for workflow execution"""
    workflow_path: str = DEFAULT_WORKFLOW
    target: TargetModel


class AgentExecutionRequest(BaseModel):
    """Request model for agent execution"""
    agent_name: str
    directive: str
    context: Optional[Dict[str, Any]] = None


class StatusResponse(BaseModel):
    """Status response model"""
    running: bool
    current_phase: Optional[str]
    agents_registered: int
    results_count: int


# Startup and shutdown events
@app.on_event("startup")
async def startup_event():
    """Initialize orchestrator on startup"""
    global orchestrator
    log.info("Starting dLNk dLNk API...")
    
    try:
        orchestrator = Orchestrator(workspace_dir=WORKSPACE_DIR)
        await orchestrator.initialize()
        log.success("API initialized successfully")
    except Exception as e:
        log.error(f"Failed to initialize API: {e}", exc_info=True)
        raise


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    global orchestrator
    if orchestrator:
        await orchestrator.cleanup()
        log.info("API shutdown complete")


# Dashboard endpoint
@app.get("/")
async def root():
    """Serve the dashboard HTML"""
    dashboard_path = Path(__file__).parent / "dashboard.html"
    if dashboard_path.exists():
        return FileResponse(dashboard_path)
    return {"message": "dLNk dLNk API - Visit /docs for API documentation"}


# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": "1.0.0",
        "framework": "dLNk dLNk"
    }


# Status endpoint
@app.get("/status", response_model=StatusResponse)
async def get_status():
    """Get framework status"""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    
    status = orchestrator.get_status()
    return StatusResponse(**status)


@app.websocket("/ws/logs")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    log.info("WebSocket client connected for logs")
    
    if not orchestrator or not orchestrator.pubsub_manager:
        await websocket.send_json({"level": "error", "message": "Orchestrator or PubSubManager not initialized."})
        await websocket.close()
        return

    pubsub = orchestrator.pubsub_manager.redis.pubsub()
    await pubsub.subscribe("log_stream")

    try:
        while True:
            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if message and message["type"] == "message":
                log_entry = json.loads(message["data"])
                await websocket.send_json(log_entry)
            await asyncio.sleep(0.01)  # Prevent busy-waiting
    except WebSocketDisconnect:
        log.info("WebSocket client disconnected from logs")
    except Exception as e:
        log.error(f"WebSocket error: {e}", exc_info=True)
    finally:
        await pubsub.unsubscribe("log_stream")
        log.info("WebSocket unsubscribed from log_stream")


# Agents endpoints
@app.get("/agents")
async def list_agents():
    """List all available agents"""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    
    agents = orchestrator.get_registered_agents()
    agent_info = []
    
    for agent_name in agents:
        info = orchestrator.get_agent_info(agent_name)
        if info:
            agent_info.append(info)
    
    return {
        "count": len(agent_info),
        "agents": agent_info
    }


@app.get("/agents/{agent_name}")
async def get_agent(agent_name: str):
    """Get information about a specific agent"""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    
    info = orchestrator.get_agent_info(agent_name)
    if not info:
        raise HTTPException(status_code=404, detail=f"Agent {agent_name} not found")
    
    return info


# Workflow endpoints
@app.post("/workflows/execute")
async def execute_workflow(request: WorkflowExecutionRequest, background_tasks: BackgroundTasks):
    """Execute a workflow"""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    
    try:
        target_dict = request.target.dict()
        
        # Run in background
        background_tasks.add_task(
            orchestrator.execute_workflow,
            request.workflow_path,
            target_dict
        )
        
        return {
            "status": "started",
            "message": f"Workflow execution started for target: {request.target.name}",
            "target": request.target.name
        }
    except Exception as e:
        log.error(f"Workflow execution failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# Agent execution endpoints
@app.post("/agents/execute")
async def execute_agent(request: AgentExecutionRequest):
    """Execute a single agent"""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    
    try:
        strategy = Strategy(
            phase="api",
            directive=request.directive,
            context=request.context or {}
        )
        
        result = await orchestrator.execute_agent_directly(request.agent_name, strategy)
        
        return {
            "agent_name": request.agent_name,
            "success": result.success,
            "summary": result.summary,
            "errors": result.errors,
            "data": result.data
        }
    except Exception as e:
        log.error(f"Agent execution failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# Results endpoints
@app.get("/results")
async def get_results():
    """Get all campaign results"""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    
    results = orchestrator.campaign_results
    
    return {
        "count": len(results),
        "results": [r.dict() if hasattr(r, 'dict') else str(r) for r in results]
    }


@app.get("/results/{index}")
async def get_result(index: int):
    """Get a specific result"""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    
    if index < 0 or index >= len(orchestrator.campaign_results):
        raise HTTPException(status_code=404, detail="Result not found")
    
    result = orchestrator.campaign_results[index]
    return result.dict() if hasattr(result, 'dict') else str(result)


# Error handlers
@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """Handle general exceptions"""
    log.error(f"Unhandled exception: {exc}", exc_info=True)
    return {
        "error": "Internal server error",
        "detail": str(exc)
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, debug=API_DEBUG)

