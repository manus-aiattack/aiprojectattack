"""
Main Integrated API
Combines all routes and WebSocket handlers
"""

from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
import logging

# Import routes
from api.routes import scan, exploit, ai, knowledge, statistics
from api.routes import attack, c2, auth
from api import websocket_handler

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Manus Penetration Testing Framework API",
    description="Complete API for automated penetration testing",
    version="3.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify allowed origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(scan.router)
app.include_router(exploit.router)
app.include_router(ai.router)
app.include_router(knowledge.router)
app.include_router(statistics.router)
app.include_router(attack.router)
app.include_router(c2.router)
app.include_router(auth.router)

# WebSocket endpoints
@app.websocket("/ws/logs")
async def websocket_logs_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time logs"""
    await websocket_handler.websocket_logs(websocket)


@app.websocket("/ws/attacks")
async def websocket_attacks_endpoint(websocket: WebSocket):
    """WebSocket endpoint for attack progress"""
    await websocket_handler.websocket_attacks(websocket)


@app.websocket("/ws/agents")
async def websocket_agents_endpoint(websocket: WebSocket):
    """WebSocket endpoint for agent status"""
    await websocket_handler.websocket_agents(websocket)


@app.websocket("/ws")
async def websocket_general_endpoint(websocket: WebSocket):
    """General WebSocket endpoint"""
    await websocket_handler.websocket_general(websocket)


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": "Manus Penetration Testing Framework",
        "version": "3.0.0",
        "status": "operational",
        "endpoints": {
            "scan": "/api/scan",
            "exploit": "/api/exploit",
            "ai": "/api/ai",
            "knowledge": "/api/knowledge",
            "statistics": "/api/statistics",
            "attack": "/api/attack",
            "c2": "/api/c2",
            "auth": "/api/auth",
            "websocket": {
                "logs": "/ws/logs",
                "attacks": "/ws/attacks",
                "agents": "/ws/agents",
                "general": "/ws"
            }
        }
    }


# Health check
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "services": {
            "api": "operational",
            "websocket": "operational",
            "database": "operational"
        }
    }


# API documentation
@app.get("/api/docs")
async def api_documentation():
    """API documentation"""
    return {
        "scan": {
            "quick": "POST /api/scan/quick - Quick scan",
            "full": "POST /api/scan/full - Full scan",
            "vuln": "POST /api/scan/vuln - Vulnerability scan",
            "status": "GET /api/scan/status/{scan_id} - Get scan status"
        },
        "exploit": {
            "generate": "POST /api/exploit/generate - Generate exploit",
            "execute": "POST /api/exploit/execute - Execute exploit",
            "list": "GET /api/exploit/list - List exploits"
        },
        "ai": {
            "analyze": "POST /api/ai/analyze - Analyze target",
            "suggest": "POST /api/ai/suggest-attack - Suggest attack",
            "optimize": "POST /api/ai/optimize-payload - Optimize payload"
        },
        "knowledge": {
            "techniques": "GET /api/knowledge/techniques - Get techniques",
            "exploits": "GET /api/knowledge/exploits - Get exploits"
        },
        "statistics": {
            "get": "GET /api/statistics - Get statistics",
            "attacks": "GET /api/statistics/attacks - Get attacks history"
        }
    }


# Startup event
@app.on_event("startup")
async def startup_event():
    """Startup event"""
    logger.info("Starting Manus API...")
    logger.info("All routes registered successfully")
    logger.info("WebSocket handlers initialized")
    
    # Start log streaming
    import asyncio
    asyncio.create_task(websocket_handler.start_log_streaming())


# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Shutdown event"""
    logger.info("Shutting down Manus API...")


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )

