"""
dLNk dLNk Attack Platform - Backend API
FastAPI application with WebSocket support
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from fastapi.responses import FileResponse
from contextlib import asynccontextmanager
import uvicorn
import asyncio
from typing import List, Dict, Any
from datetime import datetime

from api.services.database import Database
from api.services.auth import AuthService
from api.services.attack_manager import AttackManager
from api.services.websocket_manager import WebSocketManager
from api.routes import auth, admin, attack, files
from core.logger import log


# WebSocket Manager
ws_manager = WebSocketManager()

# Database
db = Database()

# Services
auth_service = AuthService(db)
attack_manager = AttackManager(db, ws_manager)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events"""
    # Startup
    log.info("[API] Starting dLNk dLNk Attack Platform API...")
    await db.connect()
    log.success("[API] Database connected")
    
    yield
    
    # Shutdown
    log.info("[API] Shutting down...")
    await db.disconnect()
    log.info("[API] Database disconnected")


# Create FastAPI app
app = FastAPI(
    title="dLNk dLNk Attack Platform API",
    description="Advanced Penetration Testing Platform with AI-powered Zero-Day Discovery",
    version="2.0.0",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# API Key Header
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(api_key: str = Depends(api_key_header)):
    """Verify API key"""
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API Key required"
        )
    
    user = await auth_service.verify_key(api_key)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key"
        )
    
    if not user["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API Key is disabled"
        )
    
    return user


async def verify_admin(user: Dict = Depends(verify_api_key)):
    """Verify admin role"""
    if user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return user


# Root endpoint
@app.get("/")
async def root():
    return {
        "name": "dLNk dLNk Attack Platform API",
        "version": "2.0.0",
        "status": "operational",
        "timestamp": datetime.now().isoformat()
    }


# Health check
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "database": await db.health_check(),
        "timestamp": datetime.now().isoformat()
    }


# WebSocket endpoint for real-time attack updates
@app.websocket("/ws/attack/{attack_id}")
async def websocket_attack(websocket: WebSocket, attack_id: str):
    """WebSocket for real-time attack updates"""
    await ws_manager.connect(websocket, attack_id)
    try:
        while True:
            # Keep connection alive
            data = await websocket.receive_text()
            # Echo back (optional)
            await websocket.send_json({"type": "pong", "timestamp": datetime.now().isoformat()})
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, attack_id)


# WebSocket endpoint for system monitoring (Admin only)
@app.websocket("/ws/system")
async def websocket_system(websocket: WebSocket):
    """WebSocket for system monitoring (Admin only)"""
    # Note: WebSocket doesn't support headers easily, so we'll accept connection
    # and verify later through a message
    await ws_manager.connect_system(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Handle system monitoring requests
            await websocket.send_json({"type": "system_status", "data": await get_system_status()})
    except WebSocketDisconnect:
        ws_manager.disconnect_system(websocket)


async def get_system_status() -> Dict:
    """Get system status"""
    import psutil
    import ollama
    
    # CPU and Memory
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    # LLM Status
    llm_status = {}
    try:
        models = ollama.list()
        llm_status = {
            "available": True,
            "models": [model["name"] for model in models.get("models", [])],
            "count": len(models.get("models", []))
        }
    except Exception as e:
        llm_status = {
            "available": False,
            "error": str(e)
        }
    
    # Active attacks
    active_attacks = await db.get_active_attacks_count()
    
    return {
        "timestamp": datetime.now().isoformat(),
        "system": {
            "cpu_percent": cpu_percent,
            "memory_percent": memory.percent,
            "memory_used_gb": memory.used / (1024**3),
            "memory_total_gb": memory.total / (1024**3),
            "disk_percent": disk.percent,
            "disk_used_gb": disk.used / (1024**3),
            "disk_total_gb": disk.total / (1024**3)
        },
        "llm": llm_status,
        "attacks": {
            "active": active_attacks
        }
    }


# Set dependencies for routers
admin.set_dependencies(db, auth_service)

# Include routers
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(admin.router, prefix="/api/admin", tags=["Admin"], dependencies=[Depends(verify_admin)])
app.include_router(attack.router, prefix="/api/attack", tags=["Attack"], dependencies=[Depends(verify_api_key)])
app.include_router(files.router, prefix="/api/files", tags=["Files"], dependencies=[Depends(verify_api_key)])


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )

