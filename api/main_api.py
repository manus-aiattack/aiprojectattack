"""
Main API Server for dLNk dLNk Framework
Integrates authentication, license management, and framework APIs
"""

import asyncio
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
import uvicorn

# Import services
from services.auth_service import AuthService
from services.license_service import LicenseService

# Import API routes
from api.auth_routes import router as auth_router, set_auth_service
from api.license_routes import router as license_router, set_license_service

# Create FastAPI app
app = FastAPI(
    title="dLNk HACK - dLNk dLNk Framework API",
    description="Advanced AI-Driven Attack Framework - Enterprise Edition",
    version="3.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global service instances
auth_service: AuthService = None
license_service: LicenseService = None


@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    global auth_service, license_service
    
    print("🚀 Starting dLNk HACK API Server...")
    
    # Initialize authentication service
    print("   Initializing authentication service...")
    auth_service = AuthService(
        redis_url="redis://localhost:6379",
        secret_key="your-secret-key-change-in-production"
    )
    await auth_service.initialize()
    set_auth_service(auth_service)
    print("   ✅ Authentication service ready")
    
    # Initialize license service
    print("   Initializing license service...")
    license_service = LicenseService(redis_url="redis://localhost:6379")
    await license_service.initialize()
    set_license_service(license_service)
    print("   ✅ License service ready")
    
    print("✅ dLNk HACK API Server started successfully!")
    print(f"   📍 API Documentation: http://localhost:8000/api/docs")
    print(f"   📍 Dashboard: http://localhost:8000/dashboard")
    print(f"   📍 Admin Panel: http://localhost:8000/admin")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    print("🛑 Shutting down dLNk HACK API Server...")


# Include routers
app.include_router(auth_router, prefix="/api")
app.include_router(license_router, prefix="/api")


# Root endpoint
@app.get("/", response_class=HTMLResponse)
async def root():
    """Root endpoint with API information"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>dLNk HACK API</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%);
                color: #e0e0e0;
                padding: 40px;
                margin: 0;
            }
            .container {
                max-width: 800px;
                margin: 0 auto;
                background: rgba(26, 31, 58, 0.8);
                border: 1px solid rgba(0, 255, 136, 0.3);
                border-radius: 15px;
                padding: 40px;
            }
            h1 {
                color: #00ff88;
                text-align: center;
                font-size: 36px;
                margin-bottom: 10px;
            }
            .subtitle {
                text-align: center;
                color: #b0b0b0;
                margin-bottom: 40px;
            }
            .links {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin-top: 30px;
            }
            .link-card {
                background: rgba(10, 14, 39, 0.8);
                border: 1px solid rgba(0, 255, 136, 0.3);
                border-radius: 10px;
                padding: 20px;
                text-align: center;
                text-decoration: none;
                color: #e0e0e0;
                transition: all 0.3s ease;
            }
            .link-card:hover {
                transform: translateY(-5px);
                box-shadow: 0 10px 30px rgba(0, 255, 136, 0.3);
                border-color: #00ff88;
            }
            .link-icon {
                font-size: 48px;
                margin-bottom: 10px;
            }
            .link-title {
                font-size: 18px;
                font-weight: bold;
                color: #00ff88;
                margin-bottom: 5px;
            }
            .link-desc {
                font-size: 14px;
                color: #b0b0b0;
            }
            .status {
                background: rgba(0, 255, 136, 0.2);
                border: 1px solid #00ff88;
                border-radius: 20px;
                padding: 8px 16px;
                display: inline-block;
                margin-top: 20px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>dLNk HACK API</h1>
            <p class="subtitle">Advanced AI-Driven Attack Framework - Enterprise Edition</p>
            
            <div style="text-align: center;">
                <span class="status">🟢 ONLINE</span>
            </div>
            
            <div class="links">
                <a href="/api/docs" class="link-card">
                    <div class="link-icon">📚</div>
                    <div class="link-title">API Docs</div>
                    <div class="link-desc">Interactive API documentation</div>
                </a>
                
                <a href="/dashboard" class="link-card">
                    <div class="link-icon">🎯</div>
                    <div class="link-title">Dashboard</div>
                    <div class="link-desc">Main attack dashboard</div>
                </a>
                
                <a href="/admin" class="link-card">
                    <div class="link-icon">⚙️</div>
                    <div class="link-title">Admin Panel</div>
                    <div class="link-desc">System administration</div>
                </a>
            </div>
            
            <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid rgba(255, 255, 255, 0.1); text-align: center; color: #b0b0b0; font-size: 14px;">
                <p>dLNk HACK Framework v3.0.0 - Enterprise Edition</p>
                <p>© 2024 dLNk HACK Team. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    """


# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": "3.0.0",
        "services": {
            "auth": "online" if auth_service else "offline",
            "license": "online" if license_service else "offline"
        }
    }


# Mount static files for web interface
try:
    app.mount("/dashboard", StaticFiles(directory="web", html=True), name="dashboard")
    app.mount("/admin", StaticFiles(directory="web", html=True), name="admin")
except Exception as e:
    print(f"⚠️ Warning: Could not mount static files: {e}")


# Additional API endpoints for framework integration

@app.get("/api/status")
async def get_framework_status():
    """Get framework status"""
    return {
        "status": "online",
        "agents": {
            "total": 62,
            "active": 0,
            "idle": 62
        },
        "workflows": {
            "running": 0,
            "completed": 0,
            "failed": 0
        }
    }


@app.post("/api/attack/target")
async def attack_target(
    target_data: dict,
    current_user: dict = Depends(lambda: None)  # Add auth dependency in production
):
    """
    Start attack on target
    
    This is a placeholder - integrate with your orchestrator
    """
    return {
        "success": True,
        "message": "Attack initiated",
        "workflow_id": "wf_" + "".join([str(i) for i in range(8)]),
        "target": target_data.get("target"),
        "status": "running"
    }


@app.post("/api/attack/zeroday")
async def zeroday_hunt(
    hunt_data: dict,
    current_user: dict = Depends(lambda: None)
):
    """
    Start zero-day hunting
    
    This is a placeholder - integrate with your AI planner
    """
    return {
        "success": True,
        "message": "Zero-day hunt initiated",
        "hunt_id": "hunt_" + "".join([str(i) for i in range(8)]),
        "estimated_time": "8-12 hours",
        "status": "running"
    }


@app.post("/api/attack/cve")
async def cve_attack(
    cve_data: dict,
    current_user: dict = Depends(lambda: None)
):
    """
    Start CVE-based attack
    
    This is a placeholder - integrate with your vulnerability scanner
    """
    return {
        "success": True,
        "message": "CVE attack initiated",
        "attack_id": "atk_" + "".join([str(i) for i in range(8)]),
        "cves_selected": "all",
        "status": "running"
    }


@app.post("/api/attack/full")
async def full_capabilities_attack(
    attack_data: dict,
    current_user: dict = Depends(lambda: None)
):
    """
    Start full capabilities attack
    
    This is a placeholder - integrate with your agent manager
    """
    return {
        "success": True,
        "message": "Full attack initiated",
        "attack_id": "full_" + "".join([str(i) for i in range(8)]),
        "agents_deployed": 62,
        "status": "running"
    }


@app.post("/api/attack/auto")
async def auto_attack(
    auto_data: dict,
    current_user: dict = Depends(lambda: None)
):
    """
    Start fully automated attack
    
    This is a placeholder - integrate with your AI planner
    """
    return {
        "success": True,
        "message": "Automated attack initiated",
        "attack_id": "auto_" + "".join([str(i) for i in range(8)]),
        "ai_strategy": auto_data.get("strategy", "adaptive"),
        "status": "running"
    }


if __name__ == "__main__":
    # Run the server
    uvicorn.run(
        "main_api:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )

