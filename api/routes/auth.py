"""
Authentication API Routes
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from api.services.database import Database
from api.services.auth import AuthService

router = APIRouter()

# Dependency injection - will be set by main.py
db: Database = None
auth_service: AuthService = None

def set_dependencies(database: Database, auth_svc: AuthService):
    """Set dependencies from main.py"""
    global db, auth_service
    db = database
    auth_service = auth_svc


class LoginRequest(BaseModel):
    api_key: str


@router.post("/login")
async def login(request: LoginRequest):
    """Login with API Key"""
    user = await auth_service.verify_key(request.api_key)
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    
    if not user["is_active"]:
        raise HTTPException(status_code=403, detail="Account is disabled")
    
    return {
        "success": True,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "quota_limit": user["quota_limit"],
            "quota_used": user["quota_used"],
            "api_key": user["api_key"]
        }
    }


@router.post("/verify")
async def verify(request: LoginRequest):
    """Verify API Key"""
    user = await auth_service.verify_key(request.api_key)
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    
    return {
        "valid": True,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"]
        }
    }


@router.post("/logout")
async def logout():
    """Logout (placeholder)"""
    return {"success": True, "message": "Logged out"}

