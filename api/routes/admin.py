"""
Admin API Routes
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from api.services.database import Database
from api.services.auth import AuthService

router = APIRouter()

# Dependency injection
db = Database()
auth_service = AuthService(db)


class CreateKeyRequest(BaseModel):
    username: str
    role: str = "user"
    quota_limit: int = 100


class ToggleUserRequest(BaseModel):
    is_active: bool


@router.post("/keys/create")
async def create_key(request: CreateKeyRequest):
    """สร้าง API Key ใหม่ (Admin only)"""
    try:
        result = await auth_service.create_user_key(
            username=request.username,
            role=request.role,
            quota_limit=request.quota_limit
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/users")
async def get_all_users():
    """ดูรายการ Users ทั้งหมด (Admin only)"""
    users = await db.get_all_users()
    return {"users": users}


@router.delete("/users/{user_id}")
async def delete_user(user_id: int):
    """ลบ User (Admin only)"""
    try:
        await db.delete_user(user_id)
        return {"success": True, "message": "User deleted"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/users/{user_id}/toggle")
async def toggle_user(user_id: int, request: ToggleUserRequest):
    """เปิด/ปิด User (Admin only)"""
    try:
        await db.toggle_user_status(user_id, request.is_active)
        return {"success": True, "message": "User status updated"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/attacks")
async def get_all_attacks(limit: int = 100):
    """ดูการโจมตีทั้งหมด (Admin only)"""
    attacks = await db.get_all_attacks(limit)
    return {"attacks": attacks}


@router.get("/logs/agents")
async def get_agent_logs(limit: int = 500):
    """ดู Agent logs ทั้งหมด (Admin only)"""
    logs = await db.get_all_agent_logs(limit)
    return {"logs": logs}


@router.get("/logs/system")
async def get_system_logs(limit: int = 500):
    """ดู System logs ทั้งหมด (Admin only)"""
    logs = await db.get_system_logs(limit)
    return {"logs": logs}


@router.get("/system/status")
async def get_system_status():
    """ดูสถานะระบบ (Admin only)"""
    import psutil
    import ollama
    
    # System resources
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    # LLM status
    try:
        models = ollama.list()
        llm_status = {
            "available": True,
            "models": [
                {
                    "name": model["name"],
                    "size": model.get("size", 0),
                    "modified": model.get("modified_at", "")
                }
                for model in models.get("models", [])
            ]
        }
    except Exception as e:
        llm_status = {
            "available": False,
            "error": str(e)
        }
    
    # Database status
    db_status = await db.health_check()
    
    # Active attacks
    active_attacks = await db.get_active_attacks_count()
    
    return {
        "system": {
            "cpu_percent": cpu_percent,
            "memory_percent": memory.percent,
            "memory_used_gb": round(memory.used / (1024**3), 2),
            "memory_total_gb": round(memory.total / (1024**3), 2),
            "disk_percent": disk.percent,
            "disk_used_gb": round(disk.used / (1024**3), 2),
            "disk_total_gb": round(disk.total / (1024**3), 2)
        },
        "llm": llm_status,
        "database": {
            "status": "healthy" if db_status else "unhealthy"
        },
        "attacks": {
            "active": active_attacks
        }
    }

