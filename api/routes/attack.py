"""
Attack API Routes
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from typing import Optional, Dict, Any
from api.services.database import Database
from api.services.attack_manager import AttackManager
from api.services.websocket_manager import WebSocketManager
from api.services.auth import AuthService

router = APIRouter()

# Dependency injection
db = Database()
ws_manager = WebSocketManager()
attack_manager = AttackManager(db, ws_manager)
auth_service = AuthService(db)


class StartAttackRequest(BaseModel):
    target_url: str
    attack_type: str  # "full_auto", "sql_injection", "command_injection", "zero_day_hunt"
    options: Optional[Dict[str, Any]] = {}


@router.post("/start")
async def start_attack(request: StartAttackRequest, req: Request):
    """เริ่มการโจมตี"""
    # Get user from request state (set by dependency)
    user = req.state.user if hasattr(req.state, "user") else None
    
    if not user:
        # Fallback: get from header
        api_key = req.headers.get("X-API-Key")
        user = await auth_service.verify_key(api_key)
        
        if not user:
            raise HTTPException(status_code=401, detail="Unauthorized")
    
    # Check quota
    if not await auth_service.check_quota(user["id"]):
        raise HTTPException(status_code=403, detail="Quota exceeded")
    
    # Start attack
    result = await attack_manager.start_attack(
        user_id=user["id"],
        user_key=user["api_key"],
        target_url=request.target_url,
        attack_type=request.attack_type,
        options=request.options
    )
    
    # Consume quota
    await auth_service.consume_quota(user["id"])
    
    return result


@router.post("/{attack_id}/stop")
async def stop_attack(attack_id: str):
    """หยุดการโจมตี"""
    result = await attack_manager.stop_attack(attack_id)
    return result


@router.get("/{attack_id}/status")
async def get_attack_status(attack_id: str, req: Request):
    """ดูสถานะการโจมตี"""
    # Get user
    api_key = req.headers.get("X-API-Key")
    user = await auth_service.verify_key(api_key)
    
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    # Get attack
    attack = await db.get_attack(attack_id)
    
    if not attack:
        raise HTTPException(status_code=404, detail="Attack not found")
    
    # Check permission (users can only see their own attacks, admins can see all)
    if user["role"] != "admin" and attack["user_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Get full status
    result = await attack_manager.get_attack_status(attack_id)
    return result


@router.get("/{attack_id}/results")
async def get_attack_results(attack_id: str, req: Request):
    """ดูผลการโจมตี"""
    # Get user
    api_key = req.headers.get("X-API-Key")
    user = await auth_service.verify_key(api_key)
    
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    # Get attack
    attack = await db.get_attack(attack_id)
    
    if not attack:
        raise HTTPException(status_code=404, detail="Attack not found")
    
    # Check permission
    if user["role"] != "admin" and attack["user_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    return {
        "attack_id": attack_id,
        "status": attack["status"],
        "results": attack["results"],
        "started_at": attack["started_at"],
        "completed_at": attack["completed_at"]
    }


@router.get("/history")
async def get_attack_history(req: Request, limit: int = 50):
    """ดูประวัติการโจมตี"""
    # Get user
    api_key = req.headers.get("X-API-Key")
    user = await auth_service.verify_key(api_key)
    
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    # Get attacks
    if user["role"] == "admin":
        attacks = await db.get_all_attacks(limit)
    else:
        attacks = await db.get_user_attacks(user["id"], limit)
    
    return {"attacks": attacks}

