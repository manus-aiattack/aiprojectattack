"""
Attack API Routes
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, validator
from typing import Optional, Dict, Any
import re
from urllib.parse import urlparse
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
    
    @validator('target_url')
    def validate_target_url(cls, v):
        """Validate target URL"""
        if not v:
            raise ValueError('Target URL is required')
        
        # Parse URL
        try:
            parsed = urlparse(v)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError('Invalid URL format')
            
            # Only allow HTTP/HTTPS
            if parsed.scheme not in ['http', 'https']:
                raise ValueError('Only HTTP and HTTPS protocols are allowed')
            
            # Block private IP ranges
            hostname = parsed.hostname
            if hostname:
                # Check for private IP ranges
                if re.match(r'^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)', hostname):
                    raise ValueError('Private IP ranges are not allowed')
                
                # Check for localhost
                if hostname in ['localhost', '::1']:
                    raise ValueError('Localhost is not allowed')
        
        except Exception as e:
            raise ValueError(f'Invalid URL: {str(e)}')
        
        return v
    
    @validator('attack_type')
    def validate_attack_type(cls, v):
        """Validate attack type"""
        allowed_types = [
            'full_auto', 'scan', 'exploit', 'post_exploit',
            'sql_injection', 'xss', 'command_injection', 
            'zero_day_hunt', 'auth_bypass', 'ssrf'
        ]
        
        if v not in allowed_types:
            raise ValueError(f'Invalid attack type. Allowed: {", ".join(allowed_types)}')
        
        return v
    
    @validator('options')
    def validate_options(cls, v):
        """Validate attack options"""
        if v is None:
            return {}
        
        # Limit options size
        if len(str(v)) > 10000:  # 10KB limit
            raise ValueError('Options payload too large')
        
        return v


@router.post("/start")
async def start_attack(request: StartAttackRequest, req: Request):
    """เริ่มการโจมตี"""
    try:
        # Get user from request state (set by dependency)
        user = req.state.user if hasattr(req.state, "user") else None
        
        if not user:
            # Fallback: get from header
            api_key = req.headers.get("X-API-Key")
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
        
        # Check if user is active
        if not user.get("is_active", True):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is disabled"
            )
        
        # Check quota
        if not await auth_service.check_quota(user["id"]):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Quota exceeded. Please try again later."
            )
        
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
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@router.post("/{attack_id}/stop")
async def stop_attack(attack_id: str, req: Request):
    """หยุดการโจมตี"""
    try:
        # Validate attack_id format
        if not attack_id or len(attack_id) > 100:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid attack ID"
            )
        
        # Get user
        api_key = req.headers.get("X-API-Key")
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
        
        # Get attack to check ownership
        attack = await db.get_attack(attack_id)
        if not attack:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Attack not found"
            )
        
        # Check permission (users can only stop their own attacks, admins can stop all)
        if user["role"] != "admin" and attack["user_id"] != user["id"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
        
        result = await attack_manager.stop_attack(attack_id)
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@router.get("/{attack_id}/status")
async def get_attack_status(attack_id: str, req: Request):
    """ดูสถานะการโจมตี"""
    try:
        # Validate attack_id format
        if not attack_id or len(attack_id) > 100:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid attack ID"
            )
        
        # Get user
        api_key = req.headers.get("X-API-Key")
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
        
        # Get attack
        attack = await db.get_attack(attack_id)
        if not attack:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Attack not found"
            )
        
        # Check permission (users can only see their own attacks, admins can see all)
        if user["role"] != "admin" and attack["user_id"] != user["id"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
        
        # Get full status
        result = await attack_manager.get_attack_status(attack_id)
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@router.get("/{attack_id}/results")
async def get_attack_results(attack_id: str, req: Request):
    """ดูผลการโจมตี"""
    try:
        # Validate attack_id format
        if not attack_id or len(attack_id) > 100:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid attack ID"
            )
        
        # Get user
        api_key = req.headers.get("X-API-Key")
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
        
        # Get attack
        attack = await db.get_attack(attack_id)
        if not attack:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Attack not found"
            )
        
        # Check permission
        if user["role"] != "admin" and attack["user_id"] != user["id"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
        
        return {
            "attack_id": attack_id,
            "status": attack["status"],
            "results": attack["results"],
            "started_at": attack["started_at"],
            "completed_at": attack["completed_at"]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@router.get("/history")
async def get_attack_history(req: Request, limit: int = 50):
    """ดูประวัติการโจมตี"""
    try:
        # Validate limit parameter
        if limit < 1 or limit > 1000:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Limit must be between 1 and 1000"
            )
        
        # Get user
        api_key = req.headers.get("X-API-Key")
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
        
        # Get attacks
        if user["role"] == "admin":
            attacks = await db.get_all_attacks(limit)
        else:
            attacks = await db.get_user_attacks(user["id"], limit)
        
        return {"attacks": attacks}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )

