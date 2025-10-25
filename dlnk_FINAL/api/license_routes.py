"""
License API Routes
FastAPI routes for license management
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import Optional
from services.license_service import LicenseService
from api.auth_routes import get_current_user, require_role
from services.auth_service import UserRole

# Create router
router = APIRouter(prefix="/license", tags=["license"])

# Global license service instance
license_service: Optional[LicenseService] = None


def set_license_service(service: LicenseService):
    """Set the global license service instance"""
    global license_service
    license_service = service


def get_license_service() -> LicenseService:
    """Dependency to get license service"""
    if not license_service:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="License service not initialized"
        )
    return license_service


# API Models
class GenerateLicenseRequest(BaseModel):
    organization: str
    license_type: str
    duration_days: int = 365
    max_agents: Optional[int] = None
    max_concurrent_workflows: Optional[int] = None


# Routes

@router.post("/generate", dependencies=[Depends(require_role(UserRole.ADMIN))])
async def generate_license(
    request: GenerateLicenseRequest,
    license_svc: LicenseService = Depends(get_license_service)
):
    """
    Generate a new license (Admin only)
    """
    try:
        license_data = await license_svc.generate_license(
            organization=request.organization,
            license_type=request.license_type,
            duration_days=request.duration_days,
            max_agents=request.max_agents,
            max_concurrent_workflows=request.max_concurrent_workflows
        )
        
        return {
            "success": True,
            "message": "License generated successfully",
            "data": license_data
        }
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.get("/verify/{license_key}")
async def verify_license(
    license_key: str,
    license_svc: LicenseService = Depends(get_license_service)
):
    """
    Verify a license key
    """
    try:
        license_data = await license_svc.verify_license(license_key)
        
        return {
            "success": True,
            "data": license_data
        }
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.get("/info/{license_key}")
async def get_license_info(
    license_key: str,
    license_svc: LicenseService = Depends(get_license_service)
):
    """
    Get license information
    """
    license_data = await license_svc.get_license(license_key)
    
    if not license_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="License not found"
        )
        
    return {
        "success": True,
        "data": license_data
    }


@router.post("/revoke/{license_key}", dependencies=[Depends(require_role(UserRole.ADMIN))])
async def revoke_license(
    license_key: str,
    license_svc: LicenseService = Depends(get_license_service)
):
    """
    Revoke a license (Admin only)
    """
    try:
        await license_svc.revoke_license(license_key)
        
        return {
            "success": True,
            "message": "License revoked successfully"
        }
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.get("/list", dependencies=[Depends(require_role(UserRole.ADMIN))])
async def list_licenses(
    license_svc: LicenseService = Depends(get_license_service)
):
    """
    List all licenses (Admin only)
    """
    licenses = await license_svc.list_licenses()
    
    return {
        "success": True,
        "data": licenses,
        "count": len(licenses)
    }

