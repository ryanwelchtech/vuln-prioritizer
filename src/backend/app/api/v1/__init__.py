"""
API v1 router configuration.
"""
from fastapi import APIRouter

from app.api.v1 import vulnerabilities, scans, assets, auth

router = APIRouter()

router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
router.include_router(vulnerabilities.router, prefix="/vulnerabilities", tags=["Vulnerabilities"])
router.include_router(scans.router, prefix="/scans", tags=["Scans"])
router.include_router(assets.router, prefix="/assets", tags=["Assets"])
