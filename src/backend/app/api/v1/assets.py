"""
Asset management endpoints.
"""
from typing import Optional, List
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability

router = APIRouter()


class AssetCreate(BaseModel):
    hostname: str
    ip_address: Optional[str] = None
    asset_type: str = "server"  # server, workstation, network_device, container, cloud
    environment: str = "production"  # production, staging, development, testing
    criticality: float = 1.0  # 0.5-1.5
    owner: Optional[str] = None
    business_unit: Optional[str] = None
    tags: List[str] = []


class AssetUpdate(BaseModel):
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    asset_type: Optional[str] = None
    environment: Optional[str] = None
    criticality: Optional[float] = None
    owner: Optional[str] = None
    business_unit: Optional[str] = None
    tags: Optional[List[str]] = None


class AssetResponse(BaseModel):
    id: int
    hostname: str
    ip_address: Optional[str]
    asset_type: str
    environment: str
    criticality: float
    owner: Optional[str]
    business_unit: Optional[str]
    tags: List[str]
    vulnerability_count: int
    critical_vuln_count: int
    last_scan: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


class AssetDetailResponse(AssetResponse):
    vulnerabilities: List[dict]


class AssetStats(BaseModel):
    total_assets: int
    by_type: dict
    by_environment: dict
    avg_criticality: float
    assets_with_critical_vulns: int


@router.get("", response_model=List[AssetResponse])
async def list_assets(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    asset_type: Optional[str] = None,
    environment: Optional[str] = None,
    business_unit: Optional[str] = None,
    min_criticality: Optional[float] = None,
    has_critical_vulns: Optional[bool] = None,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List assets with filtering."""
    query = select(Asset).order_by(Asset.criticality.desc(), Asset.hostname)

    if asset_type:
        query = query.where(Asset.asset_type == asset_type)
    if environment:
        query = query.where(Asset.environment == environment)
    if business_unit:
        query = query.where(Asset.business_unit == business_unit)
    if min_criticality is not None:
        query = query.where(Asset.criticality >= min_criticality)
    if has_critical_vulns is True:
        query = query.where(Asset.critical_vuln_count > 0)

    query = query.offset(skip).limit(limit)

    result = await db.execute(query)
    return result.scalars().all()


@router.get("/stats", response_model=AssetStats)
async def get_asset_stats(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get asset statistics."""
    # Total assets
    total_result = await db.execute(select(func.count(Asset.id)))
    total_assets = total_result.scalar() or 0

    # By type
    type_result = await db.execute(
        select(Asset.asset_type, func.count(Asset.id))
        .group_by(Asset.asset_type)
    )
    by_type = dict(type_result.all())

    # By environment
    env_result = await db.execute(
        select(Asset.environment, func.count(Asset.id))
        .group_by(Asset.environment)
    )
    by_environment = dict(env_result.all())

    # Average criticality
    avg_result = await db.execute(select(func.avg(Asset.criticality)))
    avg_criticality = avg_result.scalar() or 1.0

    # Assets with critical vulns
    critical_result = await db.execute(
        select(func.count(Asset.id)).where(Asset.critical_vuln_count > 0)
    )
    assets_with_critical = critical_result.scalar() or 0

    return AssetStats(
        total_assets=total_assets,
        by_type=by_type,
        by_environment=by_environment,
        avg_criticality=round(avg_criticality, 2),
        assets_with_critical_vulns=assets_with_critical,
    )


@router.get("/{asset_id}", response_model=AssetDetailResponse)
async def get_asset(
    asset_id: int,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get asset details with vulnerabilities."""
    result = await db.execute(
        select(Asset).where(Asset.id == asset_id)
    )
    asset = result.scalar_one_or_none()

    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found",
        )

    # Get associated vulnerabilities (through scans)
    from app.models.scan import Scan, ScanVulnerability

    vuln_result = await db.execute(
        select(Vulnerability)
        .join(ScanVulnerability, ScanVulnerability.vulnerability_id == Vulnerability.id)
        .join(Scan, Scan.id == ScanVulnerability.scan_id)
        .where(Scan.asset_id == asset_id)
        .order_by(Vulnerability.risk_score.desc().nulls_last())
        .distinct()
    )

    vulnerabilities = []
    for vuln in vuln_result.scalars().all():
        vulnerabilities.append({
            "id": vuln.id,
            "cve_id": vuln.cve_id,
            "description": vuln.description,
            "cvss_v3_score": vuln.cvss_v3_score,
            "epss_score": vuln.epss_score,
            "in_kev": vuln.in_kev,
            "risk_score": vuln.risk_score,
            "severity": vuln.severity,
            "status": vuln.status,
        })

    return AssetDetailResponse(
        id=asset.id,
        hostname=asset.hostname,
        ip_address=asset.ip_address,
        asset_type=asset.asset_type,
        environment=asset.environment,
        criticality=asset.criticality,
        owner=asset.owner,
        business_unit=asset.business_unit,
        tags=asset.tags or [],
        vulnerability_count=asset.vulnerability_count,
        critical_vuln_count=asset.critical_vuln_count,
        last_scan=asset.last_scan,
        created_at=asset.created_at,
        vulnerabilities=vulnerabilities,
    )


@router.post("", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
async def create_asset(
    asset_data: AssetCreate,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a new asset."""
    # Check if hostname already exists
    result = await db.execute(
        select(Asset).where(Asset.hostname == asset_data.hostname)
    )
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Asset with this hostname already exists",
        )

    # Validate criticality range
    if not 0.5 <= asset_data.criticality <= 1.5:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Criticality must be between 0.5 and 1.5",
        )

    asset = Asset(
        hostname=asset_data.hostname,
        ip_address=asset_data.ip_address,
        asset_type=asset_data.asset_type,
        environment=asset_data.environment,
        criticality=asset_data.criticality,
        owner=asset_data.owner,
        business_unit=asset_data.business_unit,
        tags=asset_data.tags,
    )

    db.add(asset)
    await db.commit()
    await db.refresh(asset)

    return asset


@router.put("/{asset_id}", response_model=AssetResponse)
async def update_asset(
    asset_id: int,
    asset_data: AssetUpdate,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update an asset."""
    result = await db.execute(
        select(Asset).where(Asset.id == asset_id)
    )
    asset = result.scalar_one_or_none()

    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found",
        )

    # Update fields
    update_data = asset_data.model_dump(exclude_unset=True)

    if "criticality" in update_data and not 0.5 <= update_data["criticality"] <= 1.5:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Criticality must be between 0.5 and 1.5",
        )

    for field, value in update_data.items():
        setattr(asset, field, value)

    await db.commit()
    await db.refresh(asset)

    return asset


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset(
    asset_id: int,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete an asset."""
    result = await db.execute(
        select(Asset).where(Asset.id == asset_id)
    )
    asset = result.scalar_one_or_none()

    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found",
        )

    await db.delete(asset)
    await db.commit()


@router.post("/{asset_id}/recalculate-risk")
async def recalculate_asset_risk(
    asset_id: int,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Recalculate risk scores for all vulnerabilities associated with an asset.

    Uses the asset's criticality factor in the calculation.
    """
    result = await db.execute(
        select(Asset).where(Asset.id == asset_id)
    )
    asset = result.scalar_one_or_none()

    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found",
        )

    # Get all vulnerabilities for this asset
    from app.models.scan import Scan, ScanVulnerability
    from app.services.risk_scorer import risk_scorer

    vuln_result = await db.execute(
        select(Vulnerability)
        .join(ScanVulnerability, ScanVulnerability.vulnerability_id == Vulnerability.id)
        .join(Scan, Scan.id == ScanVulnerability.scan_id)
        .where(Scan.asset_id == asset_id)
        .distinct()
    )

    updated_count = 0
    critical_count = 0

    for vuln in vuln_result.scalars().all():
        score_result = risk_scorer.calculate_risk_score(
            cvss_score=vuln.cvss_v3_score,
            epss_score=vuln.epss_score,
            in_kev=vuln.in_kev,
            asset_criticality=asset.criticality,
        )

        vuln.risk_score = score_result["risk_score"]
        vuln.severity = score_result["severity"]
        updated_count += 1

        if score_result["severity"] == "critical":
            critical_count += 1

    # Update asset stats
    asset.vulnerability_count = updated_count
    asset.critical_vuln_count = critical_count

    await db.commit()

    return {
        "message": "Risk scores recalculated",
        "asset_id": asset_id,
        "vulnerabilities_updated": updated_count,
        "critical_count": critical_count,
    }
