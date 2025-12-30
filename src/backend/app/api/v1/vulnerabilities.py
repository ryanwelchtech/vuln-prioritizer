"""
Vulnerability management endpoints.
"""
from typing import Optional, List
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.vulnerability import Vulnerability
from app.models.asset import Asset
from app.services.risk_scorer import risk_scorer

router = APIRouter()


class VulnerabilityCreate(BaseModel):
    cve_id: str
    asset_id: Optional[int] = None


class VulnerabilityResponse(BaseModel):
    id: int
    cve_id: str
    description: Optional[str]
    cvss_v3_score: Optional[float]
    cvss_v3_vector: Optional[str]
    epss_score: Optional[float]
    epss_percentile: Optional[float]
    in_kev: bool
    risk_score: Optional[float]
    severity: Optional[str]
    status: str
    first_seen: datetime
    last_seen: datetime

    class Config:
        from_attributes = True


class VulnerabilityEnrichResponse(BaseModel):
    cve_id: str
    description: Optional[str]
    cvss_v3_score: Optional[float]
    cvss_v3_vector: Optional[str]
    epss_score: Optional[float]
    epss_percentile: Optional[float]
    in_kev: bool
    kev_details: Optional[dict]
    risk_score: float
    severity: str
    components: dict
    factors: dict


class BulkScoreRequest(BaseModel):
    cve_ids: List[str]
    asset_criticality: float = 1.0
    network_reachability: float = 1.0


class VulnerabilityStats(BaseModel):
    total: int
    by_severity: dict
    by_status: dict
    avg_risk_score: float
    kev_count: int


@router.get("", response_model=List[VulnerabilityResponse])
async def list_vulnerabilities(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    in_kev: Optional[bool] = None,
    min_risk_score: Optional[float] = None,
    sort_by: str = Query("risk_score", pattern="^(risk_score|cvss_v3_score|epss_score|first_seen)$"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List vulnerabilities with filtering and sorting."""
    query = select(Vulnerability)

    # Apply filters
    if severity:
        query = query.where(Vulnerability.severity == severity)
    if status:
        query = query.where(Vulnerability.status == status)
    if in_kev is not None:
        query = query.where(Vulnerability.in_kev == in_kev)
    if min_risk_score is not None:
        query = query.where(Vulnerability.risk_score >= min_risk_score)

    # Apply sorting
    sort_column = getattr(Vulnerability, sort_by)
    if sort_order == "desc":
        query = query.order_by(sort_column.desc().nulls_last())
    else:
        query = query.order_by(sort_column.asc().nulls_first())

    query = query.offset(skip).limit(limit)

    result = await db.execute(query)
    return result.scalars().all()


@router.get("/stats", response_model=VulnerabilityStats)
async def get_vulnerability_stats(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get vulnerability statistics."""
    # Total count
    total_result = await db.execute(select(func.count(Vulnerability.id)))
    total = total_result.scalar() or 0

    # By severity
    severity_result = await db.execute(
        select(Vulnerability.severity, func.count(Vulnerability.id))
        .group_by(Vulnerability.severity)
    )
    by_severity = dict(severity_result.all())

    # By status
    status_result = await db.execute(
        select(Vulnerability.status, func.count(Vulnerability.id))
        .group_by(Vulnerability.status)
    )
    by_status = dict(status_result.all())

    # Average risk score
    avg_result = await db.execute(select(func.avg(Vulnerability.risk_score)))
    avg_risk_score = avg_result.scalar() or 0.0

    # KEV count
    kev_result = await db.execute(
        select(func.count(Vulnerability.id)).where(Vulnerability.in_kev == True)
    )
    kev_count = kev_result.scalar() or 0

    return VulnerabilityStats(
        total=total,
        by_severity=by_severity,
        by_status=by_status,
        avg_risk_score=round(avg_risk_score, 2),
        kev_count=kev_count,
    )


@router.get("/enrich/{cve_id}", response_model=VulnerabilityEnrichResponse)
async def enrich_vulnerability(
    cve_id: str,
    asset_criticality: float = Query(1.0, ge=0.5, le=1.5),
    network_reachability: float = Query(1.0, ge=0.5, le=1.5),
    current_user: dict = Depends(get_current_user),
):
    """
    Enrich and score a single CVE.

    Fetches data from NVD, EPSS, and CISA KEV, then calculates risk score.
    """
    # Validate CVE format
    if not cve_id.startswith("CVE-"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid CVE format. Expected CVE-YYYY-NNNNN",
        )

    # Enrich vulnerability
    enriched = await risk_scorer.enrich_vulnerability(cve_id)

    # Calculate risk score
    score_result = risk_scorer.calculate_risk_score(
        cvss_score=enriched.get("cvss_v3_score"),
        epss_score=enriched.get("epss_score"),
        in_kev=enriched.get("in_kev", False),
        asset_criticality=asset_criticality,
        network_reachability=network_reachability,
    )

    return VulnerabilityEnrichResponse(
        cve_id=cve_id,
        description=enriched.get("description"),
        cvss_v3_score=enriched.get("cvss_v3_score"),
        cvss_v3_vector=enriched.get("cvss_v3_vector"),
        epss_score=enriched.get("epss_score"),
        epss_percentile=enriched.get("epss_percentile"),
        in_kev=enriched.get("in_kev", False),
        kev_details=enriched.get("kev_details"),
        **score_result,
    )


@router.post("/score/bulk")
async def bulk_score_vulnerabilities(
    request: BulkScoreRequest,
    current_user: dict = Depends(get_current_user),
):
    """
    Score multiple CVEs in bulk.

    Returns scored vulnerabilities sorted by risk score (highest first).
    """
    if len(request.cve_ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum 100 CVEs per request",
        )

    results = await risk_scorer.score_vulnerabilities(
        cve_ids=request.cve_ids,
        asset_criticality=request.asset_criticality,
        network_reachability=request.network_reachability,
    )

    return {
        "count": len(results),
        "vulnerabilities": results,
    }


@router.get("/{vuln_id}", response_model=VulnerabilityResponse)
async def get_vulnerability(
    vuln_id: int,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a specific vulnerability by ID."""
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.id == vuln_id)
    )
    vuln = result.scalar_one_or_none()

    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found",
        )

    return vuln


@router.post("", response_model=VulnerabilityResponse, status_code=status.HTTP_201_CREATED)
async def create_vulnerability(
    vuln_data: VulnerabilityCreate,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Create or update a vulnerability record.

    Automatically enriches with NVD, EPSS, and KEV data.
    """
    # Check if already exists
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.cve_id == vuln_data.cve_id)
    )
    existing = result.scalar_one_or_none()

    if existing:
        # Update last_seen
        existing.last_seen = datetime.utcnow()
        await db.commit()
        await db.refresh(existing)
        return existing

    # Enrich new vulnerability
    enriched = await risk_scorer.enrich_vulnerability(vuln_data.cve_id)

    # Get asset criticality if linked
    asset_criticality = 1.0
    if vuln_data.asset_id:
        asset_result = await db.execute(
            select(Asset).where(Asset.id == vuln_data.asset_id)
        )
        asset = asset_result.scalar_one_or_none()
        if asset:
            asset_criticality = asset.criticality

    # Calculate risk score
    score_result = risk_scorer.calculate_risk_score(
        cvss_score=enriched.get("cvss_v3_score"),
        epss_score=enriched.get("epss_score"),
        in_kev=enriched.get("in_kev", False),
        asset_criticality=asset_criticality,
    )

    # Create vulnerability
    vuln = Vulnerability(
        cve_id=vuln_data.cve_id,
        description=enriched.get("description"),
        cvss_v3_score=enriched.get("cvss_v3_score"),
        cvss_v3_vector=enriched.get("cvss_v3_vector"),
        cvss_v2_score=enriched.get("cvss_v2_score"),
        epss_score=enriched.get("epss_score"),
        epss_percentile=enriched.get("epss_percentile"),
        in_kev=enriched.get("in_kev", False),
        kev_due_date=enriched.get("kev_details", {}).get("due_date") if enriched.get("in_kev") else None,
        risk_score=score_result["risk_score"],
        severity=score_result["severity"],
        cwe_ids=enriched.get("cwe_ids", []),
        references=enriched.get("references", []),
    )

    db.add(vuln)
    await db.commit()
    await db.refresh(vuln)

    return vuln


@router.patch("/{vuln_id}/status")
async def update_vulnerability_status(
    vuln_id: int,
    new_status: str = Query(..., pattern="^(open|in_progress|remediated|accepted|false_positive)$"),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update vulnerability status."""
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.id == vuln_id)
    )
    vuln = result.scalar_one_or_none()

    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found",
        )

    vuln.status = new_status
    await db.commit()

    return {"message": "Status updated", "status": new_status}


@router.delete("/{vuln_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_vulnerability(
    vuln_id: int,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a vulnerability."""
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.id == vuln_id)
    )
    vuln = result.scalar_one_or_none()

    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found",
        )

    await db.delete(vuln)
    await db.commit()
