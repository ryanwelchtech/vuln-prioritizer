"""
Scan management endpoints.
"""
from typing import Optional, List
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query, UploadFile, File
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.scan import Scan, ScanVulnerability
from app.models.vulnerability import Vulnerability
from app.models.asset import Asset
from app.services.risk_scorer import risk_scorer

router = APIRouter()


class ScanCreate(BaseModel):
    name: str
    scan_type: str  # nessus, qualys, rapid7, manual
    asset_id: Optional[int] = None
    cve_ids: List[str] = []


class ScanResponse(BaseModel):
    id: int
    name: str
    scan_type: str
    status: str
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


class ScanDetailResponse(ScanResponse):
    vulnerabilities: List[dict]


class ScanStats(BaseModel):
    total_scans: int
    completed_scans: int
    total_vulns_found: int
    avg_vulns_per_scan: float


@router.get("", response_model=List[ScanResponse])
async def list_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
    scan_type: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all scans with filtering."""
    query = select(Scan).order_by(Scan.created_at.desc())

    if status:
        query = query.where(Scan.status == status)
    if scan_type:
        query = query.where(Scan.scan_type == scan_type)

    query = query.offset(skip).limit(limit)

    result = await db.execute(query)
    return result.scalars().all()


@router.get("/stats", response_model=ScanStats)
async def get_scan_stats(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get scan statistics."""
    # Total scans
    total_result = await db.execute(select(func.count(Scan.id)))
    total_scans = total_result.scalar() or 0

    # Completed scans
    completed_result = await db.execute(
        select(func.count(Scan.id)).where(Scan.status == "completed")
    )
    completed_scans = completed_result.scalar() or 0

    # Total vulns found
    vulns_result = await db.execute(
        select(func.sum(Scan.total_vulnerabilities))
    )
    total_vulns = vulns_result.scalar() or 0

    avg_vulns = total_vulns / total_scans if total_scans > 0 else 0

    return ScanStats(
        total_scans=total_scans,
        completed_scans=completed_scans,
        total_vulns_found=total_vulns,
        avg_vulns_per_scan=round(avg_vulns, 2),
    )


@router.get("/{scan_id}", response_model=ScanDetailResponse)
async def get_scan(
    scan_id: int,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get scan details with vulnerabilities."""
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    # Get associated vulnerabilities
    vuln_result = await db.execute(
        select(ScanVulnerability, Vulnerability)
        .join(Vulnerability, ScanVulnerability.vulnerability_id == Vulnerability.id)
        .where(ScanVulnerability.scan_id == scan_id)
        .order_by(Vulnerability.risk_score.desc().nulls_last())
    )

    vulnerabilities = []
    for scan_vuln, vuln in vuln_result.all():
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

    return ScanDetailResponse(
        id=scan.id,
        name=scan.name,
        scan_type=scan.scan_type,
        status=scan.status,
        total_vulnerabilities=scan.total_vulnerabilities,
        critical_count=scan.critical_count,
        high_count=scan.high_count,
        medium_count=scan.medium_count,
        low_count=scan.low_count,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        created_at=scan.created_at,
        vulnerabilities=vulnerabilities,
    )


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    scan_data: ScanCreate,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Create a new scan and process CVEs.

    Enriches and scores all provided CVEs.
    """
    # Create scan record
    scan = Scan(
        name=scan_data.name,
        scan_type=scan_data.scan_type,
        asset_id=scan_data.asset_id,
        status="processing",
        started_at=datetime.utcnow(),
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Get asset criticality if linked
    asset_criticality = 1.0
    if scan_data.asset_id:
        asset_result = await db.execute(
            select(Asset).where(Asset.id == scan_data.asset_id)
        )
        asset = asset_result.scalar_one_or_none()
        if asset:
            asset_criticality = asset.criticality

    # Process CVEs
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for cve_id in scan_data.cve_ids:
        # Check if vulnerability exists
        vuln_result = await db.execute(
            select(Vulnerability).where(Vulnerability.cve_id == cve_id)
        )
        vuln = vuln_result.scalar_one_or_none()

        if not vuln:
            # Enrich and create new vulnerability
            enriched = await risk_scorer.enrich_vulnerability(cve_id)
            score_result = risk_scorer.calculate_risk_score(
                cvss_score=enriched.get("cvss_v3_score"),
                epss_score=enriched.get("epss_score"),
                in_kev=enriched.get("in_kev", False),
                asset_criticality=asset_criticality,
            )

            vuln = Vulnerability(
                cve_id=cve_id,
                description=enriched.get("description"),
                cvss_v3_score=enriched.get("cvss_v3_score"),
                cvss_v3_vector=enriched.get("cvss_v3_vector"),
                epss_score=enriched.get("epss_score"),
                epss_percentile=enriched.get("epss_percentile"),
                in_kev=enriched.get("in_kev", False),
                risk_score=score_result["risk_score"],
                severity=score_result["severity"],
            )
            db.add(vuln)
            await db.commit()
            await db.refresh(vuln)
        else:
            # Update last_seen
            vuln.last_seen = datetime.utcnow()

        # Link to scan
        scan_vuln = ScanVulnerability(
            scan_id=scan.id,
            vulnerability_id=vuln.id,
        )
        db.add(scan_vuln)

        # Count severity
        if vuln.severity:
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1

    # Update scan stats
    scan.total_vulnerabilities = len(scan_data.cve_ids)
    scan.critical_count = severity_counts["critical"]
    scan.high_count = severity_counts["high"]
    scan.medium_count = severity_counts["medium"]
    scan.low_count = severity_counts["low"]
    scan.status = "completed"
    scan.completed_at = datetime.utcnow()

    await db.commit()
    await db.refresh(scan)

    return scan


@router.post("/upload", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def upload_scan_file(
    file: UploadFile = File(...),
    scan_type: str = Query(..., pattern="^(nessus|qualys|rapid7|csv)$"),
    name: Optional[str] = None,
    asset_id: Optional[int] = None,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Upload and process a scan file.

    Supported formats:
    - Nessus (.nessus XML)
    - Qualys (.xml)
    - Rapid7 (.xml)
    - CSV (with cve_id column)
    """
    content = await file.read()
    scan_name = name or file.filename or f"Upload {datetime.utcnow().isoformat()}"

    # Parse CVE IDs based on format
    cve_ids = []

    if scan_type == "csv":
        # Simple CSV parsing
        lines = content.decode("utf-8").strip().split("\n")
        for line in lines[1:]:  # Skip header
            parts = line.split(",")
            for part in parts:
                part = part.strip().strip('"')
                if part.startswith("CVE-"):
                    cve_ids.append(part)
    else:
        # XML parsing - extract CVE IDs
        import re
        content_str = content.decode("utf-8", errors="ignore")
        cve_pattern = r"CVE-\d{4}-\d{4,}"
        cve_ids = list(set(re.findall(cve_pattern, content_str)))

    if not cve_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No CVE IDs found in uploaded file",
        )

    # Create scan with extracted CVEs
    scan_data = ScanCreate(
        name=scan_name,
        scan_type=scan_type,
        asset_id=asset_id,
        cve_ids=cve_ids[:500],  # Limit to 500 CVEs per upload
    )

    return await create_scan(scan_data, current_user, db)


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: int,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a scan and its associations."""
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    # Delete scan vulnerabilities first
    await db.execute(
        ScanVulnerability.__table__.delete().where(
            ScanVulnerability.scan_id == scan_id
        )
    )

    await db.delete(scan)
    await db.commit()
