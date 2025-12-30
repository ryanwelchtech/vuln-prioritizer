"""
Scan models for vulnerability scan results.
"""
from datetime import datetime
from typing import Optional, List
from sqlalchemy import String, Float, DateTime, Text, Integer, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class Scan(Base):
    """Vulnerability scan record."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(100), unique=True, index=True)

    # Scan source
    scanner: Mapped[str] = mapped_column(String(50), nullable=False)  # trivy, grype, etc.
    scan_type: Mapped[str] = mapped_column(String(50), nullable=False)  # image, filesystem, repository

    # Target
    target: Mapped[str] = mapped_column(String(500), nullable=False)  # image name, path, etc.
    asset_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("assets.id"), nullable=True)

    # Status
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending, running, completed, failed
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Summary
    total_vulnerabilities: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)

    # Timestamps
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Relationships
    results: Mapped[List["ScanResult"]] = relationship("ScanResult", back_populates="scan")


class ScanResult(Base):
    """Individual vulnerability finding from a scan."""

    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id"), nullable=False)
    vulnerability_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("vulnerabilities.id"), nullable=True)

    # CVE Info
    cve_id: Mapped[str] = mapped_column(String(20), index=True, nullable=False)

    # Package Info
    package_name: Mapped[str] = mapped_column(String(255), nullable=False)
    package_version: Mapped[str] = mapped_column(String(100), nullable=False)
    fixed_version: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    package_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # npm, pip, apt, etc.

    # Severity from scanner
    scanner_severity: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)

    # Location
    file_path: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    layer: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Risk score (after enrichment)
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Raw data
    raw_data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationships
    scan: Mapped["Scan"] = relationship("Scan", back_populates="results")
