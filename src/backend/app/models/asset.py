"""
Asset model for tracking business assets and their criticality.
"""
from datetime import datetime
from typing import Optional, List
from sqlalchemy import String, Float, DateTime, Text, Integer, JSON, Boolean
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Asset(Base):
    """Asset model for business context in vulnerability prioritization."""

    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    asset_type: Mapped[str] = mapped_column(String(50), default="server")  # server, workstation, network_device, container, cloud

    # Business Context
    environment: Mapped[str] = mapped_column(String(50), default="production")  # production, staging, development, testing
    criticality: Mapped[float] = mapped_column(Float, default=1.0)  # 0.5 (low) to 1.5 (critical)
    owner: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    business_unit: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Tags
    tags: Mapped[Optional[List[str]]] = mapped_column(JSON, nullable=True, default=list)

    # Vulnerability counts (denormalized for performance)
    vulnerability_count: Mapped[int] = mapped_column(Integer, default=0)
    critical_vuln_count: Mapped[int] = mapped_column(Integer, default=0)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_scan: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
