"""
Asset model for tracking business assets and their criticality.
"""
from datetime import datetime
from typing import Optional, List
from sqlalchemy import String, Float, DateTime, Text, Integer, JSON
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Asset(Base):
    """Asset model for business context in vulnerability prioritization."""

    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    asset_type: Mapped[str] = mapped_column(String(50), nullable=False)  # server, container, application, etc.

    # Identification
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    container_image: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    # Business Context
    environment: Mapped[str] = mapped_column(String(50), default="production")  # production, staging, development
    criticality: Mapped[float] = mapped_column(Float, default=1.0)  # 0.5 (low) to 1.5 (critical)
    owner: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    team: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Network Context
    network_zone: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    internet_facing: Mapped[bool] = mapped_column(default=False)
    network_reachability: Mapped[float] = mapped_column(Float, default=1.0)  # 0.5 (internal) to 1.5 (public)

    # Tags and metadata
    tags: Mapped[Optional[List[str]]] = mapped_column(JSON, nullable=True)
    metadata: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Compliance
    compliance_frameworks: Mapped[Optional[List[str]]] = mapped_column(JSON, nullable=True)  # PCI, HIPAA, etc.

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_scanned: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
