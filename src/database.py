"""
SQLAlchemy 2.x database layer for the asset monitoring tool.

All JSON fields are stored as TEXT columns and serialised/deserialised
transparently via a custom TypeDecorator so callers always work with
Python objects (dicts/lists) rather than raw JSON strings.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List, Optional, Tuple

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    event,
    func,
    select,
    update,
    CheckConstraint,
    UniqueConstraint,
    Index,
)
from sqlalchemy.orm import DeclarativeBase, Session, relationship, selectinload, sessionmaker
from sqlalchemy.types import TypeDecorator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utcnow() -> datetime:
    """Return a timezone-aware UTC datetime."""
    return datetime.now(tz=timezone.utc)


class JSONEncodedValue(TypeDecorator):
    """Transparently stores Python dicts/lists as JSON text in the database.

    On write: serialises any Python object to a JSON string.
    On read:  deserialises the JSON string back to the original Python object.
    NULL database values are returned as None.
    """

    impl = Text
    cache_ok = True

    def process_bind_param(self, value: Any, dialect: Any) -> Optional[str]:
        if value is None:
            return None
        return json.dumps(value, default=str)

    def process_result_value(self, value: Optional[str], dialect: Any) -> Any:
        if value is None:
            return None
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return value


# ---------------------------------------------------------------------------
# ORM base
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    __allow_unmapped__ = True


# ---------------------------------------------------------------------------
# ORM models
# ---------------------------------------------------------------------------

class Company(Base):
    """A target company / bug-bounty programme that owns one or more domains."""

    __tablename__ = "companies"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    name: str = Column(String(256), unique=True, nullable=False, index=True)
    description: Optional[str] = Column(Text, nullable=True)
    is_active: bool = Column(Boolean, default=True, nullable=False, index=True)
    program_type: Optional[str] = Column(String(64), nullable=True)   # HackerOne / Bugcrowd / private …
    program_url: Optional[str] = Column(String(512), nullable=True)
    notes: Optional[str] = Column(Text, nullable=True)  # Freeform notes about the project
    created_at: datetime = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    domains: List["Domain"] = relationship(
        "Domain", back_populates="company_ref", cascade="all, delete-orphan"
    )
    manual_ips: List["ManualIP"] = relationship(
        "ManualIP", back_populates="company_ref", cascade="all, delete-orphan"
    )
    mobile_apps: List["MobileApp"] = relationship(
        "MobileApp", back_populates="company_ref", cascade="all, delete-orphan"
    )
    api_assets: List["APIAsset"] = relationship(
        "APIAsset", back_populates="company_ref", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Company id={self.id} name={self.name!r} active={self.is_active}>"


class ManualIP(Base):
    """An IP address manually added to a company's attack surface."""

    __tablename__ = "manual_ips"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    company_id: int = Column(
        Integer, ForeignKey("companies.id", ondelete="CASCADE"), nullable=False, index=True
    )
    ip_address: str = Column(String(45), nullable=False)   # IPv4 or IPv6
    label: Optional[str] = Column(String(256), nullable=True)
    notes: Optional[str] = Column(Text, nullable=True)
    added_at: datetime = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    company_ref: "Company" = relationship("Company", back_populates="manual_ips")

    def __repr__(self) -> str:
        return f"<ManualIP id={self.id} ip={self.ip_address!r} company_id={self.company_id}>"


class Domain(Base):
    """A root domain that is being monitored."""

    __tablename__ = "domains"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    domain: str = Column(String(253), unique=True, nullable=False, index=True)
    added_at: datetime = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    last_scan: Optional[datetime] = Column(DateTime(timezone=True), nullable=True)
    scan_interval_minutes: int = Column(Integer, default=360, nullable=False)
    # FK added via ALTER TABLE migration for existing DBs; None = use global config
    profile_id: Optional[int] = Column(
        Integer, ForeignKey("scan_profiles.id", ondelete="SET NULL"), nullable=True
    )
    # FK to owning company — nullable so existing domains without a company still work
    company_id: Optional[int] = Column(
        Integer, ForeignKey("companies.id", ondelete="SET NULL"), nullable=True, index=True
    )
    # Scope boundary: "in_scope", "out_of_scope", "unknown"
    scope_type: str = Column(String(32), default="unknown", nullable=False, index=True)

    subdomains: List["Subdomain"] = relationship(
        "Subdomain", back_populates="domain_ref", cascade="all, delete-orphan"
    )
    company_ref: Optional["Company"] = relationship("Company", back_populates="domains")

    def __repr__(self) -> str:
        return f"<Domain id={self.id} domain={self.domain!r}>"


class Subdomain(Base):
    """A discovered subdomain (FQDN) associated with a root domain."""

    __tablename__ = "subdomains"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    domain_id: int = Column(
        Integer, ForeignKey("domains.id", ondelete="CASCADE"), nullable=False, index=True
    )
    fqdn: str = Column(String(253), unique=True, nullable=False, index=True)
    discovery_technique: Optional[str] = Column(String(64), nullable=True)
    first_seen: datetime = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    last_seen: Optional[datetime] = Column(DateTime(timezone=True), nullable=True)
    status: str = Column(String(32), default="unknown", nullable=False)

    # JSON columns
    ip_addresses: Optional[Any] = Column(JSONEncodedValue, nullable=True)
    technologies: Optional[Any] = Column(JSONEncodedValue, nullable=True)

    http_status: Optional[int] = Column(Integer, nullable=True)
    page_title: Optional[str] = Column(Text, nullable=True)
    classification: Optional[str] = Column(String(64), nullable=True)
    favicon_hash: Optional[str] = Column(String(128), nullable=True)
    body_hash: Optional[str] = Column(String(128), nullable=True)
    headers_hash: Optional[str] = Column(String(128), nullable=True)
    cert_fingerprint: Optional[str] = Column(String(128), nullable=True)
    takeover_vulnerable: bool = Column(Boolean, default=False, nullable=False)
    notes: Optional[str] = Column(Text, nullable=True)

    domain_ref: "Domain" = relationship("Domain", back_populates="subdomains")
    scans: List["SubdomainScan"] = relationship(
        "SubdomainScan", back_populates="subdomain_ref", cascade="all, delete-orphan"
    )
    endpoints: List["Endpoint"] = relationship(
        "Endpoint", back_populates="subdomain_ref", cascade="all, delete-orphan"
    )
    assets: List["Asset"] = relationship(
        "Asset", back_populates="subdomain_ref", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Subdomain id={self.id} fqdn={self.fqdn!r} status={self.status!r}>"


class SubdomainScan(Base):
    """A point-in-time scan record for a subdomain."""

    __tablename__ = "subdomain_scans"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    subdomain_id: int = Column(
        Integer,
        ForeignKey("subdomains.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scanned_at: datetime = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    status: str = Column(String(32), nullable=False, default="unknown")
    http_status: Optional[int] = Column(Integer, nullable=True)
    response_size: Optional[int] = Column(Integer, nullable=True)
    body_hash: Optional[str] = Column(String(128), nullable=True)

    # JSON columns
    technologies: Optional[Any] = Column(JSONEncodedValue, nullable=True)
    raw_headers: Optional[Any] = Column(JSONEncodedValue, nullable=True)
    dns_records: Optional[Any] = Column(JSONEncodedValue, nullable=True)
    dnssec_info: Optional[Any] = Column(JSONEncodedValue, nullable=True)
    email_security: Optional[Any] = Column(JSONEncodedValue, nullable=True)
    nameserver_security: Optional[Any] = Column(JSONEncodedValue, nullable=True)

    subdomain_ref: "Subdomain" = relationship("Subdomain", back_populates="scans")

    def __repr__(self) -> str:
        return (
            f"<SubdomainScan id={self.id} subdomain_id={self.subdomain_id} "
            f"scanned_at={self.scanned_at}>"
        )


class Endpoint(Base):
    """A URL endpoint discovered within a subdomain."""

    __tablename__ = "endpoints"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    subdomain_id: int = Column(
        Integer,
        ForeignKey("subdomains.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    path: str = Column(String(2048), nullable=False)
    method: str = Column(String(16), nullable=False, default="GET")
    content_type: Optional[str] = Column(String(128), nullable=True)
    status_code: Optional[int] = Column(Integer, nullable=True)
    first_seen: datetime = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    last_seen: Optional[datetime] = Column(DateTime(timezone=True), nullable=True)
    source: Optional[str] = Column(String(64), nullable=True)

    # JSON column
    parameters: Optional[Any] = Column(JSONEncodedValue, nullable=True)

    subdomain_ref: "Subdomain" = relationship("Subdomain", back_populates="endpoints")

    def __repr__(self) -> str:
        return (
            f"<Endpoint id={self.id} subdomain_id={self.subdomain_id} "
            f"method={self.method!r} path={self.path!r}>"
        )


class ChangeEvent(Base):
    """A detected change event for any monitored asset."""

    __tablename__ = "change_events"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    event_type: str = Column(String(64), nullable=False, index=True)
    severity: str = Column(String(16), nullable=False, index=True)
    target: str = Column(String(512), nullable=False)
    description: str = Column(Text, nullable=False)

    # JSON column
    diff_data: Optional[Any] = Column(JSONEncodedValue, nullable=True)

    detected_at: datetime = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    alerted: bool = Column(Boolean, default=False, nullable=False, index=True)
    alerted_at: Optional[datetime] = Column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return (
            f"<ChangeEvent id={self.id} type={self.event_type!r} "
            f"severity={self.severity!r} target={self.target!r}>"
        )


class PortScan(Base):
    """One nmap scan snapshot for a single host."""

    __tablename__ = "port_scans"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    host: str = Column(String(253), nullable=False, index=True)
    subdomain_id: Optional[int] = Column(
        Integer, ForeignKey("subdomains.id", ondelete="SET NULL"), nullable=True, index=True
    )
    scanned_at: datetime = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    status: str = Column(String(16), default="unknown", nullable=False)
    scan_duration: float = Column(Float, default=0.0, nullable=False)
    error: Optional[str] = Column(Text, nullable=True)

    open_ports: List["OpenPort"] = relationship(
        "OpenPort", back_populates="scan_ref", cascade="all, delete-orphan", lazy="select"
    )

    def __repr__(self) -> str:
        return f"<PortScan id={self.id} host={self.host!r} status={self.status!r}>"


class OpenPort(Base):
    """A single open port discovered within a PortScan."""

    __tablename__ = "open_ports"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    port_scan_id: int = Column(
        Integer, ForeignKey("port_scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    host: str = Column(String(253), nullable=False)
    port: int = Column(Integer, nullable=False)
    protocol: str = Column(String(8), default="tcp", nullable=False)
    state: str = Column(String(16), default="open", nullable=False)
    service: str = Column(String(64), default="", nullable=False)
    product: str = Column(String(128), default="", nullable=False)
    version: str = Column(String(64), default="", nullable=False)
    extra_info: str = Column(String(256), default="", nullable=False)

    scan_ref: "PortScan" = relationship("PortScan", back_populates="open_ports")

    def __repr__(self) -> str:
        return f"<OpenPort id={self.id} host={self.host!r} port={self.port}/{self.protocol}>"


class Asset(Base):
    """A static or dynamic asset (JS, CSS, image, etc.) linked to a subdomain."""

    __tablename__ = "assets"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    subdomain_id: int = Column(
        Integer,
        ForeignKey("subdomains.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    asset_url: str = Column(String(2048), nullable=False)
    asset_type: str = Column(String(64), nullable=False, default="unknown")
    content_hash: Optional[str] = Column(String(128), nullable=True)
    first_seen: datetime = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    last_seen: Optional[datetime] = Column(DateTime(timezone=True), nullable=True)
    last_changed: Optional[datetime] = Column(DateTime(timezone=True), nullable=True)

    subdomain_ref: "Subdomain" = relationship("Subdomain", back_populates="assets")

    def __repr__(self) -> str:
        return (
            f"<Asset id={self.id} subdomain_id={self.subdomain_id} "
            f"asset_type={self.asset_type!r} url={self.asset_url!r}>"
        )


class MobileApp(Base):
    """A mobile application asset (Android/iOS) owned by a company."""

    __tablename__ = "mobile_apps"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    company_id: int = Column(
        Integer, ForeignKey("companies.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: str = Column(String(256), nullable=False)
    platform: str = Column(String(32), nullable=False, index=True)  # android, ios
    package_name: Optional[str] = Column(String(256), nullable=True)  # com.example.app
    app_store_url: Optional[str] = Column(String(512), nullable=True)
    store_id: Optional[str] = Column(String(256), nullable=True)  # App Store / Play Store ID
    last_scan: Optional[datetime] = Column(DateTime(timezone=True), nullable=True)
    is_active: bool = Column(Boolean, default=True, nullable=False)
    notes: Optional[str] = Column(Text, nullable=True)
    created_at: datetime = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    # JSON columns
    app_metadata: Optional[Any] = Column(JSONEncodedValue, nullable=True)  # version, permissions, etc.
    security_issues: Optional[Any] = Column(JSONEncodedValue, nullable=True)  # found vulnerabilities

    company_ref: "Company" = relationship("Company", back_populates="mobile_apps")

    def __repr__(self) -> str:
        return f"<MobileApp id={self.id} name={self.name!r} platform={self.platform!r}>"


class APIAsset(Base):
    """An API endpoint or API documentation asset owned by a company."""

    __tablename__ = "api_assets"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    company_id: int = Column(
        Integer, ForeignKey("companies.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: str = Column(String(256), nullable=False)
    base_url: str = Column(String(512), nullable=False)
    api_type: str = Column(String(64), nullable=False, index=True)  # rest, graphql, grpc, soap
    specification_url: Optional[str] = Column(String(512), nullable=True)  # swagger.json, openapi.yaml
    authentication: Optional[str] = Column(String(128), nullable=True)  # bearer, api_key, oauth, none
    is_public: bool = Column(Boolean, default=False, nullable=False)
    last_scan: Optional[datetime] = Column(DateTime(timezone=True), nullable=True)
    is_active: bool = Column(Boolean, default=True, nullable=False)
    notes: Optional[str] = Column(Text, nullable=True)
    created_at: datetime = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    # JSON columns
    endpoints: Optional[Any] = Column(JSONEncodedValue, nullable=True)  # discovered endpoints
    security_issues: Optional[Any] = Column(JSONEncodedValue, nullable=True)  # found vulnerabilities
    headers: Optional[Any] = Column(JSONEncodedValue, nullable=True)  # discovered headers

    company_ref: "Company" = relationship("Company", back_populates="api_assets")

    def __repr__(self) -> str:
        return f"<APIAsset id={self.id} name={self.name!r} type={self.api_type!r} url={self.base_url!r}>"


class ScanProfile(Base):
    """A named scan profile controlling enumeration, port-scan, and crawl behaviour."""

    __tablename__ = "scan_profiles"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    name: str = Column(String(64), unique=True, nullable=False, index=True)
    description: Optional[str] = Column(Text, nullable=True)
    is_builtin: bool = Column(Boolean, default=False, nullable=False)
    settings: Optional[Any] = Column(JSONEncodedValue, nullable=True)
    created_at: datetime = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    def __repr__(self) -> str:
        return f"<ScanProfile id={self.id} name={self.name!r} builtin={self.is_builtin}>"


class AppSetting(Base):
    """Key-value store for runtime-configurable settings (DB overrides YAML config)."""

    __tablename__ = "app_settings"

    key: str = Column(String(128), primary_key=True)
    value: Optional[str] = Column(Text, nullable=True)
    updated_at: datetime = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    def __repr__(self) -> str:
        return f"<AppSetting key={self.key!r}>"


class GitHubMonitoredRepo(Base):
    """GitHub repositories under monitoring."""

    __tablename__ = "github_monitored_repos"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    organization: str = Column(String(255), nullable=False, index=True)
    repository: str = Column(String(255), nullable=False, index=True)
    full_name: str = Column(String(511), nullable=False)  # org/repo
    monitor_secrets: bool = Column(Boolean, default=True, nullable=False)
    monitor_dangerous_functions: bool = Column(Boolean, default=True, nullable=False)
    monitor_issues: bool = Column(Boolean, default=True, nullable=False)
    monitor_wiki: bool = Column(Boolean, default=True, nullable=False)
    monitor_gists: bool = Column(Boolean, default=False, nullable=False)
    last_commit_hash: Optional[str] = Column(String(64), nullable=True)
    last_scan_timestamp: Optional[datetime] = Column(DateTime(timezone=True), nullable=True)
    alert_on_new_repos: bool = Column(Boolean, default=False, nullable=False)
    created_at: datetime = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at: datetime = Column(
        DateTime(timezone=True),
        default=_utcnow,
        onupdate=_utcnow,
        nullable=False
    )

    # Relationship
    findings: List["GitHubFinding"] = relationship(
        "GitHubFinding",
        back_populates="repo",
        cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint('organization', 'repository', name='uix_github_repo'),
        Index('ix_github_full_name', 'full_name'),
    )

    def __repr__(self) -> str:
        return f"<GitHubMonitoredRepo id={self.id} full_name={self.full_name!r}>"


class GitHubFinding(Base):
    """Security findings from GitHub monitoring."""

    __tablename__ = "github_findings"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    repo_id: int = Column(
        Integer,
        ForeignKey('github_monitored_repos.id', ondelete='CASCADE'),
        nullable=False,
        index=True
    )
    finding_type: str = Column(String(50), nullable=False, index=True)  # 'secret', 'dangerous_function', 'sensitive_data'
    severity: str = Column(String(20), nullable=False, index=True)  # CRITICAL, HIGH, MEDIUM, LOW
    file_path: str = Column(String(1024), nullable=False)
    line_number: Optional[int] = Column(Integer, nullable=True)
    commit_hash: Optional[str] = Column(String(64), nullable=True, index=True)
    commit_url: Optional[str] = Column(String(512), nullable=True)
    author: Optional[str] = Column(String(255), nullable=True)
    timestamp: datetime = Column(DateTime(timezone=True), default=_utcnow, nullable=False, index=True)
    pattern_name: str = Column(String(255), nullable=False)
    matched_text: Optional[str] = Column(Text, nullable=True)
    context_before: Optional[str] = Column(Text, nullable=True)
    context_after: Optional[str] = Column(Text, nullable=True)
    false_positive: bool = Column(Boolean, default=False, nullable=False, index=True)
    reviewed: bool = Column(Boolean, default=False, nullable=False)
    notes: Optional[str] = Column(Text, nullable=True)

    # Relationship
    repo: "GitHubMonitoredRepo" = relationship("GitHubMonitoredRepo", back_populates="findings")

    __table_args__ = (
        Index('ix_github_finding_type_severity', 'finding_type', 'severity'),
        Index('ix_github_finding_timestamp', 'timestamp'),
        CheckConstraint(
            "severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')",
            name='ck_github_severity'
        ),
        CheckConstraint(
            "finding_type IN ('secret', 'dangerous_function', 'sensitive_data')",
            name='ck_github_finding_type'
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<GitHubFinding id={self.id} type={self.finding_type!r} "
            f"severity={self.severity!r}>"
        )


def _apply_config_overrides(model: Any, overrides: Dict[str, Any]) -> None:
    """Recursively set override values on a Pydantic model tree."""
    import logging as _logging
    _log = _logging.getLogger(__name__)
    for key, value in overrides.items():
        if isinstance(value, dict) and hasattr(model, key):
            sub = getattr(model, key)
            if sub is not None:
                _apply_config_overrides(sub, value)
        elif hasattr(model, key):
            try:
                setattr(model, key, value)
            except Exception as exc:
                _log.warning(
                    "Config override ignored — %s=%r: %s", key, value, exc
                )


# Built-in profile definitions — seeded once on first run.
_BUILTIN_PROFILES: List[Dict[str, Any]] = [
    {
        "id": 1,
        "name": "Passive Only",
        "description": "No active probing. CT logs, Wayback Machine, and passive DNS only. Zero noise on the target.",
        "is_builtin": True,
        "settings": {
            "scan_mode": "passive",
            "enumeration": {
                "certificate_transparency": True,
                "dns_bruteforce": False,
                "passive_dns": True,
                "wayback_machine": True,
                "ssl_san_extraction": False,
                "js_analysis": False,
                "zone_transfer": False,
                "reverse_ip": False,
                "dns_records": False,
            },
            "port_scanning": {"enabled": False, "arguments": ""},
            "crawl": {"enabled": False, "max_depth": 0, "max_pages": 0},
        },
    },
    {
        "id": 2,
        "name": "Stealth",
        "description": "Low-and-slow active scanning. Reduced techniques, slow nmap timing, shallow crawl. Minimises detection footprint.",
        "is_builtin": True,
        "settings": {
            "scan_mode": "stealth",
            "enumeration": {
                "certificate_transparency": True,
                "dns_bruteforce": False,
                "passive_dns": True,
                "wayback_machine": True,
                "ssl_san_extraction": True,
                "js_analysis": False,
                "zone_transfer": False,
                "reverse_ip": False,
                "dns_records": True,
            },
            "port_scanning": {"enabled": True, "arguments": "-sT -T2 --open"},
            "crawl": {"enabled": True, "max_depth": 2, "max_pages": 100},
        },
    },
    {
        "id": 3,
        "name": "Standard",
        "description": "Balanced default. All major enumeration techniques, TCP connect port scan, full crawl.",
        "is_builtin": True,
        "settings": {
            "scan_mode": "open",
            "enumeration": {
                "certificate_transparency": True,
                "dns_bruteforce": True,
                "passive_dns": True,
                "wayback_machine": True,
                "ssl_san_extraction": True,
                "js_analysis": True,
                "zone_transfer": True,
                "reverse_ip": True,
                "dns_records": True,
            },
            "port_scanning": {"enabled": True, "arguments": "-sT -T4 -sV --version-intensity 2 --open"},
            "crawl": {"enabled": True, "max_depth": 3, "max_pages": 500},
        },
    },
    {
        "id": 4,
        "name": "Aggressive",
        "description": "Full enumeration, aggressive port scanning with version/script detection, deep crawl. Authorised engagements only.",
        "is_builtin": True,
        "settings": {
            "scan_mode": "aggressive",
            "enumeration": {
                "certificate_transparency": True,
                "dns_bruteforce": True,
                "passive_dns": True,
                "wayback_machine": True,
                "ssl_san_extraction": True,
                "js_analysis": True,
                "zone_transfer": True,
                "reverse_ip": True,
                "dns_records": True,
            },
            "port_scanning": {"enabled": True, "arguments": "-sT -T5 -sV -sC --open"},
            "crawl": {"enabled": True, "max_depth": 5, "max_pages": 1000},
        },
    },
]


# ---------------------------------------------------------------------------
# DatabaseManager
# ---------------------------------------------------------------------------

class DatabaseManager:
    """High-level interface for all database operations.

    All public methods open and close their own session internally unless
    a session is explicitly supplied via ``get_session()``.

    Args:
        db_path: Path to the SQLite database file, e.g. ``"./data/monitor.db"``.
                 Use ``":memory:"`` for an in-memory database (useful in tests).
    """

    def __init__(self, db_path: str) -> None:
        connect_args: Dict[str, Any] = {}
        if not db_path.startswith(":memory:"):
            # Enable WAL mode for better concurrent read/write performance.
            connect_args["check_same_thread"] = False

        self._engine = create_engine(
            f"sqlite:///{db_path}",
            connect_args=connect_args,
            echo=False,
        )

        # Enable journal mode and foreign-key enforcement for every
        # new SQLite connection. Journal mode can be overridden via
        # SQLITE_JOURNAL_MODE env var (useful for Docker on Windows).
        import os
        journal_mode = os.getenv("SQLITE_JOURNAL_MODE", "WAL")
        @event.listens_for(self._engine, "connect")
        def _set_sqlite_pragmas(dbapi_conn: Any, _connection_record: Any) -> None:
            cursor = dbapi_conn.cursor()
            cursor.execute(f"PRAGMA journal_mode={journal_mode}")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        self._Session = sessionmaker(bind=self._engine, expire_on_commit=False)
        Base.metadata.create_all(self._engine)
        self._run_migrations()
        self.seed_builtin_profiles()

    # ------------------------------------------------------------------
    # Session helper
    # ------------------------------------------------------------------

    @contextmanager
    def get_session(self) -> Generator[Session, None, None]:
        """Provide a transactional scope around a series of operations.

        Yields:
            An active :class:`sqlalchemy.orm.Session`.

        The session is committed on success and rolled back on any exception.
        It is always closed when the context manager exits.
        """
        session: Session = self._Session()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    # ------------------------------------------------------------------
    # Schema migration (SQLite-safe column additions)
    # ------------------------------------------------------------------

    def _run_migrations(self) -> None:
        """Apply additive schema changes to existing databases."""
        with self._engine.connect() as conn:
            # Add profile_id to domains if missing
            rows = conn.execute(
                __import__("sqlalchemy").text("PRAGMA table_info(domains)")
            ).fetchall()
            existing_cols = {r[1] for r in rows}
            if "profile_id" not in existing_cols:
                conn.execute(
                    __import__("sqlalchemy").text(
                        "ALTER TABLE domains ADD COLUMN profile_id INTEGER "
                        "REFERENCES scan_profiles(id) ON DELETE SET NULL"
                    )
                )

            # Add scope_type to domains if missing
            rows = conn.execute(
                __import__("sqlalchemy").text("PRAGMA table_info(domains)")
            ).fetchall()
            existing_cols = {r[1] for r in rows}
            if "scope_type" not in existing_cols:
                conn.execute(
                    __import__("sqlalchemy").text(
                        "ALTER TABLE domains ADD COLUMN scope_type VARCHAR(32) DEFAULT 'unknown' NOT NULL"
                    )
                )

            # Add company_id to domains if missing
            rows = conn.execute(
                __import__("sqlalchemy").text("PRAGMA table_info(domains)")
            ).fetchall()
            existing_cols = {r[1] for r in rows}
            if "company_id" not in existing_cols:
                conn.execute(
                    __import__("sqlalchemy").text(
                        "ALTER TABLE domains ADD COLUMN company_id INTEGER "
                        "REFERENCES companies(id) ON DELETE SET NULL"
                    )
                )
                # Create index on company_id for faster lookups
                conn.execute(
                    __import__("sqlalchemy").text(
                        "CREATE INDEX IF NOT EXISTS ix_domains_company_id ON domains(company_id)"
                    )
                )

            # Add notes to companies if missing
            rows = conn.execute(
                __import__("sqlalchemy").text("PRAGMA table_info(companies)")
            ).fetchall()
            existing_cols = {r[1] for r in rows}
            if "notes" not in existing_cols:
                conn.execute(
                    __import__("sqlalchemy").text(
                        "ALTER TABLE companies ADD COLUMN notes TEXT"
                    )
                )

            conn.commit()

    # ------------------------------------------------------------------
    # Scan profile operations
    # ------------------------------------------------------------------

    def seed_builtin_profiles(self) -> None:
        """Insert built-in profiles if they don't exist yet."""
        with self.get_session() as session:
            for p in _BUILTIN_PROFILES:
                existing = session.scalar(
                    select(ScanProfile).where(ScanProfile.id == p["id"])
                )
                if existing is None:
                    obj = ScanProfile(
                        id=p["id"],
                        name=p["name"],
                        description=p["description"],
                        is_builtin=p["is_builtin"],
                        settings=p["settings"],
                    )
                    session.add(obj)

    def get_all_profiles(self) -> List["ScanProfile"]:
        """Return all scan profiles ordered built-ins first, then by name."""
        with self.get_session() as session:
            return list(
                session.scalars(
                    select(ScanProfile).order_by(
                        ScanProfile.is_builtin.desc(), ScanProfile.name
                    )
                ).all()
            )

    def get_profile(self, profile_id: int) -> Optional["ScanProfile"]:
        with self.get_session() as session:
            return session.scalar(
                select(ScanProfile).where(ScanProfile.id == profile_id)
            )

    def create_profile(
        self,
        name: str,
        description: str,
        settings: Dict[str, Any],
    ) -> "ScanProfile":
        with self.get_session() as session:
            obj = ScanProfile(
                name=name,
                description=description,
                is_builtin=False,
                settings=settings,
            )
            session.add(obj)
            session.flush()
            session.refresh(obj)
            return obj

    def update_profile(
        self, profile_id: int, **kwargs: Any
    ) -> Optional["ScanProfile"]:
        with self.get_session() as session:
            obj = session.scalar(
                select(ScanProfile).where(ScanProfile.id == profile_id)
            )
            if obj is None or obj.is_builtin:
                return None
            for k, v in kwargs.items():
                if hasattr(obj, k):
                    setattr(obj, k, v)
            session.flush()
            session.refresh(obj)
            return obj

    def delete_profile(self, profile_id: int) -> bool:
        with self.get_session() as session:
            obj = session.scalar(
                select(ScanProfile).where(ScanProfile.id == profile_id)
            )
            if obj is None or obj.is_builtin:
                return False
            session.delete(obj)
            return True

    def set_domain_profile(
        self, domain_id: int, profile_id: Optional[int]
    ) -> bool:
        """Assign (or clear) a scan profile for a domain. Returns False if domain not found."""
        with self.get_session() as session:
            obj = session.get(Domain, domain_id)
            if obj is None:
                return False
            obj.profile_id = profile_id
            return True

    def set_domain_scope(
        self, domain_id: int, scope_type: str
    ) -> bool:
        """Set scope boundary for a domain. scope_type: in_scope, out_of_scope, unknown."""
        if scope_type not in ("in_scope", "out_of_scope", "unknown"):
            return False
        with self.get_session() as session:
            obj = session.get(Domain, domain_id)
            if obj is None:
                return False
            obj.scope_type = scope_type
            return True

    def get_domain_details(self, domain_id: int) -> Optional[Dict[str, Any]]:
        """Return full detail payload for a single domain: subdomains, ports, changes, profile."""
        from datetime import timedelta
        from sqlalchemy import case as sa_case

        with self.get_session() as session:
            dom = session.get(Domain, domain_id)
            if dom is None:
                return None

            profile = None
            if dom.profile_id:
                profile = session.get(ScanProfile, dom.profile_id)

            subs = list(
                session.scalars(
                    select(Subdomain)
                    .where(Subdomain.domain_id == domain_id)
                    .order_by(Subdomain.fqdn)
                ).all()
            )

            # Latest port scan per subdomain FQDN
            subq = (
                select(PortScan.host, func.max(PortScan.scanned_at).label("max_at"))
                .group_by(PortScan.host)
                .subquery()
            )
            port_scans = list(
                session.scalars(
                    select(PortScan)
                    .join(
                        subq,
                        (PortScan.host == subq.c.host)
                        & (PortScan.scanned_at == subq.c.max_at),
                    )
                    .where(PortScan.host.in_([s.fqdn for s in subs]))
                    .options(selectinload(PortScan.open_ports))
                    .order_by(PortScan.host)
                ).all()
            )

            cutoff = _utcnow() - timedelta(days=7)
            sub_fqdns = [s.fqdn for s in subs]
            changes = list(
                session.scalars(
                    select(ChangeEvent)
                    .where(
                        ChangeEvent.detected_at >= cutoff,
                        ChangeEvent.target.in_(sub_fqdns + [dom.domain]),
                    )
                    .order_by(ChangeEvent.detected_at.desc())
                ).all()
            )

        # Build host → ports map
        host_ports: Dict[str, list] = {}
        for ps in port_scans:
            host_ports[ps.host] = [
                {
                    "port": p.port,
                    "protocol": p.protocol,
                    "state": p.state,
                    "service": p.service,
                    "product": p.product,
                    "version": p.version,
                    "extra_info": p.extra_info,
                }
                for p in sorted(ps.open_ports, key=lambda x: x.port)
            ]

        live_count = sum(1 for s in subs if s.status == "alive")
        open_port_count = sum(len(v) for v in host_ports.values())

        return {
            "domain": {
                "id": dom.id,
                "domain": dom.domain,
                "added_at": dom.added_at.isoformat() if dom.added_at else None,
                "last_scan": dom.last_scan.isoformat() if dom.last_scan else None,
                "profile_id": dom.profile_id,
                "profile_name": profile.name if profile else None,
                "profile_mode": (profile.settings or {}).get("scan_mode") if profile else None,
            },
            "stats": {
                "total_subs": len(subs),
                "live_subs": live_count,
                "open_ports": open_port_count,
                "events_7d": len(changes),
            },
            "subdomains": [
                {
                    "id": s.id,
                    "fqdn": s.fqdn,
                    "status": s.status,
                    "http_status": s.http_status,
                    "ip_addresses": s.ip_addresses or [],
                    "technologies": s.technologies or [],
                    "classification": s.classification,
                    "page_title": s.page_title,
                    "takeover_vulnerable": s.takeover_vulnerable,
                    "first_seen": s.first_seen.isoformat() if s.first_seen else None,
                    "last_seen": s.last_seen.isoformat() if s.last_seen else None,
                    "open_ports": host_ports.get(s.fqdn, []),
                }
                for s in subs
            ],
            "port_scans": [
                {
                    "host": ps.host,
                    "status": ps.status,
                    "scanned_at": ps.scanned_at.isoformat() if ps.scanned_at else None,
                    "scan_duration": ps.scan_duration,
                    "error": ps.error,
                    "ports": host_ports.get(ps.host, []),
                }
                for ps in port_scans
            ],
            "recent_changes": [
                {
                    "id": e.id,
                    "event_type": e.event_type,
                    "severity": e.severity,
                    "target": e.target,
                    "description": e.description,
                    "detected_at": e.detected_at.isoformat() if e.detected_at else None,
                    "alerted": e.alerted,
                    "diff_data": e.diff_data,
                }
                for e in changes
            ],
        }

    # ------------------------------------------------------------------
    # Domain operations
    # ------------------------------------------------------------------

    def add_domain(self, domain: str, company_id: Optional[int] = None) -> Domain:
        """Add a new root domain to the database.

        If the domain already exists the existing record is returned without
        modification (and company_id is NOT updated).

        Args:
            domain: The root domain name, e.g. ``"example.com"``.
            company_id: Optional company (project) ID to associate with this domain.

        Returns:
            The :class:`Domain` ORM object (persisted).
        """
        with self.get_session() as session:
            existing = session.scalar(select(Domain).where(Domain.domain == domain))
            if existing is not None:
                return existing
            obj = Domain(domain=domain, company_id=company_id)
            session.add(obj)
            session.flush()
            # Refresh to populate auto-generated fields before the session closes.
            session.refresh(obj)
            return obj

    def get_domain(self, domain: str) -> Optional[Domain]:
        """Retrieve a root domain by its name.

        Args:
            domain: The root domain name to look up.

        Returns:
            The :class:`Domain` object or ``None`` if not found.
        """
        with self.get_session() as session:
            return session.scalar(select(Domain).where(Domain.domain == domain))

    def get_all_domains(self) -> List[Domain]:
        """Return all monitored root domains.

        Returns:
            A list of :class:`Domain` objects, possibly empty.
        """
        with self.get_session() as session:
            return list(session.scalars(select(Domain)).all())

    # ------------------------------------------------------------------
    # Subdomain operations
    # ------------------------------------------------------------------

    def upsert_subdomain(
        self, fqdn: str, domain_id: int, **kwargs: Any
    ) -> Tuple[Subdomain, bool]:
        """Insert or update a subdomain record.

        Args:
            fqdn: Fully qualified domain name, e.g. ``"api.example.com"``.
            domain_id: Foreign key referencing the parent :class:`Domain`.
            **kwargs: Any additional :class:`Subdomain` column values to set
                (e.g. ``status="alive"``, ``http_status=200``).

        Returns:
            A ``(subdomain, is_new)`` tuple where *is_new* is ``True`` when
            the record was inserted for the first time.
        """
        with self.get_session() as session:
            obj = session.scalar(select(Subdomain).where(Subdomain.fqdn == fqdn))
            is_new = obj is None

            if is_new:
                obj = Subdomain(fqdn=fqdn, domain_id=domain_id)
                session.add(obj)

            # Apply keyword arguments as attribute updates.
            for key, value in kwargs.items():
                if hasattr(obj, key):
                    setattr(obj, key, value)

            # Always update last_seen timestamp.
            obj.last_seen = _utcnow()

            session.flush()
            session.refresh(obj)
            return obj, is_new

    def get_subdomain(self, fqdn: str) -> Optional[Subdomain]:
        """Retrieve a subdomain by its FQDN.

        Args:
            fqdn: The fully qualified domain name to look up.

        Returns:
            The :class:`Subdomain` object or ``None`` if not found.
        """
        with self.get_session() as session:
            return session.scalar(select(Subdomain).where(Subdomain.fqdn == fqdn))

    def get_live_subdomains(self, domain_id: int) -> List[Subdomain]:
        """Return all subdomains with status ``'alive'`` for a root domain.

        Args:
            domain_id: The primary key of the parent :class:`Domain`.

        Returns:
            A list of live :class:`Subdomain` objects.
        """
        with self.get_session() as session:
            return list(
                session.scalars(
                    select(Subdomain).where(
                        Subdomain.domain_id == domain_id,
                        Subdomain.status == "alive",
                    )
                ).all()
            )

    # ------------------------------------------------------------------
    # Scan record operations
    # ------------------------------------------------------------------

    def add_scan_record(self, subdomain_id: int, **kwargs: Any) -> SubdomainScan:
        """Append a new scan record for a subdomain.

        Args:
            subdomain_id: FK referencing the scanned :class:`Subdomain`.
            **kwargs: Column values for the new :class:`SubdomainScan` row.

        Returns:
            The newly created :class:`SubdomainScan` object.
        """
        with self.get_session() as session:
            obj = SubdomainScan(subdomain_id=subdomain_id, **kwargs)
            session.add(obj)
            session.flush()
            session.refresh(obj)
            return obj

    def get_latest_subdomain_scan(self, subdomain_id: int) -> Optional[SubdomainScan]:
        """Return the most recent :class:`SubdomainScan` for a subdomain, or ``None``."""
        with self.get_session() as session:
            return session.scalar(
                select(SubdomainScan)
                .where(SubdomainScan.subdomain_id == subdomain_id)
                .order_by(SubdomainScan.scanned_at.desc())
                .limit(1)
            )

    # ------------------------------------------------------------------
    # Endpoint operations
    # ------------------------------------------------------------------

    def upsert_endpoint(
        self, subdomain_id: int, path: str, method: str = "GET", **kwargs: Any
    ) -> Tuple[Endpoint, bool]:
        """Insert or update an endpoint record.

        Endpoints are uniquely identified by the combination of
        ``(subdomain_id, path, method)``.

        Args:
            subdomain_id: FK referencing the parent :class:`Subdomain`.
            path: URL path, e.g. ``"/api/v1/users"``.
            method: HTTP method (default ``"GET"``).
            **kwargs: Additional :class:`Endpoint` column values.

        Returns:
            A ``(endpoint, is_new)`` tuple.
        """
        with self.get_session() as session:
            obj = session.scalar(
                select(Endpoint).where(
                    Endpoint.subdomain_id == subdomain_id,
                    Endpoint.path == path,
                    Endpoint.method == method,
                )
            )
            is_new = obj is None

            if is_new:
                obj = Endpoint(subdomain_id=subdomain_id, path=path, method=method)
                session.add(obj)

            for key, value in kwargs.items():
                if hasattr(obj, key):
                    setattr(obj, key, value)

            obj.last_seen = _utcnow()

            session.flush()
            session.refresh(obj)
            return obj, is_new

    def get_endpoints(self, subdomain_id: int) -> List[Endpoint]:
        """Return all endpoints for a subdomain.

        Args:
            subdomain_id: The primary key of the parent :class:`Subdomain`.

        Returns:
            A list of :class:`Endpoint` objects.
        """
        with self.get_session() as session:
            return list(
                session.scalars(
                    select(Endpoint).where(Endpoint.subdomain_id == subdomain_id)
                ).all()
            )

    # ------------------------------------------------------------------
    # Change event operations
    # ------------------------------------------------------------------

    def add_change_event(
        self,
        event_type: str,
        severity: str,
        target: str,
        description: str,
        diff_data: Optional[Any] = None,
    ) -> ChangeEvent:
        """Record a newly detected change event.

        Args:
            event_type: Short event category, e.g. ``"NEW_SUBDOMAIN"``.
            severity: ``"INFO"``, ``"LOW"``, ``"MEDIUM"``, ``"HIGH"``,
                      or ``"CRITICAL"``.
            target: The FQDN or URL that changed.
            description: Human-readable description of what changed.
            diff_data: Arbitrary dict/list with structured diff information.

        Returns:
            The persisted :class:`ChangeEvent` object.
        """
        with self.get_session() as session:
            obj = ChangeEvent(
                event_type=event_type,
                severity=severity,
                target=target,
                description=description,
                diff_data=diff_data,
            )
            session.add(obj)
            session.flush()
            session.refresh(obj)
            return obj

    def get_unalerted_events(self) -> List[ChangeEvent]:
        """Return all change events that have not yet been sent as alerts.

        Returns:
            A list of :class:`ChangeEvent` objects with ``alerted=False``,
            ordered oldest-first.
        """
        with self.get_session() as session:
            return list(
                session.scalars(
                    select(ChangeEvent)
                    .where(ChangeEvent.alerted == False)  # noqa: E712
                    .order_by(ChangeEvent.detected_at)
                ).all()
            )

    def mark_events_alerted(self, event_ids: List[int]) -> None:
        """Mark a batch of change events as alerted.

        Args:
            event_ids: Primary keys of the :class:`ChangeEvent` rows to update.
        """
        if not event_ids:
            return
        now = _utcnow()
        with self.get_session() as session:
            session.execute(
                update(ChangeEvent)
                .where(ChangeEvent.id.in_(event_ids))
                .values(alerted=True, alerted_at=now)
            )

    # ------------------------------------------------------------------
    # Asset operations
    # ------------------------------------------------------------------

    def upsert_asset(
        self,
        subdomain_id: int,
        asset_url: str,
        asset_type: str,
        content_hash: Optional[str],
    ) -> Tuple[Asset, bool]:
        """Insert or update an asset record, tracking content-hash changes.

        Assets are uniquely identified by ``(subdomain_id, asset_url)``.

        Args:
            subdomain_id: FK referencing the parent :class:`Subdomain`.
            asset_url: Absolute URL of the asset.
            asset_type: MIME category or file extension hint, e.g. ``"js"``.
            content_hash: Hash of the asset body (``None`` if unavailable).

        Returns:
            A ``(asset, changed)`` tuple where *changed* is ``True`` when the
            ``content_hash`` differs from the previously stored value.
        """
        now = _utcnow()
        with self.get_session() as session:
            obj = session.scalar(
                select(Asset).where(
                    Asset.subdomain_id == subdomain_id,
                    Asset.asset_url == asset_url,
                )
            )

            if obj is None:
                obj = Asset(
                    subdomain_id=subdomain_id,
                    asset_url=asset_url,
                    asset_type=asset_type,
                    content_hash=content_hash,
                    last_seen=now,
                )
                session.add(obj)
                session.flush()
                session.refresh(obj)
                return obj, False  # brand-new asset — not a "change" per se

            changed = obj.content_hash != content_hash
            obj.asset_type = asset_type
            obj.last_seen = now

            if changed:
                obj.content_hash = content_hash
                obj.last_changed = now

            session.flush()
            session.refresh(obj)
            return obj, changed

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def get_recent_events(self, hours: int = 24) -> List[ChangeEvent]:
        """Return change events detected within the last *hours* hours.

        Args:
            hours: Look-back window in hours (default 24).

        Returns:
            A list of :class:`ChangeEvent` objects ordered newest-first.
        """
        from datetime import timedelta

        cutoff = _utcnow() - timedelta(hours=hours)
        with self.get_session() as session:
            return list(
                session.scalars(
                    select(ChangeEvent)
                    .where(ChangeEvent.detected_at >= cutoff)
                    .order_by(ChangeEvent.detected_at.desc())
                ).all()
            )

    # ------------------------------------------------------------------
    # Port scan operations
    # ------------------------------------------------------------------

    def add_port_scan(
        self,
        host: str,
        subdomain_id: Optional[int] = None,
        status: str = "unknown",
        scan_duration: float = 0.0,
        error: Optional[str] = None,
        ports: Optional[List[Dict[str, Any]]] = None,
    ) -> "PortScan":
        """Persist one port scan result and its open ports.

        Args:
            host:          IP or FQDN that was scanned.
            subdomain_id:  FK to the Subdomain row (if known).
            status:        nmap host state: ``"up"``, ``"down"``, ``"error"``.
            scan_duration: Wall-clock seconds the scan took.
            error:         Error message if the scan failed.
            ports:         List of port dicts from the scanner
                           (keys: port, protocol, state, service, product,
                           version, extrainfo).

        Returns:
            The new :class:`PortScan` row.
        """
        with self.get_session() as session:
            scan = PortScan(
                host=host,
                subdomain_id=subdomain_id,
                status=status,
                scan_duration=scan_duration,
                error=error,
            )
            session.add(scan)
            session.flush()
            for p in ports or []:
                session.add(OpenPort(
                    port_scan_id=scan.id,
                    host=host,
                    port=int(p.get("port", 0)),
                    protocol=str(p.get("protocol", "tcp")),
                    state=str(p.get("state", "open")),
                    service=str(p.get("service", "")),
                    product=str(p.get("product", "")),
                    version=str(p.get("version", "")),
                    extra_info=str(p.get("extrainfo", "")),
                ))
            session.flush()
            session.refresh(scan)
            return scan

    def get_latest_port_scan(self, host: str) -> Optional["PortScan"]:
        """Return the most recent :class:`PortScan` for *host*, or ``None``."""
        with self.get_session() as session:
            return session.scalar(
                select(PortScan)
                .where(PortScan.host == host)
                .order_by(PortScan.scanned_at.desc())
                .limit(1)
            )

    def get_open_ports_for_scan(self, port_scan_id: int) -> List["OpenPort"]:
        """Return all :class:`OpenPort` rows for a given scan ID."""
        with self.get_session() as session:
            return list(
                session.scalars(
                    select(OpenPort).where(OpenPort.port_scan_id == port_scan_id)
                ).all()
            )

    def get_all_latest_port_scans(self) -> List["PortScan"]:
        """Return the latest :class:`PortScan` for every distinct host."""
        with self.get_session() as session:
            subq = (
                select(PortScan.host, func.max(PortScan.scanned_at).label("max_at"))
                .group_by(PortScan.host)
                .subquery()
            )
            rows = session.scalars(
                select(PortScan)
                .join(
                    subq,
                    (PortScan.host == subq.c.host)
                    & (PortScan.scanned_at == subq.c.max_at),
                )
                .options(selectinload(PortScan.open_ports))
                .order_by(PortScan.host)
            ).all()
            return list(rows)

    def get_dashboard_summary(self) -> Dict[str, Any]:
        """Return aggregated stats used by the web dashboard summary cards."""
        from datetime import timedelta

        cutoff_24h = _utcnow() - timedelta(hours=24)

        with self.get_session() as session:
            total_domains = session.scalar(select(func.count(Domain.id))) or 0
            total_subs = session.scalar(select(func.count(Subdomain.id))) or 0
            live_subs = session.scalar(
                select(func.count(Subdomain.id)).where(Subdomain.status == "alive")
            ) or 0
            total_open_ports = session.scalar(select(func.count(OpenPort.id))) or 0
            hosts_scanned = session.scalar(
                select(func.count(func.distinct(PortScan.host)))
            ) or 0
            events_24h = session.scalar(
                select(func.count(ChangeEvent.id)).where(
                    ChangeEvent.detected_at >= cutoff_24h
                )
            ) or 0
            critical_24h = session.scalar(
                select(func.count(ChangeEvent.id)).where(
                    ChangeEvent.detected_at >= cutoff_24h,
                    ChangeEvent.severity == "CRITICAL",
                )
            ) or 0
            high_24h = session.scalar(
                select(func.count(ChangeEvent.id)).where(
                    ChangeEvent.detected_at >= cutoff_24h,
                    ChangeEvent.severity == "HIGH",
                )
            ) or 0
            last_scan_row = session.scalar(
                select(PortScan.scanned_at).order_by(PortScan.scanned_at.desc()).limit(1)
            )

        return {
            "domains": total_domains,
            "subdomains_total": total_subs,
            "subdomains_live": live_subs,
            "open_ports_total": total_open_ports,
            "hosts_scanned": hosts_scanned,
            "events_24h": events_24h,
            "critical_24h": critical_24h,
            "high_24h": high_24h,
            "last_port_scan": last_scan_row.isoformat() if last_scan_row else None,
        }

    def get_events_by_severity(self, severity: str) -> List[ChangeEvent]:
        """Return all change events matching a specific severity level.

        Args:
            severity: One of ``"INFO"``, ``"LOW"``, ``"MEDIUM"``, ``"HIGH"``,
                      ``"CRITICAL"`` (case-insensitive).

        Returns:
            A list of matching :class:`ChangeEvent` objects, newest-first.
        """
        with self.get_session() as session:
            return list(
                session.scalars(
                    select(ChangeEvent)
                    .where(ChangeEvent.severity == severity.upper())
                    .order_by(ChangeEvent.detected_at.desc())
                ).all()
            )

    def delete_domain(self, domain_id: int) -> bool:
        """Delete a root domain and cascade-delete all its subdomains and events.

        Returns True if the domain was found and deleted, False if not found.
        """
        with self.get_session() as session:
            obj = session.get(Domain, domain_id)
            if obj is None:
                return False
            session.delete(obj)
            return True

    def get_all_domains_with_stats(self) -> List[Dict[str, Any]]:
        """Return all root domains with subdomain counts, last scan time, and assigned profile."""
        from sqlalchemy import case as sa_case
        with self.get_session() as session:
            rows = session.execute(
                select(
                    Domain.id,
                    Domain.domain,
                    Domain.added_at,
                    Domain.last_scan,
                    Domain.profile_id,
                    Domain.scope_type,
                    ScanProfile.name.label("profile_name"),
                    ScanProfile.settings.label("profile_settings"),
                    func.count(Subdomain.id).label("total_subs"),
                    func.sum(
                        sa_case((Subdomain.status == "alive", 1), else_=0)
                    ).label("live_subs"),
                )
                .outerjoin(Subdomain, Domain.id == Subdomain.domain_id)
                .outerjoin(ScanProfile, Domain.profile_id == ScanProfile.id)
                .group_by(Domain.id)
                .order_by(Domain.domain)
            ).all()

        result = []
        for r in rows:
            settings = r.profile_settings
            if isinstance(settings, str):
                import json as _json
                try:
                    settings = _json.loads(settings)
                except Exception:
                    settings = {}
            profile_mode = (settings or {}).get("scan_mode") if settings else None
            result.append({
                "id": r.id,
                "domain": r.domain,
                "added_at": r.added_at.isoformat() if r.added_at else None,
                "last_scan": r.last_scan.isoformat() if r.last_scan else None,
                "profile_id": r.profile_id,
                "profile_name": r.profile_name,
                "profile_mode": profile_mode,
                "scope_type": r.scope_type,
                "total_subs": r.total_subs or 0,
                "live_subs": int(r.live_subs or 0),
            })
        return result

    # ------------------------------------------------------------------
    # AppSetting operations
    # ------------------------------------------------------------------

    def get_setting(self, key: str, default: Optional[str] = None) -> Optional[str]:
        with self.get_session() as session:
            row = session.get(AppSetting, key)
            return row.value if row is not None else default

    def set_setting(self, key: str, value: Optional[str]) -> None:
        with self.get_session() as session:
            row = session.get(AppSetting, key)
            if row is None:
                session.add(AppSetting(key=key, value=value, updated_at=_utcnow()))
            else:
                row.value = value
                row.updated_at = _utcnow()

    def get_all_settings(self) -> Dict[str, Optional[str]]:
        with self.get_session() as session:
            rows = list(session.scalars(select(AppSetting)).all())
            return {r.key: r.value for r in rows}

    # ------------------------------------------------------------------
    # Config override operations (config.* keys in AppSetting)
    # ------------------------------------------------------------------

    def get_config_overrides(self) -> Dict[str, Any]:
        """Return stored config overrides as a nested dict."""
        all_settings = self.get_all_settings()
        result: Dict[str, Any] = {}
        for key, value in all_settings.items():
            if not key.startswith("config."):
                continue
            dotted = key[len("config."):]
            try:
                parsed: Any = json.loads(value) if value is not None else None
            except (json.JSONDecodeError, TypeError):
                parsed = value
            parts = dotted.split(".")
            target: Dict[str, Any] = result
            for part in parts[:-1]:
                target = target.setdefault(part, {})
            target[parts[-1]] = parsed
        return result

    def set_config_overrides(self, overrides: Dict[str, Any]) -> None:
        """Store a nested config override dict as flat config.* rows."""
        from sqlalchemy import delete as _delete

        def _flatten(d: Dict[str, Any], prefix: str = ""):
            for k, v in d.items():
                full = f"{prefix}{k}"
                if isinstance(v, dict):
                    yield from _flatten(v, f"{full}.")
                else:
                    yield full, v

        with self.get_session() as session:
            session.execute(_delete(AppSetting).where(AppSetting.key.like("config.%")))
            for dotted_key, value in _flatten(overrides):
                serialized = json.dumps(value) if not isinstance(value, str) else value
                session.add(AppSetting(
                    key=f"config.{dotted_key}",
                    value=serialized,
                    updated_at=_utcnow(),
                ))

    def apply_settings_to_config(self, config: Any) -> None:
        """Apply stored config.* overrides on top of an AppConfig object."""
        overrides = self.get_config_overrides()
        _apply_config_overrides(config, overrides)

    # ------------------------------------------------------------------
    # User management (user:<username> keys in AppSetting)
    # ------------------------------------------------------------------

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        value = self.get_setting(f"user:{username}")
        if value is None:
            return None
        try:
            return json.loads(value)
        except Exception:
            return None

    def set_user(self, username: str, password_hash: str, role: str = "admin") -> None:
        self.set_setting(f"user:{username}", json.dumps({
            "password_hash": password_hash,
            "role": role,
        }))

    def list_users(self) -> List[Dict[str, Any]]:
        all_settings = self.get_all_settings()
        users = []
        for key, value in all_settings.items():
            if not key.startswith("user:"):
                continue
            username = key[5:]
            try:
                data: Dict[str, Any] = json.loads(value) if value else {}
            except Exception:
                data = {}
            users.append({"username": username, "role": data.get("role", "viewer")})
        return sorted(users, key=lambda u: u["username"])

    def delete_user(self, username: str) -> bool:
        with self.get_session() as session:
            row = session.get(AppSetting, f"user:{username}")
            if row is None:
                return False
            session.delete(row)
            return True

    def verify_password(self, username: str, password: str) -> Optional[str]:
        """Return the user's role if credentials are valid, else None.

        Supports bcrypt hashes (``bcrypt:<hash>``) and legacy unsalted SHA-256
        (``sha256:<hex>``). On a successful SHA-256 login the hash is silently
        upgraded to bcrypt in-place.
        """
        import hashlib
        import bcrypt as _bcrypt

        user = self.get_user(username)
        if user is None:
            return None
        stored_hash = user.get("password_hash", "")
        role = user.get("role", "viewer")

        if stored_hash.startswith("bcrypt:"):
            hash_bytes = stored_hash[7:].encode()
            if _bcrypt.checkpw(password.encode(), hash_bytes):
                return role
            return None

        if stored_hash.startswith("sha256:"):
            expected = "sha256:" + hashlib.sha256(password.encode()).hexdigest()
            if stored_hash == expected:
                # Upgrade to bcrypt on first successful login
                new_hash = "bcrypt:" + _bcrypt.hashpw(
                    password.encode(), _bcrypt.gensalt()
                ).decode()
                self.set_user(username, new_hash, role)
                return role
        return None

    # ------------------------------------------------------------------
    # Company (Project) operations
    # ------------------------------------------------------------------

    def create_company(
        self,
        name: str,
        description: Optional[str] = None,
        program_type: Optional[str] = None,
        program_url: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> Company:
        """Create a new company/project.

        Args:
            name: Company/project name (must be unique).
            description: Optional description.
            program_type: Optional program type (HackerOne, Bugcrowd, private, etc.).
            program_url: Optional program URL.
            notes: Optional freeform notes.

        Returns:
            The newly created :class:`Company` object.
        """
        with self.get_session() as session:
            obj = Company(
                name=name,
                description=description,
                program_type=program_type,
                program_url=program_url,
                notes=notes,
            )
            session.add(obj)
            session.flush()
            session.refresh(obj)
            return obj

    def get_company(self, company_id: int) -> Optional[Company]:
        """Retrieve a company by ID.

        Args:
            company_id: The primary key of the company.

        Returns:
            The :class:`Company` object or ``None`` if not found.
        """
        with self.get_session() as session:
            return session.get(Company, company_id)

    def get_company_by_name(self, name: str) -> Optional[Company]:
        """Retrieve a company by name.

        Args:
            name: The company name.

        Returns:
            The :class:`Company` object or ``None`` if not found.
        """
        with self.get_session() as session:
            return session.scalar(select(Company).where(Company.name == name))

    def get_all_companies(self) -> List[Company]:
        """Return all companies/projects.

        Returns:
            A list of :class:`Company` objects with eager-loaded relationships.
        """
        with self.get_session() as session:
            stmt = select(Company).options(
                selectinload(Company.domains),
                selectinload(Company.mobile_apps),
                selectinload(Company.api_assets),
            ).order_by(Company.name)
            return list(session.scalars(stmt).all())

    def update_company(self, company_id: int, **kwargs: Any) -> Optional[Company]:
        """Update a company's attributes.

        Args:
            company_id: The primary key of the company.
            **kwargs: Field values to update (name, description, notes, etc.).

        Returns:
            The updated :class:`Company` object or ``None`` if not found.
        """
        with self.get_session() as session:
            obj = session.get(Company, company_id)
            if obj is None:
                return None
            for key, value in kwargs.items():
                if hasattr(obj, key):
                    setattr(obj, key, value)
            session.flush()
            session.refresh(obj)
            return obj

    def delete_company(self, company_id: int) -> bool:
        """Delete a company and all its assets (cascade).

        Args:
            company_id: The primary key of the company.

        Returns:
            ``True`` if the company was found and deleted, ``False`` otherwise.
        """
        with self.get_session() as session:
            obj = session.get(Company, company_id)
            if obj is None:
                return False
            session.delete(obj)
            return True

    def get_company_details(self, company_id: int) -> Optional[Dict[str, Any]]:
        """Return full details for a company including all asset types.

        Args:
            company_id: The primary key of the company.

        Returns:
            A dict with company info, domains, mobile apps, and API assets, or ``None``.
        """
        with self.get_session() as session:
            company = session.get(Company, company_id)
            if company is None:
                return None

            # Get domains
            domains = list(
                session.scalars(
                    select(Domain).where(Domain.company_id == company_id)
                    .order_by(Domain.domain)
                ).all()
            )

            # Get mobile apps
            mobile_apps = list(
                session.scalars(
                    select(MobileApp).where(MobileApp.company_id == company_id)
                    .order_by(MobileApp.name)
                ).all()
            )

            # Get API assets
            api_assets = list(
                session.scalars(
                    select(APIAsset).where(APIAsset.company_id == company_id)
                    .order_by(APIAsset.name)
                ).all()
            )

            return {
                "company": {
                    "id": company.id,
                    "name": company.name,
                    "description": company.description,
                    "is_active": company.is_active,
                    "program_type": company.program_type,
                    "program_url": company.program_url,
                    "notes": company.notes,
                    "created_at": company.created_at.isoformat() if company.created_at else None,
                },
                "domains": [
                    {
                        "id": d.id,
                        "domain": d.domain,
                        "scope_type": d.scope_type,
                        "added_at": d.added_at.isoformat() if d.added_at else None,
                        "last_scan": d.last_scan.isoformat() if d.last_scan else None,
                    }
                    for d in domains
                ],
                "mobile_apps": [
                    {
                        "id": app.id,
                        "name": app.name,
                        "platform": app.platform,
                        "package_name": app.package_name,
                        "app_store_url": app.app_store_url,
                        "store_id": app.store_id,
                        "is_active": app.is_active,
                        "notes": app.notes,
                        "last_scan": app.last_scan.isoformat() if app.last_scan else None,
                        "created_at": app.created_at.isoformat() if app.created_at else None,
                    }
                    for app in mobile_apps
                ],
                "api_assets": [
                    {
                        "id": api.id,
                        "name": api.name,
                        "base_url": api.base_url,
                        "api_type": api.api_type,
                        "specification_url": api.specification_url,
                        "authentication": api.authentication,
                        "is_public": api.is_public,
                        "is_active": api.is_active,
                        "notes": api.notes,
                        "last_scan": api.last_scan.isoformat() if api.last_scan else None,
                        "created_at": api.created_at.isoformat() if api.created_at else None,
                    }
                    for api in api_assets
                ],
            }

    # ------------------------------------------------------------------
    # Mobile App operations
    # ------------------------------------------------------------------

    def create_mobile_app(
        self,
        company_id: int,
        name: str,
        platform: str,
        package_name: Optional[str] = None,
        app_store_url: Optional[str] = None,
        store_id: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> MobileApp:
        """Create a new mobile app asset.

        Args:
            company_id: FK to the owning company.
            name: App name.
            platform: Platform (android or ios).
            package_name: Optional package name (e.g., com.example.app).
            app_store_url: Optional store URL.
            store_id: Optional store ID.
            notes: Optional notes.

        Returns:
            The newly created :class:`MobileApp` object.
        """
        with self.get_session() as session:
            obj = MobileApp(
                company_id=company_id,
                name=name,
                platform=platform,
                package_name=package_name,
                app_store_url=app_store_url,
                store_id=store_id,
                notes=notes,
            )
            session.add(obj)
            session.flush()
            session.refresh(obj)
            return obj

    def get_mobile_app(self, app_id: int) -> Optional[MobileApp]:
        """Retrieve a mobile app by ID."""
        with self.get_session() as session:
            return session.get(MobileApp, app_id)

    def update_mobile_app(self, app_id: int, **kwargs: Any) -> Optional[MobileApp]:
        """Update a mobile app's attributes."""
        with self.get_session() as session:
            obj = session.get(MobileApp, app_id)
            if obj is None:
                return None
            for key, value in kwargs.items():
                if hasattr(obj, key):
                    setattr(obj, key, value)
            session.flush()
            session.refresh(obj)
            return obj

    def delete_mobile_app(self, app_id: int) -> bool:
        """Delete a mobile app."""
        with self.get_session() as session:
            obj = session.get(MobileApp, app_id)
            if obj is None:
                return False
            session.delete(obj)
            return True

    def get_all_mobile_apps(self, company_id: Optional[int] = None) -> List[MobileApp]:
        """Return all mobile apps, optionally filtered by company."""
        with self.get_session() as session:
            if company_id is not None:
                return list(
                    session.scalars(
                        select(MobileApp).where(MobileApp.company_id == company_id)
                        .order_by(MobileApp.name)
                    ).all()
                )
            return list(session.scalars(select(MobileApp).order_by(MobileApp.name)).all())

    # ------------------------------------------------------------------
    # API Asset operations
    # ------------------------------------------------------------------

    def create_api_asset(
        self,
        company_id: int,
        name: str,
        base_url: str,
        api_type: str,
        specification_url: Optional[str] = None,
        authentication: Optional[str] = None,
        is_public: bool = False,
        notes: Optional[str] = None,
    ) -> APIAsset:
        """Create a new API asset.

        Args:
            company_id: FK to the owning company.
            name: API name.
            base_url: Base URL of the API.
            api_type: API type (rest, graphql, grpc, soap).
            specification_url: Optional spec URL (swagger.json, etc.).
            authentication: Optional auth type (bearer, api_key, oauth, none).
            is_public: Whether the API is publicly accessible.
            notes: Optional notes.

        Returns:
            The newly created :class:`APIAsset` object.
        """
        with self.get_session() as session:
            obj = APIAsset(
                company_id=company_id,
                name=name,
                base_url=base_url,
                api_type=api_type,
                specification_url=specification_url,
                authentication=authentication,
                is_public=is_public,
                notes=notes,
            )
            session.add(obj)
            session.flush()
            session.refresh(obj)
            return obj

    def get_api_asset(self, asset_id: int) -> Optional[APIAsset]:
        """Retrieve an API asset by ID."""
        with self.get_session() as session:
            return session.get(APIAsset, asset_id)

    def update_api_asset(self, asset_id: int, **kwargs: Any) -> Optional[APIAsset]:
        """Update an API asset's attributes."""
        with self.get_session() as session:
            obj = session.get(APIAsset, asset_id)
            if obj is None:
                return None
            for key, value in kwargs.items():
                if hasattr(obj, key):
                    setattr(obj, key, value)
            session.flush()
            session.refresh(obj)
            return obj

    def delete_api_asset(self, asset_id: int) -> bool:
        """Delete an API asset."""
        with self.get_session() as session:
            obj = session.get(APIAsset, asset_id)
            if obj is None:
                return False
            session.delete(obj)
            return True

    def get_all_api_assets(self, company_id: Optional[int] = None) -> List[APIAsset]:
        """Return all API assets, optionally filtered by company."""
        with self.get_session() as session:
            if company_id is not None:
                return list(
                    session.scalars(
                        select(APIAsset).where(APIAsset.company_id == company_id)
                        .order_by(APIAsset.name)
                    ).all()
                )
            return list(session.scalars(select(APIAsset).order_by(APIAsset.name)).all())

    def get_or_create_flask_secret(self) -> str:
        """Return a stable Flask secret key, generating one on first call."""
        key = self.get_setting("system:flask_secret")
        if key:
            return key
        import secrets as _secrets
        new_key = _secrets.token_hex(32)
        self.set_setting("system:flask_secret", new_key)
        return new_key

    def ensure_default_admin(self) -> Optional[str]:
        """Ensure at least one admin user exists.

        If DASHBOARD_SECRET env var is set, it is always synced as the admin
        password (so rotating the env var changes the password).
        Otherwise, if no users exist, a random password is generated and returned
        so the caller can log it.
        """
        import os
        import secrets as _secrets
        import bcrypt as _bcrypt

        def _hash(pwd: str) -> str:
            return "bcrypt:" + _bcrypt.hashpw(pwd.encode(), _bcrypt.gensalt()).decode()

        env_secret = os.environ.get("DASHBOARD_SECRET", "").strip()
        if env_secret:
            self.set_user("admin", _hash(env_secret), "admin")
            return None  # operator knows the password

        if self.list_users():
            return None  # users already exist

        temp_password = _secrets.token_urlsafe(12)
        self.set_user("admin", _hash(temp_password), "admin")
        return temp_password

    # ------------------------------------------------------------------
    # GitHub monitoring operations
    # ------------------------------------------------------------------

    def add_github_repo(self, organization: str, repository: str, **kwargs: Any) -> int:
        """Add a GitHub repository to monitoring. Returns repo ID."""
        full_name = f"{organization}/{repository}"
        with self.get_session() as session:
            # Check if already exists
            existing = session.scalar(
                select(GitHubMonitoredRepo).where(
                    GitHubMonitoredRepo.organization == organization,
                    GitHubMonitoredRepo.repository == repository
                )
            )
            if existing:
                return existing.id

            repo = GitHubMonitoredRepo(
                organization=organization,
                repository=repository,
                full_name=full_name,
                **kwargs
            )
            session.add(repo)
            session.flush()
            session.refresh(repo)
            return repo.id

    def get_github_repo(self, repo_id: int) -> Optional[GitHubMonitoredRepo]:
        """Get a GitHub repo by ID."""
        with self.get_session() as session:
            return session.scalar(
                select(GitHubMonitoredRepo).where(GitHubMonitoredRepo.id == repo_id)
            )

    def list_github_repos(self, organization: Optional[str] = None) -> List[GitHubMonitoredRepo]:
        """List all monitored GitHub repos, optionally filtered by organization."""
        with self.get_session() as session:
            query = select(GitHubMonitoredRepo)
            if organization:
                query = query.where(GitHubMonitoredRepo.organization == organization)
            return list(
                session.scalars(
                    query.order_by(GitHubMonitoredRepo.created_at.desc())
                ).all()
            )

    def update_github_repo_last_scan(
        self, repo_id: int, commit_hash: Optional[str] = None
    ) -> None:
        """Update last scan timestamp and commit hash."""
        with self.get_session() as session:
            repo = session.get(GitHubMonitoredRepo, repo_id)
            if repo:
                repo.last_scan_timestamp = _utcnow()
                if commit_hash:
                    repo.last_commit_hash = commit_hash

    def add_github_finding(self, repo_id: int, finding: Dict[str, Any]) -> int:
        """Add a GitHub finding. Returns finding ID."""
        with self.get_session() as session:
            github_finding = GitHubFinding(
                repo_id=repo_id,
                finding_type=finding.get('finding_type', 'secret'),
                severity=finding.get('severity', 'MEDIUM'),
                file_path=finding.get('file_path', ''),
                line_number=finding.get('line_number'),
                commit_hash=finding.get('commit_hash'),
                commit_url=finding.get('commit_url'),
                author=finding.get('author'),
                pattern_name=finding.get('pattern_name', ''),
                matched_text=finding.get('matched_text'),
                context_before=finding.get('context_before'),
                context_after=finding.get('context_after'),
            )
            session.add(github_finding)
            session.flush()
            session.refresh(github_finding)
            return github_finding.id

    def get_github_findings(
        self,
        repo_id: Optional[int] = None,
        finding_type: Optional[str] = None,
        severity: Optional[str] = None,
        unreviewed_only: bool = False,
        limit: int = 100,
    ) -> List[GitHubFinding]:
        """Get GitHub findings with optional filters."""
        with self.get_session() as session:
            query = select(GitHubFinding).join(GitHubMonitoredRepo)

            if repo_id:
                query = query.where(GitHubFinding.repo_id == repo_id)
            if finding_type:
                query = query.where(GitHubFinding.finding_type == finding_type)
            if severity:
                query = query.where(GitHubFinding.severity == severity)
            if unreviewed_only:
                query = query.where(GitHubFinding.reviewed == False)  # noqa: E712

            return list(
                session.scalars(
                    query.order_by(GitHubFinding.timestamp.desc()).limit(limit)
                ).all()
            )

    def mark_finding_false_positive(self, finding_id: int, is_fp: bool = True) -> None:
        """Mark a finding as false positive (or not)."""
        with self.get_session() as session:
            finding = session.get(GitHubFinding, finding_id)
            if finding:
                finding.false_positive = is_fp
                finding.reviewed = True

    def mark_finding_reviewed(self, finding_id: int) -> None:
        """Mark a finding as reviewed."""
        with self.get_session() as session:
            finding = session.get(GitHubFinding, finding_id)
            if finding:
                finding.reviewed = True

    def delete_github_repo(self, repo_id: int) -> bool:
        """Delete a GitHub repo and all its findings (cascade)."""
        with self.get_session() as session:
            repo = session.get(GitHubMonitoredRepo, repo_id)
            if repo:
                session.delete(repo)
                return True
            return False
