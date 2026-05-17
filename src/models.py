"""
Core data models for the Cloud Asset Security Review system.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class AssetType(str, Enum):
    EC2_INSTANCE = "ec2_instance"
    ALB = "alb"
    API_GATEWAY = "api_gateway"
    ROUTE53_RECORD = "route53_record"
    S3_BUCKET = "s3_bucket"
    ECS_SERVICE = "ecs_service"
    CLOUDFRONT = "cloudfront"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ScanStatus(str, Enum):
    PENDING = "pending"
    ENRICHING = "enriching"
    SCANNING = "scanning"
    REVIEWING = "reviewing"
    COMPLETE = "complete"
    FAILED = "failed"


@dataclass
class Asset:
    """Represents a discovered cloud asset."""
    asset_id: str
    asset_type: AssetType
    hostname: str
    ip_addresses: list[str] = field(default_factory=list)
    region: str = "us-east-1"
    account_id: str = ""
    resource_arn: str = ""
    tags: dict[str, str] = field(default_factory=dict)
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    discovered_via: str = "cloudtrail"
    raw_event: dict[str, Any] = field(default_factory=dict)

    @property
    def owner(self) -> str:
        return self.tags.get("Owner", self.tags.get("owner", "unknown"))

    @property
    def team(self) -> str:
        return self.tags.get("Team", self.tags.get("team", "unknown"))

    @property
    def environment(self) -> str:
        return self.tags.get("Environment", self.tags.get("env", "unknown"))


@dataclass
class TLSInfo:
    """TLS certificate and configuration details."""
    issuer: str = ""
    subject: str = ""
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None
    days_to_expiry: int = -1
    san_domains: list[str] = field(default_factory=list)
    protocol_versions: list[str] = field(default_factory=list)
    cipher_suites: list[str] = field(default_factory=list)
    is_self_signed: bool = False
    is_expired: bool = False
    is_wildcard: bool = False
    certificate_transparency: bool = False


@dataclass
class HTTPInfo:
    """HTTP response metadata."""
    status_code: int = 0
    server: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    redirect_chain: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    response_time_ms: float = 0
    content_type: str = ""
    waf_detected: bool = False
    cdn_detected: bool = False
    cdn_provider: str = ""


@dataclass
class PortScanResult:
    """Open port scan results."""
    open_ports: list[int] = field(default_factory=list)
    port_services: dict[int, str] = field(default_factory=dict)
    scan_time_s: float = 0


@dataclass
class AssetMetadata:
    """Enriched metadata for an asset."""
    asset_id: str
    dns_records: dict[str, list[str]] = field(default_factory=dict)
    ip_info: dict[str, Any] = field(default_factory=dict)
    http_info: Optional[HTTPInfo] = None
    https_info: Optional[HTTPInfo] = None
    tls_info: Optional[TLSInfo] = None
    port_scan: Optional[PortScanResult] = None
    enriched_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class SecurityFinding:
    """A single security finding from automated checks."""
    check_id: str
    title: str
    description: str
    risk_level: RiskLevel
    category: str
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    cwe_id: str = ""
    cvss_score: float = 0.0


@dataclass
class LLMReview:
    """LLM-generated security review."""
    overall_risk: RiskLevel
    executive_summary: str
    key_findings: list[str]
    attack_surface_analysis: str
    prioritized_actions: list[dict[str, str]]
    threat_scenarios: list[str]
    compliance_notes: str
    raw_response: str = ""
    model: str = ""
    tokens_used: int = 0


@dataclass
class SecurityReport:
    """Complete security review report for an asset."""
    report_id: str
    asset: Asset
    metadata: Optional[AssetMetadata]
    findings: list[SecurityFinding]
    llm_review: Optional[LLMReview]
    scan_status: ScanStatus
    created_at: datetime = field(default_factory=datetime.utcnow)
    scan_duration_s: float = 0

    @property
    def finding_counts(self) -> dict[str, int]:
        counts = {level.value: 0 for level in RiskLevel}
        for f in self.findings:
            counts[f.risk_level.value] += 1
        return counts

    @property
    def highest_risk(self) -> RiskLevel:
        priority = [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM,
                    RiskLevel.LOW, RiskLevel.INFO]
        for level in priority:
            if any(f.risk_level == level for f in self.findings):
                return level
        return RiskLevel.INFO
