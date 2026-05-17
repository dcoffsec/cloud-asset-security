"""
Configuration management — reads from environment variables with sensible defaults.
"""
import os
from dataclasses import dataclass, field


@dataclass
class Config:
    # AWS
    aws_region: str = field(default_factory=lambda: os.getenv("AWS_REGION", "us-east-1"))
    aws_account_id: str = field(default_factory=lambda: os.getenv("AWS_ACCOUNT_ID", ""))
    cloudtrail_log_group: str = field(default_factory=lambda: os.getenv(
        "CLOUDTRAIL_LOG_GROUP", "CloudTrail/DefaultLogGroup"))
    cloudtrail_s3_bucket: str = field(default_factory=lambda: os.getenv(
        "CLOUDTRAIL_S3_BUCKET", ""))

    # Anthropic
    anthropic_api_key: str = field(default_factory=lambda: os.getenv("ANTHROPIC_API_KEY", ""))
    llm_model: str = field(default_factory=lambda: os.getenv(
        "LLM_MODEL", "claude-opus-4-5"))
    llm_max_tokens: int = field(default_factory=lambda: int(os.getenv("LLM_MAX_TOKENS", "2048")))

    # Scanning
    scan_timeout_s: int = field(default_factory=lambda: int(os.getenv("SCAN_TIMEOUT_S", "30")))
    port_scan_targets: list = field(default_factory=lambda: [
        int(p) for p in os.getenv(
            "PORT_SCAN_TARGETS",
            "22,80,443,3306,5432,6379,8080,8443,8888,9200,27017"
        ).split(",")
    ])
    max_concurrent_scans: int = field(default_factory=lambda: int(
        os.getenv("MAX_CONCURRENT_SCANS", "5")))
    http_user_agent: str = field(default_factory=lambda: os.getenv(
        "HTTP_USER_AGENT",
        "CloudSecurityScanner/1.0 (internal-security-review)"))

    # Storage
    db_path: str = field(default_factory=lambda: os.getenv("DB_PATH", "/tmp/asset_registry.db"))
    reports_output_dir: str = field(default_factory=lambda: os.getenv(
        "REPORTS_OUTPUT_DIR", "/tmp/reports"))

    # Alerting
    slack_webhook_url: str = field(default_factory=lambda: os.getenv("SLACK_WEBHOOK_URL", ""))
    alert_on_risk_levels: list = field(default_factory=lambda:
        os.getenv("ALERT_ON_RISK_LEVELS", "CRITICAL,HIGH").split(","))

    # Poll interval for CloudTrail events (seconds)
    poll_interval_s: int = field(default_factory=lambda: int(
        os.getenv("POLL_INTERVAL_S", "60")))

    # Demo/mock mode
    mock_aws: bool = field(default_factory=lambda: os.getenv("MOCK_AWS", "false").lower() == "true")
    mock_target: str = field(default_factory=lambda: os.getenv("MOCK_TARGET", ""))


# Singleton
_config: Config | None = None


def get_config() -> Config:
    global _config
    if _config is None:
        _config = Config()
    return _config
