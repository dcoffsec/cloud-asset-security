"""
Unit tests for the Cloud Asset Security Review system.

Run with: pytest tests/ -v
"""
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.models import (
    Asset, AssetType, AssetMetadata, HTTPInfo, TLSInfo,
    PortScanResult, RiskLevel, SecurityFinding
)
from src.security_checks.header_checks import run_header_checks
from src.security_checks.tls_checks import run_tls_checks
from src.security_checks.port_checks import run_port_checks


# ─────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────

def make_asset(hostname="test.example.com", env="production", owner="team-a"):
    return Asset(
        asset_id="test-001",
        asset_type=AssetType.ALB,
        hostname=hostname,
        tags={"Owner": owner, "Environment": env, "Team": "backend"},
    )


def make_metadata(asset_id="test-001") -> AssetMetadata:
    return AssetMetadata(asset_id=asset_id)


def make_http_info(**kwargs) -> HTTPInfo:
    defaults = {
        "status_code": 200,
        "server": "nginx",
        "headers": {
            "Content-Type": "text/html",
        },
        "waf_detected": False,
        "cdn_detected": False,
    }
    defaults.update(kwargs)
    return HTTPInfo(**defaults)


# ─────────────────────────────────────────────
# Header checks
# ─────────────────────────────────────────────

class TestHeaderChecks:

    def test_missing_hsts_flagged_as_high(self):
        metadata = make_metadata()
        metadata.https_info = make_http_info()  # No HSTS header

        findings = run_header_checks(metadata)
        hsts_findings = [f for f in findings if "HSTS" in f.title or "Strict-Transport" in f.title]
        assert hsts_findings, "Expected HSTS finding"
        assert hsts_findings[0].risk_level == RiskLevel.HIGH

    def test_hsts_present_no_missing_finding(self):
        metadata = make_metadata()
        metadata.https_info = make_http_info(headers={
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Type": "text/html",
        })

        findings = run_header_checks(metadata)
        hsts_missing = [f for f in findings
                        if f.check_id == "HDR-STRICT_TRANSPORT_SECURITY_MISSING"]
        assert not hsts_missing, "Should not flag HSTS when present"

    def test_hsts_short_max_age_flagged(self):
        metadata = make_metadata()
        metadata.https_info = make_http_info(headers={
            "Strict-Transport-Security": "max-age=3600",
        })

        findings = run_header_checks(metadata)
        short_age = [f for f in findings if f.check_id == "HDR-HSTS_SHORT_MAX_AGE"]
        assert short_age, "Should flag short max-age"

    def test_missing_csp_flagged_as_medium(self):
        metadata = make_metadata()
        metadata.https_info = make_http_info()

        findings = run_header_checks(metadata)
        csp_findings = [f for f in findings if "Content-Security-Policy" in f.title]
        assert csp_findings
        assert csp_findings[0].risk_level == RiskLevel.MEDIUM

    def test_weak_csp_unsafe_inline_flagged(self):
        metadata = make_metadata()
        metadata.https_info = make_http_info(headers={
            "Content-Security-Policy": "default-src 'self' 'unsafe-inline'",
        })

        findings = run_header_checks(metadata)
        weak_csp = [f for f in findings if "unsafe-inline" in f.title.lower()
                    or "unsafe" in f.check_id.lower()]
        assert weak_csp, "Should flag unsafe-inline in CSP"

    def test_verbose_server_header_flagged(self):
        metadata = make_metadata()
        metadata.https_info = make_http_info(
            server="nginx/1.18.0",
            headers={"Server": "nginx/1.18.0"},
        )

        findings = run_header_checks(metadata)
        server_findings = [f for f in findings if "Server" in f.title]
        assert server_findings, "Should flag verbose server header with version"

    def test_cors_wildcard_with_credentials_critical(self):
        metadata = make_metadata()
        metadata.https_info = make_http_info(headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        })

        findings = run_header_checks(metadata)
        cors = [f for f in findings if "CORS" in f.title and "Credentials" in f.title]
        assert cors
        assert cors[0].risk_level == RiskLevel.HIGH

    def test_no_waf_flagged(self):
        metadata = make_metadata()
        metadata.https_info = make_http_info(waf_detected=False)

        findings = run_header_checks(metadata)
        waf_findings = [f for f in findings if f.check_id == "HDR-NO_WAF_DETECTED"]
        assert waf_findings

    def test_no_findings_on_good_headers(self):
        """A well-configured asset should produce minimal header findings."""
        metadata = make_metadata()
        metadata.https_info = make_http_info(
            waf_detected=True,
            headers={
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Content-Security-Policy": "default-src 'self'",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "camera=(), microphone=()",
            }
        )

        findings = run_header_checks(metadata)
        critical_or_high = [f for f in findings
                            if f.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)]
        assert not critical_or_high, f"Unexpected high/critical findings: {critical_or_high}"


# ─────────────────────────────────────────────
# TLS checks
# ─────────────────────────────────────────────

class TestTLSChecks:

    def test_no_https_critical(self):
        metadata = make_metadata()
        metadata.http_info = make_http_info()
        # No https_info, no tls_info → no HTTPS

        findings = run_tls_checks(metadata)
        no_https = [f for f in findings if f.check_id == "TLS-NO_HTTPS"]
        assert no_https
        assert no_https[0].risk_level == RiskLevel.CRITICAL

    def test_expired_cert_critical(self):
        metadata = make_metadata()
        metadata.https_info = make_http_info()
        metadata.tls_info = TLSInfo(
            is_expired=True,
            valid_to=datetime.now(timezone.utc) - timedelta(days=5),
            days_to_expiry=0,
        )

        findings = run_tls_checks(metadata)
        expired = [f for f in findings if f.check_id == "TLS-CERT_EXPIRED"]
        assert expired
        assert expired[0].risk_level == RiskLevel.CRITICAL

    def test_expiring_soon_14_days_high(self):
        metadata = make_metadata()
        metadata.https_info = make_http_info()
        metadata.tls_info = TLSInfo(
            days_to_expiry=10,
            valid_to=datetime.now(timezone.utc) + timedelta(days=10),
        )

        findings = run_tls_checks(metadata)
        expiring = [f for f in findings if f.check_id == "TLS-CERT_EXPIRING_SOON"]
        assert expiring
        assert expiring[0].risk_level == RiskLevel.HIGH

    def test_expiring_soon_25_days_medium(self):
        metadata = make_metadata()
        metadata.https_info = make_http_info()
        metadata.tls_info = TLSInfo(
            days_to_expiry=25,
            valid_to=datetime.now(timezone.utc) + timedelta(days=25),
        )

        findings = run_tls_checks(metadata)
        expiring = [f for f in findings if f.check_id == "TLS-CERT_EXPIRING_SOON"]
        assert expiring
        assert expiring[0].risk_level == RiskLevel.MEDIUM

    def test_self_signed_cert_high(self):
        metadata = make_metadata()
        metadata.https_info = make_http_info()
        metadata.tls_info = TLSInfo(
            is_self_signed=True,
            issuer="CN=localhost",
            subject="CN=localhost",
            days_to_expiry=365,
        )

        findings = run_tls_checks(metadata)
        self_signed = [f for f in findings if f.check_id == "TLS-SELF_SIGNED_CERT"]
        assert self_signed
        assert self_signed[0].risk_level == RiskLevel.HIGH

    def test_http_not_redirected_to_https(self):
        metadata = make_metadata()
        metadata.http_info = make_http_info(
            status_code=200,
            redirect_chain=["http://example.com"],
        )
        metadata.https_info = make_http_info()
        metadata.tls_info = TLSInfo(days_to_expiry=365)

        findings = run_tls_checks(metadata)
        redir = [f for f in findings if f.check_id == "TLS-HTTP_NOT_REDIRECTED"]
        assert redir
        assert redir[0].risk_level == RiskLevel.HIGH


# ─────────────────────────────────────────────
# Port checks
# ─────────────────────────────────────────────

class TestPortChecks:

    def test_redis_port_critical(self):
        metadata = make_metadata()
        metadata.port_scan = PortScanResult(
            open_ports=[80, 443, 6379],
            port_services={80: "HTTP", 443: "HTTPS", 6379: "Redis"},
        )

        findings = run_port_checks(metadata)
        redis = [f for f in findings if f.check_id == "PORT-6379_OPEN"]
        assert redis
        assert redis[0].risk_level == RiskLevel.CRITICAL

    def test_ssh_port_medium(self):
        metadata = make_metadata()
        metadata.port_scan = PortScanResult(
            open_ports=[22, 443],
            port_services={22: "SSH", 443: "HTTPS"},
        )

        findings = run_port_checks(metadata)
        ssh = [f for f in findings if f.check_id == "PORT-22_OPEN"]
        assert ssh
        assert ssh[0].risk_level == RiskLevel.MEDIUM

    def test_mysql_port_critical(self):
        metadata = make_metadata()
        metadata.port_scan = PortScanResult(
            open_ports=[3306],
            port_services={3306: "MySQL"},
        )

        findings = run_port_checks(metadata)
        mysql = [f for f in findings if f.check_id == "PORT-3306_OPEN"]
        assert mysql
        assert mysql[0].risk_level == RiskLevel.CRITICAL

    def test_excessive_ports_flagged(self):
        metadata = make_metadata()
        metadata.port_scan = PortScanResult(
            open_ports=[22, 80, 443, 3000, 4200, 8080, 9090],
            port_services={},
        )

        findings = run_port_checks(metadata)
        excessive = [f for f in findings if f.check_id == "PORT-EXCESSIVE_EXPOSURE"]
        assert excessive

    def test_standard_ports_no_excess_flag(self):
        metadata = make_metadata()
        metadata.port_scan = PortScanResult(
            open_ports=[80, 443],
            port_services={80: "HTTP", 443: "HTTPS"},
        )

        findings = run_port_checks(metadata)
        excessive = [f for f in findings if f.check_id == "PORT-EXCESSIVE_EXPOSURE"]
        assert not excessive

    def test_elasticsearch_port_critical(self):
        metadata = make_metadata()
        metadata.port_scan = PortScanResult(
            open_ports=[9200],
            port_services={9200: "Elasticsearch HTTP"},
        )

        findings = run_port_checks(metadata)
        es = [f for f in findings if f.check_id == "PORT-9200_OPEN"]
        assert es
        assert es[0].risk_level == RiskLevel.CRITICAL

    def test_no_scan_results_no_findings(self):
        metadata = make_metadata()
        # No port_scan set

        findings = run_port_checks(metadata)
        assert findings == []


# ─────────────────────────────────────────────
# Asset model tests
# ─────────────────────────────────────────────

class TestAssetModel:

    def test_owner_from_tags(self):
        asset = make_asset(owner="platform-team")
        assert asset.owner == "platform-team"

    def test_environment_from_tags(self):
        asset = make_asset(env="staging")
        assert asset.environment == "staging"

    def test_unknown_owner_default(self):
        asset = Asset(
            asset_id="x",
            asset_type=AssetType.ALB,
            hostname="test.com",
        )
        assert asset.owner == "unknown"

    def test_finding_counts(self):
        from src.models import SecurityReport, ScanStatus
        asset = make_asset()
        findings = [
            SecurityFinding("C1", "Critical", "", RiskLevel.CRITICAL, "cat"),
            SecurityFinding("H1", "High",     "", RiskLevel.HIGH,     "cat"),
            SecurityFinding("H2", "High2",    "", RiskLevel.HIGH,     "cat"),
            SecurityFinding("M1", "Medium",   "", RiskLevel.MEDIUM,   "cat"),
        ]
        report = SecurityReport(
            report_id="r1", asset=asset, metadata=None,
            findings=findings, llm_review=None, scan_status=ScanStatus.COMPLETE
        )
        counts = report.finding_counts
        assert counts["CRITICAL"] == 1
        assert counts["HIGH"] == 2
        assert counts["MEDIUM"] == 1
        assert report.highest_risk == RiskLevel.CRITICAL


# ─────────────────────────────────────────────
# Registry tests
# ─────────────────────────────────────────────

class TestAssetRegistry:

    def test_register_and_retrieve(self, tmp_path):
        from src.discovery.asset_registry import AssetRegistry
        registry = AssetRegistry(db_path=str(tmp_path / "test.db"))
        asset = make_asset()

        inserted = registry.register(asset)
        assert inserted

        retrieved = registry.get_by_id(asset.asset_id)
        assert retrieved is not None
        assert retrieved.hostname == asset.hostname

    def test_duplicate_hostname_not_reinserted(self, tmp_path):
        from src.discovery.asset_registry import AssetRegistry
        registry = AssetRegistry(db_path=str(tmp_path / "test.db"))
        asset = make_asset()

        first = registry.register(asset)
        second = registry.register(asset)

        assert first is True
        assert second is False  # Duplicate

    def test_pending_assets_returned(self, tmp_path):
        from src.discovery.asset_registry import AssetRegistry
        registry = AssetRegistry(db_path=str(tmp_path / "test.db"))

        assets = [
            Asset(asset_id=f"id-{i}", asset_type=AssetType.ALB,
                  hostname=f"host{i}.example.com")
            for i in range(3)
        ]
        for a in assets:
            registry.register(a)

        pending = registry.get_pending()
        assert len(pending) == 3
