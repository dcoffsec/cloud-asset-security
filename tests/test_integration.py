"""
Integration tests — test the full pipeline with mock data.
No real network calls, no AWS credentials required.
"""
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.models import (
    Asset, AssetMetadata, AssetType, HTTPInfo, PortScanResult,
    RiskLevel, ScanStatus, SecurityFinding, TLSInfo
)
from src.security_checks import run_all_checks


def make_fully_enriched_metadata(asset_id: str = "test-001") -> AssetMetadata:
    """Create a metadata object representing a poorly-secured asset."""
    metadata = AssetMetadata(asset_id=asset_id)

    metadata.dns_records = {
        "hostname": "test.example.com",
        "ipv4": ["1.2.3.4"],
        "ipv6": [],
        "cname": None,
        "ptr": "ec2-1-2-3-4.compute-1.amazonaws.com",
    }

    # HTTP — redirects to HTTPS
    metadata.http_info = HTTPInfo(
        status_code=301,
        server="nginx/1.18.0",
        headers={"Location": "https://test.example.com", "Server": "nginx/1.18.0"},
        redirect_chain=["http://test.example.com", "https://test.example.com"],
        technologies=["Nginx"],
        waf_detected=False,
        cdn_detected=False,
    )

    # HTTPS — missing most security headers
    metadata.https_info = HTTPInfo(
        status_code=200,
        server="nginx/1.18.0",
        headers={
            "Content-Type": "application/json",
            "Server": "nginx/1.18.0",
            "X-Powered-By": "Express",
        },
        technologies=["Nginx", "Express.js"],
        waf_detected=False,
        cdn_detected=False,
        response_time_ms=120.0,
    )

    # TLS — valid cert, 45 days until expiry
    metadata.tls_info = TLSInfo(
        issuer="C=US, O=Let's Encrypt, CN=R3",
        subject="CN=test.example.com",
        valid_from=datetime(2024, 11, 1, tzinfo=timezone.utc),
        valid_to=datetime(2025, 3, 1, tzinfo=timezone.utc),
        days_to_expiry=45,
        san_domains=["test.example.com"],
        protocol_versions=["TLSv1.3"],
        cipher_suites=["TLS_AES_256_GCM_SHA384"],
        is_self_signed=False,
        is_expired=False,
        is_wildcard=False,
    )

    # Port scan — SSH and Redis exposed
    metadata.port_scan = PortScanResult(
        open_ports=[22, 80, 443, 6379],
        port_services={22: "SSH", 80: "HTTP", 443: "HTTPS", 6379: "Redis"},
        scan_time_s=2.1,
    )

    return metadata


class TestFullPipeline:

    def test_run_all_checks_returns_sorted_findings(self):
        asset = Asset(
            asset_id="test-001",
            asset_type=AssetType.ALB,
            hostname="test.example.com",
            tags={"Owner": "team-a", "Environment": "production"},
        )
        metadata = make_fully_enriched_metadata()

        findings = run_all_checks(asset, metadata)

        assert len(findings) > 0
        # Verify sorted by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        levels = [severity_order[f.risk_level.value] for f in findings]
        assert levels == sorted(levels), "Findings not sorted by severity"

    def test_redis_port_detected_as_critical(self):
        asset = Asset(
            asset_id="test-001", asset_type=AssetType.ALB,
            hostname="test.example.com",
        )
        metadata = make_fully_enriched_metadata()

        findings = run_all_checks(asset, metadata)
        redis = [f for f in findings if f.check_id == "PORT-6379_OPEN"]
        assert redis, "Expected Redis port finding"
        assert redis[0].risk_level == RiskLevel.CRITICAL

    def test_missing_headers_all_detected(self):
        asset = Asset(
            asset_id="test-001", asset_type=AssetType.ALB,
            hostname="test.example.com",
        )
        metadata = make_fully_enriched_metadata()

        findings = run_all_checks(asset, metadata)
        header_findings = [f for f in findings if f.category == "Security Headers"]
        # Should find at least HSTS, CSP, X-Frame-Options, X-Content-Type-Options
        assert len(header_findings) >= 4

    def test_no_duplicate_check_ids(self):
        asset = Asset(
            asset_id="test-001", asset_type=AssetType.ALB,
            hostname="test.example.com",
        )
        metadata = make_fully_enriched_metadata()

        findings = run_all_checks(asset, metadata)
        check_ids = [f.check_id for f in findings]
        assert len(check_ids) == len(set(check_ids)), "Duplicate check IDs found"

    def test_missing_owner_tag_flagged(self):
        asset = Asset(
            asset_id="test-001", asset_type=AssetType.ALB,
            hostname="test.example.com",
            tags={},  # No owner tag
        )
        metadata = make_fully_enriched_metadata()

        findings = run_all_checks(asset, metadata)
        governance = [f for f in findings if f.check_id == "GOVERNANCE-MISSING_OWNER_TAG"]
        assert governance, "Expected governance finding for missing owner tag"

    def test_well_configured_asset_no_critical_findings(self):
        asset = Asset(
            asset_id="test-001", asset_type=AssetType.ALB,
            hostname="secure.example.com",
            tags={"Owner": "security-team", "Environment": "production", "Team": "platform"},
        )

        metadata = AssetMetadata(asset_id="test-001")
        metadata.dns_records = {"hostname": "secure.example.com", "ipv4": ["1.2.3.4"]}
        metadata.https_info = HTTPInfo(
            status_code=200,
            server="",  # Not disclosed
            headers={
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Content-Security-Policy": "default-src 'self'",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "camera=()",
            },
            technologies=["AWS CloudFront"],
            waf_detected=True,
            cdn_detected=True,
            cdn_provider="AWS CloudFront",
        )
        metadata.http_info = HTTPInfo(
            status_code=301,
            headers={"Location": "https://secure.example.com"},
            redirect_chain=["http://secure.example.com", "https://secure.example.com"],
            waf_detected=True,
            cdn_detected=True,
        )
        metadata.tls_info = TLSInfo(
            issuer="C=US, O=Amazon",
            subject="CN=secure.example.com",
            days_to_expiry=300,
            is_expired=False,
            is_self_signed=False,
            protocol_versions=["TLSv1.3"],
            cipher_suites=["TLS_AES_256_GCM_SHA384"],
        )
        metadata.port_scan = PortScanResult(
            open_ports=[80, 443],
            port_services={80: "HTTP", 443: "HTTPS"},
        )

        findings = run_all_checks(asset, metadata)
        critical = [f for f in findings if f.risk_level == RiskLevel.CRITICAL]
        high = [f for f in findings if f.risk_level == RiskLevel.HIGH]

        assert not critical, f"Unexpected CRITICAL findings on secure asset: {[f.title for f in critical]}"
        assert not high, f"Unexpected HIGH findings on secure asset: {[f.title for f in high]}"


class TestLLMReview:

    def test_deterministic_fallback_no_api_key(self):
        """LLM review should succeed without API key using deterministic fallback."""
        from src.llm_review.reviewer import generate_llm_review

        asset = Asset(
            asset_id="test-001", asset_type=AssetType.ALB,
            hostname="test.example.com",
            tags={"Owner": "test", "Environment": "staging"},
        )
        findings = [
            SecurityFinding("C1", "Critical Finding", "desc", RiskLevel.CRITICAL, "Network"),
            SecurityFinding("H1", "High Finding", "desc", RiskLevel.HIGH, "TLS"),
        ]

        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": ""}):
            review = generate_llm_review(asset, findings)

        assert review is not None
        assert review.overall_risk == RiskLevel.CRITICAL
        assert len(review.key_findings) > 0
        assert review.executive_summary != ""
        assert review.model == "deterministic"

    def test_deterministic_fallback_empty_findings(self):
        from src.llm_review.reviewer import generate_llm_review

        asset = Asset(
            asset_id="test-001", asset_type=AssetType.ALB,
            hostname="clean.example.com",
        )

        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": ""}):
            review = generate_llm_review(asset, [])

        assert review.overall_risk == RiskLevel.INFO


class TestReportGenerator:

    def test_json_report_structure(self, tmp_path):
        from src.reporting.report_generator import ReportGenerator
        from src.models import SecurityReport

        asset = Asset(
            asset_id="test-001", asset_type=AssetType.ALB,
            hostname="test.example.com",
            tags={"Owner": "test-team", "Environment": "production"},
        )
        findings = [
            SecurityFinding(
                "PORT-6379_OPEN", "Redis Exposed", "desc",
                RiskLevel.CRITICAL, "Network", evidence={"port": 6379},
                remediation="Fix it",
            )
        ]

        report = SecurityReport(
            report_id="test-report-001",
            asset=asset,
            metadata=None,
            findings=findings,
            llm_review=None,
            scan_status=ScanStatus.COMPLETE,
            scan_duration_s=5.0,
        )

        generator = ReportGenerator()
        generator.output_dir = tmp_path
        paths = generator.generate(report)

        # JSON report
        assert "json" in paths
        json_path = paths["json"]
        with open(json_path) as f:
            data = json.load(f)

        assert data["report_id"] == "test-report-001"
        assert data["asset"]["hostname"] == "test.example.com"
        assert data["scan_summary"]["overall_risk"] == "CRITICAL"
        assert len(data["findings"]) == 1
        assert data["findings"][0]["check_id"] == "PORT-6379_OPEN"

        # Markdown report
        assert "markdown" in paths
        md_content = open(paths["markdown"]).read()
        assert "test.example.com" in md_content
        assert "CRITICAL" in md_content
        assert "Redis Exposed" in md_content

    def test_report_finding_counts(self):
        from src.models import SecurityReport

        asset = Asset(asset_id="x", asset_type=AssetType.ALB, hostname="x.com")
        findings = [
            SecurityFinding("C1", "", "", RiskLevel.CRITICAL, ""),
            SecurityFinding("C2", "", "", RiskLevel.CRITICAL, ""),
            SecurityFinding("H1", "", "", RiskLevel.HIGH, ""),
            SecurityFinding("M1", "", "", RiskLevel.MEDIUM, ""),
        ]
        report = SecurityReport(
            report_id="r1", asset=asset, metadata=None,
            findings=findings, llm_review=None,
            scan_status=ScanStatus.COMPLETE,
        )

        counts = report.finding_counts
        assert counts["CRITICAL"] == 2
        assert counts["HIGH"] == 1
        assert counts["MEDIUM"] == 1
        assert counts["LOW"] == 0
        assert report.highest_risk == RiskLevel.CRITICAL
