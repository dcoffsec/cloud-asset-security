"""
Report generation — produces JSON and human-readable Markdown reports.
"""
import json
import logging
import os
import uuid
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from ..config import get_config
from ..models import RiskLevel, SecurityReport

logger = logging.getLogger(__name__)

RISK_EMOJI = {
    RiskLevel.CRITICAL: "🔴",
    RiskLevel.HIGH:     "🟠",
    RiskLevel.MEDIUM:   "🟡",
    RiskLevel.LOW:      "🔵",
    RiskLevel.INFO:     "⚪",
}

RISK_COLOR = {
    "CRITICAL": "#FF0000",
    "HIGH":     "#FF6600",
    "MEDIUM":   "#FFAA00",
    "LOW":      "#2196F3",
    "INFO":     "#9E9E9E",
}


class ReportGenerator:

    def __init__(self):
        self.config = get_config()
        self.output_dir = Path(self.config.reports_output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, report: SecurityReport) -> dict[str, str]:
        """
        Generate JSON and Markdown reports.
        Returns dict of {format: filepath}.
        """
        report_id = report.report_id or str(uuid.uuid4())[:8]
        hostname_safe = report.asset.hostname.replace(".", "_").replace("/", "_")
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        base_name = f"report_{hostname_safe}_{ts}"

        outputs = {}

        # JSON
        json_path = self.output_dir / f"{base_name}.json"
        self._write_json(report, json_path)
        outputs["json"] = str(json_path)

        # Markdown
        md_path = self.output_dir / f"{base_name}.md"
        self._write_markdown(report, md_path)
        outputs["markdown"] = str(md_path)

        logger.info("Reports written: %s", outputs)
        return outputs

    # ------------------------------------------------------------------
    # JSON output
    # ------------------------------------------------------------------

    def _write_json(self, report: SecurityReport, path: Path):
        """Write a full machine-readable JSON report."""
        data = {
            "report_id": report.report_id,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "asset": {
                "asset_id": report.asset.asset_id,
                "hostname": report.asset.hostname,
                "asset_type": report.asset.asset_type.value,
                "region": report.asset.region,
                "account_id": report.asset.account_id,
                "resource_arn": report.asset.resource_arn,
                "owner": report.asset.owner,
                "team": report.asset.team,
                "environment": report.asset.environment,
                "tags": report.asset.tags,
                "discovered_at": report.asset.discovered_at.isoformat(),
                "discovered_via": report.asset.discovered_via,
            },
            "scan_summary": {
                "status": report.scan_status.value,
                "duration_seconds": round(report.scan_duration_s, 2),
                "finding_counts": report.finding_counts,
                "overall_risk": report.highest_risk.value,
            },
            "findings": [
                {
                    "check_id": f.check_id,
                    "title": f.title,
                    "risk_level": f.risk_level.value,
                    "category": f.category,
                    "description": f.description,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "cwe_id": f.cwe_id,
                    "cvss_score": f.cvss_score,
                    "references": f.references,
                }
                for f in report.findings
            ],
            "llm_review": (
                {
                    "overall_risk": report.llm_review.overall_risk.value,
                    "executive_summary": report.llm_review.executive_summary,
                    "key_findings": report.llm_review.key_findings,
                    "attack_surface_analysis": report.llm_review.attack_surface_analysis,
                    "prioritized_actions": report.llm_review.prioritized_actions,
                    "threat_scenarios": report.llm_review.threat_scenarios,
                    "compliance_notes": report.llm_review.compliance_notes,
                    "model": report.llm_review.model,
                    "tokens_used": report.llm_review.tokens_used,
                }
                if report.llm_review else None
            ),
            "metadata": (
                {
                    "dns_records": report.metadata.dns_records,
                    "port_scan": (
                        {
                            "open_ports": report.metadata.port_scan.open_ports,
                            "port_services": report.metadata.port_scan.port_services,
                            "scan_time_s": report.metadata.port_scan.scan_time_s,
                        }
                        if report.metadata.port_scan else None
                    ),
                    "http_info": self._http_info_dict(report.metadata.http_info),
                    "https_info": self._http_info_dict(report.metadata.https_info),
                    "tls_info": (
                        {
                            "issuer": report.metadata.tls_info.issuer,
                            "subject": report.metadata.tls_info.subject,
                            "valid_to": str(report.metadata.tls_info.valid_to),
                            "days_to_expiry": report.metadata.tls_info.days_to_expiry,
                            "is_expired": report.metadata.tls_info.is_expired,
                            "is_self_signed": report.metadata.tls_info.is_self_signed,
                            "is_wildcard": report.metadata.tls_info.is_wildcard,
                            "protocol_versions": report.metadata.tls_info.protocol_versions,
                            "san_domains": report.metadata.tls_info.san_domains,
                        }
                        if report.metadata.tls_info else None
                    ),
                }
                if report.metadata else None
            ),
        }

        path.write_text(json.dumps(data, indent=2, default=str))

    @staticmethod
    def _http_info_dict(info) -> dict | None:
        if not info:
            return None
        return {
            "status_code": info.status_code,
            "server": info.server,
            "technologies": info.technologies,
            "waf_detected": info.waf_detected,
            "cdn_detected": info.cdn_detected,
            "cdn_provider": info.cdn_provider,
            "response_time_ms": round(info.response_time_ms, 1),
            "content_type": info.content_type,
            "security_headers": {
                k: v for k, v in info.headers.items()
                if k.lower() in {
                    "strict-transport-security", "x-content-type-options",
                    "x-frame-options", "content-security-policy",
                    "referrer-policy", "permissions-policy",
                }
            },
        }

    # ------------------------------------------------------------------
    # Markdown output
    # ------------------------------------------------------------------

    def _write_markdown(self, report: SecurityReport, path: Path):
        md = self._render_markdown(report)
        path.write_text(md, encoding="utf-8")

    def _render_markdown(self, report: SecurityReport) -> str:
        r = report
        asset = r.asset
        llm = r.llm_review
        counts = r.finding_counts
        highest = r.highest_risk

        lines = []
        a = lines.append

        # Header
        a(f"# Cloud Asset Security Review")
        a(f"**{asset.hostname}**  ·  {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
        a("")

        # Risk badge
        emoji = RISK_EMOJI.get(highest, "⚪")
        a(f"## {emoji} Overall Risk: {highest.value}")
        a("")

        # Asset info table
        a("## Asset Information")
        a("")
        a("| Field | Value |")
        a("|-------|-------|")
        a(f"| Hostname | `{asset.hostname}` |")
        a(f"| Asset Type | {asset.asset_type.value} |")
        a(f"| Environment | {asset.environment} |")
        a(f"| Owner | {asset.owner} |")
        a(f"| Team | {asset.team} |")
        a(f"| Region | {asset.region} |")
        a(f"| Account | {asset.account_id} |")
        a(f"| Discovered Via | {asset.discovered_via} |")
        a(f"| Scan Duration | {round(r.scan_duration_s, 1)}s |")
        a("")

        # Finding counts
        a("## Finding Summary")
        a("")
        a("| Severity | Count |")
        a("|----------|-------|")
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = counts.get(level, 0)
            emoji_l = RISK_EMOJI.get(RiskLevel(level), "")
            a(f"| {emoji_l} {level} | {count} |")
        a(f"| **Total** | **{len(r.findings)}** |")
        a("")

        # Executive summary (from LLM)
        if llm:
            a("## Executive Summary")
            a("")
            a(llm.executive_summary)
            a("")

        # Attack surface
        if llm and llm.attack_surface_analysis:
            a("## Attack Surface Analysis")
            a("")
            a(llm.attack_surface_analysis)
            a("")

        # Threat scenarios
        if llm and llm.threat_scenarios:
            a("## Threat Scenarios")
            a("")
            for scenario in llm.threat_scenarios:
                a(f"- {scenario}")
            a("")

        # Prioritized actions
        if llm and llm.prioritized_actions:
            a("## Prioritized Remediation Actions")
            a("")
            a("| # | Action | Effort | Impact |")
            a("|---|--------|--------|--------|")
            for action in llm.prioritized_actions:
                a(f"| {action.get('priority','?')} | {action.get('action','')} "
                  f"| {action.get('effort','')} | {action.get('impact','')} |")
            a("")

        # Detailed findings
        a("## Detailed Findings")
        a("")

        current_category = None
        for i, finding in enumerate(r.findings, 1):
            if finding.category != current_category:
                current_category = finding.category
                a(f"### {finding.category}")
                a("")

            emoji_f = RISK_EMOJI.get(finding.risk_level, "⚪")
            a(f"#### {emoji_f} [{finding.risk_level.value}] {finding.title}")
            a("")
            a(f"**Check ID:** `{finding.check_id}`  ")
            if finding.cwe_id:
                a(f"**CWE:** [{finding.cwe_id}](https://cwe.mitre.org/data/definitions/"
                  f"{finding.cwe_id.replace('CWE-','')}.html)")
            a("")
            a(finding.description)
            a("")

            if finding.evidence:
                a("**Evidence:**")
                a("```json")
                a(json.dumps(finding.evidence, indent=2, default=str))
                a("```")
                a("")

            if finding.remediation:
                a(f"**Remediation:** {finding.remediation}")
                a("")

            if finding.references:
                a("**References:**")
                for ref in finding.references:
                    a(f"- {ref}")
                a("")

            a("---")
            a("")

        # Infrastructure metadata
        if r.metadata:
            a("## Asset Metadata")
            a("")

            dns = r.metadata.dns_records
            if dns:
                a("### DNS")
                a(f"- **IPv4:** {', '.join(dns.get('ipv4', [])) or 'none'}")
                a(f"- **IPv6:** {', '.join(dns.get('ipv6', [])) or 'none'}")
                if dns.get('cname'):
                    a(f"- **CNAME:** {dns['cname']}")
                a("")

            if r.metadata.tls_info:
                tls = r.metadata.tls_info
                a("### TLS Certificate")
                a(f"- **Issuer:** {tls.issuer}")
                a(f"- **Valid To:** {tls.valid_to} ({tls.days_to_expiry} days)")
                a(f"- **Protocols:** {', '.join(tls.protocol_versions)}")
                a(f"- **Self-signed:** {tls.is_self_signed}")
                a(f"- **Wildcard:** {tls.is_wildcard}")
                a("")

            if r.metadata.port_scan:
                scan = r.metadata.port_scan
                a("### Open Ports")
                if scan.open_ports:
                    a("| Port | Service |")
                    a("|------|---------|")
                    for port in scan.open_ports:
                        a(f"| {port} | {scan.port_services.get(port, 'unknown')} |")
                else:
                    a("No high-risk ports detected.")
                a("")

            http = r.metadata.https_info or r.metadata.http_info
            if http:
                a("### HTTP Response")
                a(f"- **Status:** {http.status_code}")
                a(f"- **Server:** {http.server or 'not disclosed'}")
                a(f"- **Technologies:** {', '.join(http.technologies) or 'none detected'}")
                a(f"- **WAF Detected:** {http.waf_detected}")
                a(f"- **CDN Detected:** {http.cdn_detected} ({http.cdn_provider})")
                a(f"- **Response Time:** {round(http.response_time_ms)}ms")
                a("")

        # Compliance
        if llm and llm.compliance_notes:
            a("## Compliance Notes")
            a("")
            a(llm.compliance_notes)
            a("")

        # Footer
        a("---")
        a(f"*Generated by Cloud Asset Security Review System · "
          f"Model: {llm.model if llm else 'N/A'} · "
          f"Tokens: {llm.tokens_used if llm else 0}*")

        return "\n".join(lines)
