"""
Slack alerting — posts critical/high findings to a webhook.
"""
import json
import logging

import requests

from ..config import get_config
from ..models import RiskLevel, SecurityReport

logger = logging.getLogger(__name__)

RISK_COLOR = {
    "CRITICAL": "#FF0000",
    "HIGH":     "#FF6600",
    "MEDIUM":   "#FFAA00",
    "LOW":      "#2196F3",
    "INFO":     "#9E9E9E",
}


def send_slack_alert(report: SecurityReport) -> bool:
    """Post a Slack message for high/critical findings. Returns True on success."""
    config = get_config()
    if not config.slack_webhook_url:
        return False

    highest = report.highest_risk
    if highest.value not in config.alert_on_risk_levels:
        return False

    counts = report.finding_counts
    critical = counts.get("CRITICAL", 0)
    high = counts.get("HIGH", 0)

    llm_summary = ""
    if report.llm_review:
        llm_summary = report.llm_review.executive_summary[:200]

    top_findings = [
        f"• [{f.risk_level.value}] {f.title}"
        for f in report.findings[:5]
        if f.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)
    ]

    payload = {
        "attachments": [
            {
                "color": RISK_COLOR.get(highest.value, "#9E9E9E"),
                "pretext": f":rotating_light: *New {highest.value} security finding on* `{report.asset.hostname}`",
                "fields": [
                    {"title": "Asset",        "value": report.asset.hostname,        "short": True},
                    {"title": "Environment",  "value": report.asset.environment,     "short": True},
                    {"title": "Owner",        "value": report.asset.owner,           "short": True},
                    {"title": "Risk Level",   "value": highest.value,                "short": True},
                    {"title": "Critical",     "value": str(critical),                "short": True},
                    {"title": "High",         "value": str(high),                    "short": True},
                    {
                        "title": "Top Findings",
                        "value": "\n".join(top_findings) if top_findings else "See report",
                        "short": False,
                    },
                    {
                        "title": "AI Summary",
                        "value": llm_summary or "N/A",
                        "short": False,
                    },
                ],
                "footer": f"Cloud Asset Security Review · {report.report_id}",
            }
        ]
    }

    try:
        resp = requests.post(
            config.slack_webhook_url,
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        resp.raise_for_status()
        logger.info("Slack alert sent for %s", report.asset.hostname)
        return True
    except Exception as exc:
        logger.warning("Slack alert failed: %s", exc)
        return False
