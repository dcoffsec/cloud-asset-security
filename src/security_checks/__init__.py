"""
Security check runner — orchestrates all checks and deduplicates findings.
"""
import logging
import time

from ..models import Asset, AssetMetadata, SecurityFinding
from .dns_checks import run_dns_checks
from .endpoint_checks import run_endpoint_checks
from .header_checks import run_header_checks
from .port_checks import run_port_checks
from .tls_checks import run_tls_checks

logger = logging.getLogger(__name__)


def run_all_checks(asset: Asset, metadata: AssetMetadata) -> list[SecurityFinding]:
    """
    Run all security checks against an asset and its collected metadata.

    Returns a deduplicated, severity-sorted list of findings.
    """
    start = time.time()
    all_findings: list[SecurityFinding] = []

    check_suites = [
        ("TLS Checks",      lambda: run_tls_checks(metadata)),
        ("Header Checks",   lambda: run_header_checks(metadata)),
        ("Endpoint Checks", lambda: run_endpoint_checks(asset, metadata)),
        ("Port Checks",     lambda: run_port_checks(metadata)),
        ("DNS Checks",      lambda: run_dns_checks(asset, metadata)),
    ]

    for suite_name, runner in check_suites:
        try:
            findings = runner()
            all_findings.extend(findings)
            logger.debug("%s: %d findings", suite_name, len(findings))
        except Exception as exc:
            logger.error("Check suite '%s' failed for %s: %s",
                         suite_name, asset.hostname, exc, exc_info=True)

    # Deduplicate by check_id (keep first occurrence)
    seen: set[str] = set()
    deduped: list[SecurityFinding] = []
    for f in all_findings:
        if f.check_id not in seen:
            seen.add(f.check_id)
            deduped.append(f)

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    deduped.sort(key=lambda f: severity_order.get(f.risk_level.value, 99))

    elapsed = time.time() - start
    logger.info(
        "Security checks complete for %s: %d findings in %.1fs",
        asset.hostname, len(deduped), elapsed
    )

    return deduped
