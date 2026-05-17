"""
Scan orchestrator — chains all pipeline stages for a single asset.

Pipeline stages:
  Asset → Enrich → Security Checks → LLM Review → Report → Alert

Design: each stage is independent and failures are caught so partial
results are still persisted and reported. The orchestrator is stateless
and safe to run in parallel (Lambda, Kubernetes Job, ECS Task).
"""
import logging
import time
import uuid
from datetime import datetime

from .config import get_config
from .discovery.asset_registry import AssetRegistry
from .enrichment import EnrichmentPipeline
from .llm_review.reviewer import generate_llm_review
from .models import Asset, ScanStatus, SecurityReport
from .reporting.report_generator import ReportGenerator
from .reporting.slack_notifier import send_slack_alert
from .security_checks import run_all_checks

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """
    Executes the full security review pipeline for a single asset.

    This class is the unit of work in our ephemeral execution model:
    - In Lambda: one invocation per asset
    - In Kubernetes Jobs: one Job per asset
    - In ECS: one Task per asset

    Each stage updates the asset's scan_status so external monitors
    can track progress and detect stalled jobs.
    """

    def __init__(self):
        self.config = get_config()
        self.registry = AssetRegistry()
        self.enricher = EnrichmentPipeline()
        self.reporter = ReportGenerator()

    def scan(self, asset: Asset) -> SecurityReport:
        """Run the full pipeline. Returns a complete SecurityReport."""
        overall_start = time.time()
        report_id = str(uuid.uuid4())[:12]

        logger.info("Starting scan [%s] for %s", report_id, asset.hostname)

        report = SecurityReport(
            report_id=report_id,
            asset=asset,
            metadata=None,
            findings=[],
            llm_review=None,
            scan_status=ScanStatus.ENRICHING,
        )

        # ── Stage 1: Enrichment ──────────────────────────────────────
        self.registry.update_status(asset.asset_id, ScanStatus.ENRICHING)
        try:
            metadata = self.enricher.enrich(asset)
            report.metadata = metadata
            logger.info("Enrichment complete for %s", asset.hostname)
        except Exception as exc:
            logger.error("Enrichment failed for %s: %s", asset.hostname, exc, exc_info=True)
            report.scan_status = ScanStatus.FAILED
            return report

        # ── Stage 2: Security Checks ─────────────────────────────────
        self.registry.update_status(asset.asset_id, ScanStatus.SCANNING)
        try:
            findings = run_all_checks(asset, metadata)
            report.findings = findings
            logger.info(
                "Security checks: %d findings for %s",
                len(findings), asset.hostname
            )
        except Exception as exc:
            logger.error("Security checks failed for %s: %s", asset.hostname, exc, exc_info=True)
            # Continue — partial results are better than none

        # ── Stage 3: LLM Review ──────────────────────────────────────
        self.registry.update_status(asset.asset_id, ScanStatus.REVIEWING)
        try:
            llm_review = generate_llm_review(asset, report.findings)
            report.llm_review = llm_review
            logger.info(
                "LLM review: overall risk=%s for %s",
                llm_review.overall_risk.value, asset.hostname
            )
        except Exception as exc:
            logger.error("LLM review failed for %s: %s", asset.hostname, exc, exc_info=True)
            # Non-fatal — proceed without LLM review

        # ── Stage 4: Report Generation ───────────────────────────────
        report.scan_duration_s = time.time() - overall_start
        report.scan_status = ScanStatus.COMPLETE
        self.registry.update_status(asset.asset_id, ScanStatus.COMPLETE)

        try:
            output_paths = self.reporter.generate(report)
            logger.info("Reports: %s", output_paths)
        except Exception as exc:
            logger.error("Report generation failed: %s", exc, exc_info=True)

        # ── Stage 5: Alerting ────────────────────────────────────────
        try:
            send_slack_alert(report)
        except Exception as exc:
            logger.warning("Alerting failed: %s", exc)

        logger.info(
            "Scan complete [%s] for %s — risk=%s findings=%d duration=%.1fs",
            report_id,
            asset.hostname,
            report.highest_risk.value,
            len(report.findings),
            report.scan_duration_s,
        )

        return report


def scan_asset_by_id(asset_id: str) -> SecurityReport | None:
    """
    Entry point for Lambda / Kubernetes Job invocation.
    Loads asset from registry and runs full pipeline.
    """
    registry = AssetRegistry()
    asset = registry.get_by_id(asset_id)
    if not asset:
        logger.error("Asset not found: %s", asset_id)
        return None

    orchestrator = ScanOrchestrator()
    return orchestrator.scan(asset)
