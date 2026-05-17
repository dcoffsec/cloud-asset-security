"""
CLI entry point — run security scans locally or in demo mode.

Usage examples:
  # Scan a real host (no AWS required)
  python -m src.main scan --target example.com

  # Demo mode with mock AWS assets
  MOCK_AWS=true MOCK_TARGET=example.com python -m src.main demo

  # Process pending assets from registry
  python -m src.main worker --once

  # Show registry stats
  python -m src.main stats
"""
import argparse
import json
import logging
import os
import sys
import uuid
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)

# Silence noisy third-party loggers
for noisy in ["urllib3", "requests", "anthropic"]:
    logging.getLogger(noisy).setLevel(logging.WARNING)

logger = logging.getLogger("main")


def cmd_scan(args):
    """Scan a single target hostname."""
    from src.models import Asset, AssetType
    from src.orchestration.scan_orchestrator import ScanOrchestrator
    from src.discovery.asset_registry import AssetRegistry

    hostname = args.target.lstrip("https://").lstrip("http://").split("/")[0]
    logger.info("Scanning target: %s", hostname)

    asset = Asset(
        asset_id=str(uuid.uuid4()),
        asset_type=AssetType(args.asset_type),
        hostname=hostname,
        tags={
            "Owner": args.owner or "security-team",
            "Environment": args.env or "unknown",
            "Team": args.team or "unknown",
        },
        discovered_via="cli",
    )

    # Register in DB
    registry = AssetRegistry()
    registry.register(asset)

    # Run scan
    orchestrator = ScanOrchestrator()
    report = orchestrator.scan(asset)

    # Print summary
    print_report_summary(report)

    if args.json:
        from src.reporting.report_generator import ReportGenerator
        rg = ReportGenerator()
        paths = rg.generate(report)
        print(f"\nReports written to:")
        for fmt, path in paths.items():
            print(f"  [{fmt}] {path}")


def cmd_demo(args):
    """Run with mock AWS assets for demonstration."""
    os.environ["MOCK_AWS"] = "true"
    os.environ["MOCK_TARGET"] = args.target or "example.com"

    from src.discovery.cloudtrail_monitor import CloudTrailMonitor
    from src.discovery.asset_registry import AssetRegistry
    from src.orchestration.scan_orchestrator import ScanOrchestrator

    monitor = CloudTrailMonitor()
    registry = AssetRegistry()
    orchestrator = ScanOrchestrator()

    logger.info("Starting demo mode — mock target: %s", os.environ["MOCK_TARGET"])

    assets = list(monitor.poll())
    if not assets:
        logger.error("No mock assets generated")
        return

    for asset in assets:
        registry.register(asset)
        logger.info("Scanning: %s (%s)", asset.hostname, asset.asset_type.value)
        report = orchestrator.scan(asset)
        print_report_summary(report)
        print()


def cmd_worker(args):
    """Process pending assets from the registry."""
    from src.discovery.asset_registry import AssetRegistry
    from src.orchestration.scan_orchestrator import ScanOrchestrator
    from src.models import ScanStatus
    import time

    registry = AssetRegistry()
    orchestrator = ScanOrchestrator()

    iterations = 1 if args.once else float("inf")
    count = 0

    while count < iterations:
        pending = registry.get_pending(limit=5)
        if not pending:
            if args.once:
                logger.info("No pending assets")
                break
            time.sleep(10)
            continue

        for asset in pending:
            logger.info("Processing: %s", asset.hostname)
            orchestrator.scan(asset)

        count += 1
        if not args.once:
            time.sleep(5)


def cmd_stats(args):
    """Print registry statistics."""
    from src.discovery.asset_registry import AssetRegistry
    registry = AssetRegistry()
    stats = registry.stats()
    print(json.dumps(stats, indent=2))


def print_report_summary(report):
    """Print a compact summary to stdout."""
    from src.models import RiskLevel

    risk_colors = {
        "CRITICAL": "\033[91m",  # red
        "HIGH":     "\033[93m",  # yellow
        "MEDIUM":   "\033[33m",  # dark yellow
        "LOW":      "\033[94m",  # blue
        "INFO":     "\033[37m",  # grey
    }
    RESET = "\033[0m"
    BOLD  = "\033[1m"

    r = report
    risk = r.highest_risk.value
    color = risk_colors.get(risk, "")

    print(f"\n{'═'*60}")
    print(f"{BOLD}Asset: {r.asset.hostname}{RESET}")
    print(f"Type:  {r.asset.asset_type.value}  |  Env: {r.asset.environment}  |  Owner: {r.asset.owner}")
    print(f"{'─'*60}")
    print(f"Overall Risk: {color}{BOLD}{risk}{RESET}")
    print(f"Scan Duration: {round(r.scan_duration_s, 1)}s")
    print()

    counts = r.finding_counts
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        c = counts.get(level, 0)
        if c > 0:
            col = risk_colors.get(level, "")
            print(f"  {col}{level:8s}{RESET}: {c}")

    print()
    if r.findings:
        print(f"{BOLD}Top Findings:{RESET}")
        for f in r.findings[:5]:
            col = risk_colors.get(f.risk_level.value, "")
            print(f"  [{col}{f.risk_level.value}{RESET}] {f.title}")

    if r.llm_review:
        print(f"\n{BOLD}AI Summary:{RESET}")
        # Word-wrap at 70 chars
        words = r.llm_review.executive_summary.split()
        line = ""
        for word in words:
            if len(line) + len(word) > 68:
                print(f"  {line}")
                line = word
            else:
                line = (line + " " + word).strip()
        if line:
            print(f"  {line}")

    print(f"{'═'*60}")


def main():
    parser = argparse.ArgumentParser(
        description="Cloud Asset Security Review — CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # scan
    p_scan = sub.add_parser("scan", help="Scan a single hostname")
    p_scan.add_argument("--target", required=True, help="Hostname or URL to scan")
    p_scan.add_argument("--asset-type", default="alb",
                        choices=["alb", "api_gateway", "ec2_instance", "route53_record",
                                 "s3_bucket", "ecs_service", "cloudfront", "unknown"])
    p_scan.add_argument("--owner",  default="", help="Asset owner tag")
    p_scan.add_argument("--team",   default="", help="Team tag")
    p_scan.add_argument("--env",    default="production", help="Environment tag")
    p_scan.add_argument("--json",   action="store_true", help="Write JSON/MD reports to disk")
    p_scan.set_defaults(func=cmd_scan)

    # demo
    p_demo = sub.add_parser("demo", help="Run with mock AWS assets")
    p_demo.add_argument("--target", default="example.com", help="Mock target hostname")
    p_demo.set_defaults(func=cmd_demo)

    # worker
    p_worker = sub.add_parser("worker", help="Process pending assets from registry")
    p_worker.add_argument("--once", action="store_true", help="Process one batch and exit")
    p_worker.set_defaults(func=cmd_worker)

    # stats
    p_stats = sub.add_parser("stats", help="Show registry statistics")
    p_stats.set_defaults(func=cmd_stats)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
