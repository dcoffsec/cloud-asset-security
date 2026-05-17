"""
AWS Lambda handlers for the security review pipeline.

Three handler entry points:

1. handler_discover     — Triggered by EventBridge rule on CloudTrail events.
                          Registers the asset and enqueues a scan.

2. handler_scan         — Triggered by SQS. Runs full scan pipeline for one asset.
                          Designed for Lambda with concurrency limit = max_concurrent_scans.

3. handler_step_fn      — Step Functions task token handler. For use with
                          AWS Step Functions workflow orchestration.

EventBridge rule (CloudFormation snippet):
  EventPattern:
    source: [aws.ec2, aws.elasticloadbalancing, aws.apigateway, aws.route53]
    detail-type: [AWS API Call via CloudTrail]
    detail:
      eventName:
        - RunInstances
        - CreateLoadBalancer
        - CreateRestApi
        - ChangeResourceRecordSets
        - CreateDistribution

SQS message format:
  {"asset_id": "<uuid>"}
"""
import json
import logging
import os

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def handler_discover(event: dict, context) -> dict:
    """
    EventBridge / CloudTrail event → asset registration.

    This Lambda runs in under 100ms typically — it just parses the event,
    registers the asset, and sends a message to SQS for async scanning.
    """
    import boto3
    from .discovery.cloudtrail_monitor import CloudTrailMonitor
    from .discovery.asset_registry import AssetRegistry

    logger.info("Discovery event: %s", json.dumps(event, default=str)[:500])

    monitor = CloudTrailMonitor()
    registry = AssetRegistry()
    sqs = boto3.client("sqs")
    queue_url = os.environ["SCAN_QUEUE_URL"]

    registered = 0

    # EventBridge wraps the CloudTrail event in event["detail"]
    raw_event = event.get("detail", event)
    asset = monitor._parse_event({
        "EventId": raw_event.get("eventID", ""),
        "EventName": raw_event.get("eventName", ""),
        "EventTime": raw_event.get("eventTime"),
        "CloudTrailEvent": json.dumps(raw_event),
    })

    if asset and registry.register(asset):
        # Enqueue for async scanning
        sqs.send_message(
            QueueUrl=queue_url,
            MessageBody=json.dumps({"asset_id": asset.asset_id}),
            MessageGroupId="security-scan",  # For FIFO queues
        )
        registered += 1
        logger.info("Registered and enqueued: %s (%s)", asset.hostname, asset.asset_id)

    return {"registered": registered}


def handler_scan(event: dict, context) -> dict:
    """
    SQS trigger → full scan pipeline.

    Each SQS message triggers one Lambda invocation scanning one asset.
    Lambda concurrency limit enforces max_concurrent_scans.

    Ephemeral isolation: each Lambda execution is isolated — no shared
    filesystem, fresh memory space, auto-cleaned after execution.
    Cost: ~$0.0001 per scan at typical memory/duration settings.
    """
    from .orchestration.scan_orchestrator import scan_asset_by_id

    results = []
    for record in event.get("Records", []):
        try:
            body = json.loads(record["body"])
            asset_id = body["asset_id"]
            logger.info("Processing scan for asset: %s", asset_id)

            report = scan_asset_by_id(asset_id)
            if report:
                results.append({
                    "asset_id": asset_id,
                    "status": "complete",
                    "risk": report.highest_risk.value,
                    "findings": len(report.findings),
                })
            else:
                results.append({"asset_id": asset_id, "status": "not_found"})

        except Exception as exc:
            logger.error("Scan failed for record: %s — %s", record, exc, exc_info=True)
            results.append({"status": "error", "error": str(exc)})
            # Re-raise so SQS retries the message (up to maxReceiveCount)
            raise

    return {"results": results}


def handler_step_fn(event: dict, context) -> dict:
    """
    Step Functions task handler.

    Step Functions state machine:
      DiscoverAsset → EnrichAsset → RunSecurityChecks → LLMReview → GenerateReport → Notify

    This single handler implements all states — the `state` field in the
    event determines which stage to run.
    """
    from .enrichment import EnrichmentPipeline
    from .llm_review.reviewer import generate_llm_review
    from .discovery.asset_registry import AssetRegistry
    from .security_checks import run_all_checks
    from .reporting.report_generator import ReportGenerator

    state = event.get("state", "enrich")
    asset_id = event["asset_id"]

    registry = AssetRegistry()
    asset = registry.get_by_id(asset_id)

    if not asset:
        return {"error": f"Asset {asset_id} not found", "state": state}

    if state == "enrich":
        pipeline = EnrichmentPipeline()
        metadata = pipeline.enrich(asset)
        return {
            "asset_id": asset_id,
            "state": "scan",
            "enrichment_complete": True,
            # Step Functions passes this to the next state
            "open_ports": metadata.port_scan.open_ports if metadata.port_scan else [],
        }

    elif state == "scan":
        pipeline = EnrichmentPipeline()
        metadata = pipeline.enrich(asset)  # Re-run (stateless)
        findings = run_all_checks(asset, metadata)
        return {
            "asset_id": asset_id,
            "state": "review",
            "finding_count": len(findings),
            "highest_risk": max(
                (f.risk_level.value for f in findings),
                default="INFO"
            ),
        }

    return {"asset_id": asset_id, "state": state, "status": "unknown_state"}
