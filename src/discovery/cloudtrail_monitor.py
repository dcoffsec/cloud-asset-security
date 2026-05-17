"""
CloudTrail-based asset discovery.

Monitors CloudTrail events for internet-facing resource creation:
  - EC2 instances with public IPs
  - ALB / NLB creation
  - API Gateway deployments
  - Route53 record changes
  - ECS service creation
  - CloudFront distribution creation

In production this would subscribe to an EventBridge rule or
poll a CloudTrail Lake query. For the prototype we poll the
CloudTrail LookupEvents API, which covers the last 90 days.
"""
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Iterator

from ..config import get_config
from ..models import Asset, AssetType

logger = logging.getLogger(__name__)

# CloudTrail event → AssetType mapping
INTERESTING_EVENTS: dict[str, AssetType] = {
    # EC2
    "RunInstances": AssetType.EC2_INSTANCE,
    "AllocateAddress": AssetType.EC2_INSTANCE,
    # Load balancers
    "CreateLoadBalancer": AssetType.ALB,
    # API Gateway
    "CreateRestApi": AssetType.API_GATEWAY,
    "CreateApi": AssetType.API_GATEWAY,
    "CreateDeployment": AssetType.API_GATEWAY,
    # Route53
    "ChangeResourceRecordSets": AssetType.ROUTE53_RECORD,
    # ECS
    "CreateService": AssetType.ECS_SERVICE,
    # CloudFront
    "CreateDistribution": AssetType.CLOUDFRONT,
    # S3
    "CreateBucket": AssetType.S3_BUCKET,
    "PutBucketAcl": AssetType.S3_BUCKET,
    "PutBucketPolicy": AssetType.S3_BUCKET,
}


class CloudTrailMonitor:
    """
    Polls CloudTrail for resource-creation events and yields Asset objects.

    Design notes
    ------------
    - Uses LookupEvents with an AttributeKey filter on EventName so we only
      pull the events we care about (avoids full log streaming costs).
    - Maintains a high-water-mark timestamp so repeated polls don't reprocess
      old events.
    - In production, replace the poll loop with an EventBridge rule that
      invokes a Lambda / SQS message, eliminating polling entirely.
    """

    def __init__(self, boto_session=None):
        self.config = get_config()
        self._last_poll: datetime = datetime.now(timezone.utc) - timedelta(minutes=5)
        self._seen_event_ids: set[str] = set()

        if self.config.mock_aws:
            self._client = None
        else:
            import boto3
            session = boto_session or boto3.Session(region_name=self.config.aws_region)
            self._client = session.client("cloudtrail")

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def poll(self) -> Iterator[Asset]:
        """Yield newly discovered assets since the last poll."""
        if self.config.mock_aws:
            yield from self._mock_events()
            return

        now = datetime.now(timezone.utc)
        try:
            events = self._fetch_events(self._last_poll, now)
            for event in events:
                asset = self._parse_event(event)
                if asset:
                    yield asset
        except Exception as exc:
            logger.error("CloudTrail poll failed: %s", exc)
        finally:
            self._last_poll = now

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _fetch_events(self, start: datetime, end: datetime) -> list[dict]:
        """Fetch CloudTrail events in the given time window."""
        results = []
        paginator = self._client.get_paginator("lookup_events")

        for event_name in INTERESTING_EVENTS:
            try:
                pages = paginator.paginate(
                    LookupAttributes=[
                        {"AttributeKey": "EventName", "AttributeValue": event_name}
                    ],
                    StartTime=start,
                    EndTime=end,
                )
                for page in pages:
                    results.extend(page.get("Events", []))
            except Exception as exc:
                logger.warning("Failed to fetch events for %s: %s", event_name, exc)

        return results

    def _parse_event(self, event: dict) -> Asset | None:
        """Convert a raw CloudTrail event into an Asset."""
        event_id = event.get("EventId", "")
        if event_id in self._seen_event_ids:
            return None
        self._seen_event_ids.add(event_id)

        event_name = event.get("EventName", "")
        asset_type = INTERESTING_EVENTS.get(event_name, AssetType.UNKNOWN)

        try:
            cloud_trail_event = json.loads(event.get("CloudTrailEvent", "{}"))
        except json.JSONDecodeError:
            cloud_trail_event = {}

        hostname = self._extract_hostname(event_name, cloud_trail_event)
        if not hostname:
            return None

        return Asset(
            asset_id=str(uuid.uuid4()),
            asset_type=asset_type,
            hostname=hostname,
            region=cloud_trail_event.get("awsRegion", self.config.aws_region),
            account_id=cloud_trail_event.get("userIdentity", {}).get("accountId", ""),
            resource_arn=self._extract_arn(cloud_trail_event),
            tags=self._extract_tags(cloud_trail_event),
            discovered_at=event.get("EventTime", datetime.now(timezone.utc)),
            discovered_via="cloudtrail",
            raw_event=cloud_trail_event,
        )

    def _extract_hostname(self, event_name: str, event: dict) -> str:
        """Best-effort extraction of a hostname/endpoint from the event."""
        resp = event.get("responseElements") or {}
        req = event.get("requestParameters") or {}

        extractors = {
            "RunInstances": lambda: (
                resp.get("instancesSet", {})
                    .get("items", [{}])[0]
                    .get("dnsName", "")
                or resp.get("instancesSet", {})
                    .get("items", [{}])[0]
                    .get("ipAddress", "")
            ),
            "CreateLoadBalancer": lambda: (
                resp.get("loadBalancers", [{}])[0].get("dNSName", "")
            ),
            "CreateRestApi": lambda: (
                f"{resp.get('id', '')}.execute-api."
                f"{event.get('awsRegion', 'us-east-1')}.amazonaws.com"
                if resp.get("id") else ""
            ),
            "CreateApi": lambda: resp.get("apiEndpoint", ""),
            "ChangeResourceRecordSets": lambda: self._extract_route53_hostname(req),
            "CreateDistribution": lambda: (
                resp.get("distribution", {})
                    .get("domainName", "")
            ),
            "CreateBucket": lambda: (
                f"{req.get('bucketName', '')}.s3.amazonaws.com"
                if req.get("bucketName") else ""
            ),
        }

        extractor = extractors.get(event_name)
        if extractor:
            try:
                return extractor() or ""
            except (KeyError, IndexError, TypeError):
                pass

        return ""

    def _extract_route53_hostname(self, req: dict) -> str:
        """Extract the first A/CNAME record from a Route53 change batch."""
        changes = (
            req.get("changeBatch", {})
               .get("changes", {})
               .get("items", [])
        )
        for change in changes:
            record = change.get("resourceRecordSet", {})
            rtype = record.get("type", "")
            if rtype in ("A", "AAAA", "CNAME"):
                name = record.get("name", "")
                # Strip trailing dot
                return name.rstrip(".")
        return ""

    def _extract_arn(self, event: dict) -> str:
        resp = event.get("responseElements") or {}
        # Try common ARN fields
        for key in ("loadBalancerArn", "arn", "functionArn", "distributionArn"):
            if val := resp.get(key):
                return val
        return ""

    def _extract_tags(self, event: dict) -> dict[str, str]:
        req = event.get("requestParameters") or {}
        raw_tags = req.get("tagSpecificationSet", {}).get("items", [])
        tags: dict[str, str] = {}
        for spec in raw_tags:
            for tag in spec.get("tags", {}).get("items", []):
                if k := tag.get("key"):
                    tags[k] = tag.get("value", "")
        return tags

    # ------------------------------------------------------------------
    # Mock data for local development / CI
    # ------------------------------------------------------------------

    def _mock_events(self) -> Iterator[Asset]:
        """Yield synthetic assets for demo / testing without AWS credentials."""
        target = self.config.mock_target or "example.com"
        mock_assets = [
            Asset(
                asset_id="mock-001",
                asset_type=AssetType.ALB,
                hostname=target,
                ip_addresses=[],
                region="us-east-1",
                account_id="123456789012",
                tags={"Owner": "platform-team", "Environment": "production",
                      "Team": "backend"},
                discovered_via="mock",
            ),
            Asset(
                asset_id="mock-002",
                asset_type=AssetType.API_GATEWAY,
                hostname=f"api.{target}",
                ip_addresses=[],
                region="us-east-1",
                account_id="123456789012",
                tags={"Owner": "api-team", "Environment": "staging"},
                discovered_via="mock",
            ),
        ]
        yield from mock_assets
