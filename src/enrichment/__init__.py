"""
Asset enrichment pipeline — runs all enrichers in the right order.
"""
import logging
import time

from ..config import get_config
from ..models import Asset, AssetMetadata
from .http_enricher import DNSEnricher, HTTPEnricher
from .port_scanner import PortScanner
from .tls_enricher import TLSEnricher

logger = logging.getLogger(__name__)


class EnrichmentPipeline:
    """
    Runs all enrichers against an asset and returns populated AssetMetadata.

    Order matters:
    1. DNS — resolve hostname to IPs first
    2. Port scan — against resolved IP(s)
    3. HTTP — fetch response metadata
    4. HTTPS — fetch TLS + response metadata
    5. TLS details — extract certificate info
    """

    def __init__(self):
        self.config = get_config()
        self.dns = DNSEnricher()
        self.http = HTTPEnricher()
        self.tls = TLSEnricher()
        self.ports = PortScanner()

    def enrich(self, asset: Asset) -> AssetMetadata:
        start = time.time()
        metadata = AssetMetadata(asset_id=asset.asset_id)
        hostname = asset.hostname

        logger.info("Starting enrichment for %s", hostname)

        # 1. DNS
        try:
            dns_result = self.dns.enrich(hostname)
            metadata.dns_records = dns_result
            # Update asset IPs from DNS
            if dns_result.get("ipv4"):
                asset.ip_addresses = dns_result["ipv4"]
        except Exception as exc:
            logger.warning("DNS enrichment failed: %s", exc)

        # 2. Port scan (use first resolved IP for accuracy, fall back to hostname)
        try:
            scan_target = (
                asset.ip_addresses[0] if asset.ip_addresses else hostname
            )
            metadata.port_scan = self.ports.scan(scan_target)
            logger.debug(
                "Port scan: %d open ports on %s",
                len(metadata.port_scan.open_ports), scan_target
            )
        except Exception as exc:
            logger.warning("Port scan failed: %s", exc)

        # 3. HTTP
        try:
            metadata.http_info = self.http.enrich_http(hostname)
        except Exception as exc:
            logger.warning("HTTP enrichment failed: %s", exc)

        # 4. HTTPS
        try:
            metadata.https_info = self.http.enrich_https(hostname)
        except Exception as exc:
            logger.warning("HTTPS enrichment failed: %s", exc)

        # 5. TLS certificate details
        if metadata.https_info:
            try:
                metadata.tls_info = self.tls.enrich(hostname)
            except Exception as exc:
                logger.warning("TLS enrichment failed: %s", exc)

        elapsed = time.time() - start
        logger.info("Enrichment complete for %s in %.1fs", hostname, elapsed)
        return metadata
