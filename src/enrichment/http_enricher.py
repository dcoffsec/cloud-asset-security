"""
Asset enrichment — DNS, HTTP headers, technology fingerprinting.
"""
import logging
import re
import socket
import time
from typing import Optional
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException

from ..config import get_config
from ..models import HTTPInfo

logger = logging.getLogger(__name__)

# Technology fingerprinting signatures
# Maps header/body patterns → technology name
TECH_SIGNATURES: list[tuple[str, str, str]] = [
    # (source, pattern, tech_name)
    ("header:server",      r"nginx",           "Nginx"),
    ("header:server",      r"apache",          "Apache"),
    ("header:server",      r"Microsoft-IIS",   "IIS"),
    ("header:server",      r"cloudflare",      "Cloudflare"),
    ("header:x-powered-by", r"PHP",            "PHP"),
    ("header:x-powered-by", r"Express",        "Express.js"),
    ("header:x-powered-by", r"Next\.js",       "Next.js"),
    ("header:x-amz-cf-id", r".*",              "AWS CloudFront"),
    ("header:x-amz-request-id", r".*",         "AWS"),
    ("header:x-cache",     r"cloudfront",      "AWS CloudFront"),
    ("header:x-fastly-request-id", r".*",      "Fastly CDN"),
    ("header:via",         r"varnish",         "Varnish Cache"),
    ("header:x-drupal-cache", r".*",           "Drupal"),
    ("header:x-wp-total",  r".*",              "WordPress"),
    ("header:x-shopify-stage", r".*",          "Shopify"),
    ("header:set-cookie",  r"PHPSESSID",       "PHP"),
    ("header:set-cookie",  r"laravel_session", "Laravel"),
    ("header:set-cookie",  r"django",          "Django"),
    ("header:set-cookie",  r"JSESSIONID",      "Java/Tomcat"),
    ("header:cf-ray",      r".*",              "Cloudflare"),
    ("header:x-kong-proxy-latency", r".*",     "Kong API Gateway"),
    ("header:x-envoy-upstream-service-time", r".*", "Envoy Proxy"),
    ("header:x-istio-attributes", r".*",       "Istio Service Mesh"),
    ("header:server",      r"AmazonS3",        "AWS S3"),
    ("header:server",      r"awselb",          "AWS ELB"),
    ("header:x-amzn-requestid", r".*",         "AWS API Gateway"),
]

WAF_INDICATORS: list[tuple[str, str]] = [
    ("header:x-sucuri-id",         "Sucuri WAF"),
    ("header:x-fw-hash",           "Firewall"),
    ("header:x-waf-event-info",    "WAF"),
    ("header:x-akamai-edgescape",  "Akamai"),
    ("header:server", "cloudflare"),
    ("header:cf-ray", "Cloudflare WAF"),
    ("header:x-amzn-waf-action",   "AWS WAF"),
    ("header:x-azure-ref",         "Azure CDN/WAF"),
    ("header:x-imperva-id",        "Imperva WAF"),
    ("header:x-iinfo",             "Incapsula/Imperva"),
]

CDN_INDICATORS: dict[str, str] = {
    "cf-ray": "Cloudflare",
    "x-amz-cf-id": "AWS CloudFront",
    "x-fastly-request-id": "Fastly",
    "x-cache": "CDN",
    "x-akamai-transformed": "Akamai",
    "via": "CDN",
    "x-azure-ref": "Azure CDN",
}


class DNSEnricher:
    """Resolves hostnames to IPs and fetches DNS record metadata."""

    def enrich(self, hostname: str) -> dict:
        """Return dict with resolved IPs and DNS info."""
        result: dict = {"hostname": hostname, "ipv4": [], "ipv6": [], "cname": None}
        try:
            # A records
            try:
                infos = socket.getaddrinfo(hostname, None, socket.AF_INET)
                result["ipv4"] = list({i[4][0] for i in infos})
            except socket.gaierror:
                pass

            # AAAA records
            try:
                infos = socket.getaddrinfo(hostname, None, socket.AF_INET6)
                result["ipv6"] = list({i[4][0] for i in infos})
            except socket.gaierror:
                pass

            # CNAME via canonical name resolution
            try:
                result["cname"] = socket.getfqdn(hostname)
                if result["cname"] == hostname:
                    result["cname"] = None
            except Exception:
                pass

            # PTR (reverse DNS for first IP)
            if result["ipv4"]:
                try:
                    result["ptr"] = socket.gethostbyaddr(result["ipv4"][0])[0]
                except Exception:
                    result["ptr"] = None

        except Exception as exc:
            logger.warning("DNS enrichment failed for %s: %s", hostname, exc)

        return result


class HTTPEnricher:
    """Fetches HTTP/HTTPS metadata and fingerprints technologies."""

    def __init__(self):
        self.config = get_config()
        self._session = requests.Session()
        self._session.headers["User-Agent"] = self.config.http_user_agent
        self._session.max_redirects = 5

    def enrich_http(self, hostname: str) -> Optional[HTTPInfo]:
        return self._fetch(f"http://{hostname}")

    def enrich_https(self, hostname: str) -> Optional[HTTPInfo]:
        return self._fetch(f"https://{hostname}", verify_tls=True)

    def _fetch(self, url: str, verify_tls: bool = False) -> Optional[HTTPInfo]:
        start = time.time()
        try:
            resp = self._session.get(
                url,
                timeout=self.config.scan_timeout_s,
                verify=verify_tls,
                allow_redirects=True,
            )
        except RequestException as exc:
            logger.debug("HTTP fetch failed for %s: %s", url, exc)
            return None

        elapsed = (time.time() - start) * 1000
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        info = HTTPInfo(
            status_code=resp.status_code,
            server=headers_lower.get("server", ""),
            headers=dict(resp.headers),
            redirect_chain=[r.url for r in resp.history] + [resp.url],
            response_time_ms=elapsed,
            content_type=headers_lower.get("content-type", ""),
        )

        info.technologies = self._fingerprint_technologies(headers_lower, resp.text)
        info.waf_detected, info.cdn_detected, info.cdn_provider = \
            self._detect_waf_cdn(headers_lower)

        return info

    def _fingerprint_technologies(self, headers: dict, body: str) -> list[str]:
        techs: set[str] = set()
        for source, pattern, tech_name in TECH_SIGNATURES:
            if source.startswith("header:"):
                header_key = source[7:]
                value = headers.get(header_key, "")
                if value and re.search(pattern, value, re.IGNORECASE):
                    techs.add(tech_name)
        return sorted(techs)

    def _detect_waf_cdn(self, headers: dict) -> tuple[bool, bool, str]:
        waf = False
        cdn = False
        cdn_name = ""

        for source, indicator in WAF_INDICATORS:
            if source.startswith("header:"):
                key = source[7:]
                if key in headers:
                    waf = True
                    break

        for header_key, name in CDN_INDICATORS.items():
            if header_key in headers:
                cdn = True
                cdn_name = name
                break

        return waf, cdn, cdn_name
