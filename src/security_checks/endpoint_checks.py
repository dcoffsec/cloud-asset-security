"""
Endpoint exposure checks — probes for sensitive paths and dangerous HTTP methods.
"""
import logging
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urljoin

import requests
from requests.exceptions import RequestException

from ..config import get_config
from ..models import Asset, AssetMetadata, RiskLevel, SecurityFinding

logger = logging.getLogger(__name__)


@dataclass
class SensitivePath:
    path: str
    title: str
    risk_level: RiskLevel
    category: str
    description: str
    check_id: str


# Ordered by risk — CRITICAL paths first
SENSITIVE_PATHS: list[SensitivePath] = [
    # API documentation
    SensitivePath("/swagger-ui.html",    "Swagger UI Exposed",         RiskLevel.HIGH,   "API Exposure", "Swagger UI reveals full API schema, parameters, and may allow unauthenticated API testing.", "ENDPOINT-SWAGGER_UI"),
    SensitivePath("/swagger-ui/",        "Swagger UI Exposed",         RiskLevel.HIGH,   "API Exposure", "Swagger UI reveals full API schema.", "ENDPOINT-SWAGGER_UI_ALT"),
    SensitivePath("/api-docs",           "OpenAPI Spec Exposed",       RiskLevel.HIGH,   "API Exposure", "Raw OpenAPI/Swagger JSON spec exposed — reveals all endpoints, schemas, and auth methods.", "ENDPOINT-API_DOCS"),
    SensitivePath("/openapi.json",       "OpenAPI JSON Exposed",       RiskLevel.HIGH,   "API Exposure", "OpenAPI specification file exposed.", "ENDPOINT-OPENAPI_JSON"),
    SensitivePath("/openapi.yaml",       "OpenAPI YAML Exposed",       RiskLevel.HIGH,   "API Exposure", "OpenAPI specification file exposed.", "ENDPOINT-OPENAPI_YAML"),
    SensitivePath("/graphql",            "GraphQL Endpoint Exposed",   RiskLevel.MEDIUM, "API Exposure", "GraphQL endpoint may allow schema introspection, revealing full data model.", "ENDPOINT-GRAPHQL"),
    SensitivePath("/graphiql",           "GraphiQL IDE Exposed",       RiskLevel.HIGH,   "API Exposure", "GraphiQL IDE should not be accessible in production — enables arbitrary query execution.", "ENDPOINT-GRAPHIQL"),

    # Admin panels
    SensitivePath("/admin",              "Admin Panel Exposed",        RiskLevel.CRITICAL, "Admin Access", "Admin panel is internet-accessible — should be restricted to internal networks or VPN.", "ENDPOINT-ADMIN"),
    SensitivePath("/admin/",             "Admin Panel Exposed",        RiskLevel.CRITICAL, "Admin Access", "Admin panel is internet-accessible.", "ENDPOINT-ADMIN_SLASH"),
    SensitivePath("/wp-admin/",          "WordPress Admin Exposed",    RiskLevel.HIGH,   "Admin Access", "WordPress admin panel exposed to the internet.", "ENDPOINT-WP_ADMIN"),
    SensitivePath("/wp-login.php",       "WordPress Login Exposed",    RiskLevel.MEDIUM, "Admin Access", "WordPress login page accessible — target for brute force attacks.", "ENDPOINT-WP_LOGIN"),
    SensitivePath("/manager/html",       "Tomcat Manager Exposed",     RiskLevel.CRITICAL, "Admin Access", "Apache Tomcat manager is internet-accessible — critical RCE risk if default creds are in use.", "ENDPOINT-TOMCAT_MANAGER"),
    SensitivePath("/phpmyadmin",         "phpMyAdmin Exposed",         RiskLevel.CRITICAL, "Admin Access", "phpMyAdmin database admin panel exposed to the internet.", "ENDPOINT-PHPMYADMIN"),
    SensitivePath("/phpmyadmin/",        "phpMyAdmin Exposed",         RiskLevel.CRITICAL, "Admin Access", "phpMyAdmin database admin panel exposed.", "ENDPOINT-PHPMYADMIN_SLASH"),
    SensitivePath("/.env",               ".env File Exposed",          RiskLevel.CRITICAL, "Secrets Exposure", ".env file may contain database credentials, API keys, and other secrets.", "ENDPOINT-ENV_FILE"),
    SensitivePath("/.git/config",        "Git Repository Exposed",     RiskLevel.CRITICAL, "Source Code", "Git config file accessible — source code and credentials may be extractable.", "ENDPOINT-GIT_CONFIG"),
    SensitivePath("/.git/HEAD",          "Git Repository Exposed",     RiskLevel.CRITICAL, "Source Code", "Git HEAD file accessible — git repository may be downloadable.", "ENDPOINT-GIT_HEAD"),

    # Monitoring / debugging
    SensitivePath("/actuator",           "Spring Actuator Exposed",    RiskLevel.HIGH,   "Monitoring",   "Spring Boot Actuator endpoints may expose heap dumps, env vars, and allow remote shutdown.", "ENDPOINT-ACTUATOR"),
    SensitivePath("/actuator/env",       "Spring Actuator Env Exposed",RiskLevel.CRITICAL,"Monitoring",  "Spring Actuator /env exposes all environment variables including secrets.", "ENDPOINT-ACTUATOR_ENV"),
    SensitivePath("/actuator/heapdump",  "Heap Dump Endpoint Exposed", RiskLevel.CRITICAL,"Monitoring",  "Heap dump endpoint can expose in-memory secrets and session tokens.", "ENDPOINT-HEAPDUMP"),
    SensitivePath("/metrics",            "Metrics Endpoint Exposed",   RiskLevel.MEDIUM, "Monitoring",   "Prometheus/application metrics exposed — reveals infrastructure details.", "ENDPOINT-METRICS"),
    SensitivePath("/health",             "Health Check Exposed",       RiskLevel.LOW,    "Monitoring",   "Health endpoint exposed — reveals service dependencies and versions.", "ENDPOINT-HEALTH"),
    SensitivePath("/debug/pprof/",       "Go pprof Profiler Exposed",  RiskLevel.HIGH,   "Monitoring",   "Go pprof endpoint enables CPU/memory profiling and goroutine inspection.", "ENDPOINT-PPROF"),
    SensitivePath("/__debug/",           "Debug Endpoint Exposed",     RiskLevel.HIGH,   "Monitoring",   "Debug interface accessible in production.", "ENDPOINT-DEBUG"),
    SensitivePath("/console",            "Console Interface Exposed",  RiskLevel.CRITICAL,"Admin Access", "Console/REPL interface exposed — may allow arbitrary code execution.", "ENDPOINT-CONSOLE"),

    # Config / info files
    SensitivePath("/server-status",      "Apache Server Status Exposed",RiskLevel.MEDIUM, "Info Disclosure","Apache mod_status reveals active connections, worker states, and request details.", "ENDPOINT-SERVER_STATUS"),
    SensitivePath("/nginx_status",       "Nginx Status Exposed",       RiskLevel.LOW,    "Info Disclosure","Nginx stub_status reveals connection counts.", "ENDPOINT-NGINX_STATUS"),
    SensitivePath("/robots.txt",         "Robots.txt Exists",          RiskLevel.INFO,   "Info Disclosure","robots.txt may reveal hidden paths — review for sensitive endpoint disclosures.", "ENDPOINT-ROBOTS_TXT"),
    SensitivePath("/sitemap.xml",        "Sitemap Exists",             RiskLevel.INFO,   "Info Disclosure","Sitemap reveals site structure.", "ENDPOINT-SITEMAP"),
    SensitivePath("/config.json",        "Config File Exposed",        RiskLevel.HIGH,   "Secrets Exposure","config.json may contain credentials, API endpoints, or feature flags.", "ENDPOINT-CONFIG_JSON"),
    SensitivePath("/credentials.json",   "Credentials File Exposed",   RiskLevel.CRITICAL,"Secrets Exposure","credentials.json may contain plaintext credentials.", "ENDPOINT-CREDENTIALS"),

    # Kubernetes / cloud metadata
    SensitivePath("/v1/",                "Kubernetes API Exposed?",    RiskLevel.HIGH,   "Cloud Exposure","Path pattern matches Kubernetes API — verify if k8s API is internet-accessible.", "ENDPOINT-K8S_API"),
]

DANGEROUS_HTTP_METHODS = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]


def run_endpoint_checks(asset: Asset, metadata: AssetMetadata) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    config = get_config()

    # Determine base URL
    if metadata.https_info and metadata.https_info.status_code < 500:
        base_url = f"https://{asset.hostname}"
    elif metadata.http_info:
        base_url = f"http://{asset.hostname}"
    else:
        return findings

    session = requests.Session()
    session.headers["User-Agent"] = config.http_user_agent

    seen_check_ids: set[str] = set()

    for sp in SENSITIVE_PATHS:
        if sp.check_id in seen_check_ids:
            continue

        url = urljoin(base_url, sp.path)
        status = _probe_path(session, url, config.scan_timeout_s)

        if status is not None and _is_interesting_status(status):
            seen_check_ids.add(sp.check_id)
            findings.append(SecurityFinding(
                check_id=sp.check_id,
                title=sp.title,
                description=sp.description,
                risk_level=sp.risk_level,
                category=sp.category,
                evidence={"url": url, "status_code": status},
                remediation=_get_remediation(sp),
                cwe_id="CWE-200",
            ))

    # --- Dangerous HTTP methods ---
    allowed_methods = _probe_http_methods(session, base_url, config.scan_timeout_s)
    dangerous = [m for m in allowed_methods if m in DANGEROUS_HTTP_METHODS]
    if dangerous:
        findings.append(SecurityFinding(
            check_id="ENDPOINT-DANGEROUS_HTTP_METHODS",
            title=f"Dangerous HTTP Methods Allowed: {', '.join(dangerous)}",
            description=f"The server allows HTTP methods that may not be needed: "
                        f"{', '.join(dangerous)}. TRACE can enable XST attacks. "
                        f"PUT/DELETE without auth can allow file manipulation.",
            risk_level=RiskLevel.MEDIUM,
            category="HTTP Configuration",
            evidence={"allowed_methods": allowed_methods, "dangerous": dangerous},
            remediation="Restrict HTTP methods to only GET, POST (and HEAD, OPTIONS) "
                        "unless specifically required. Disable TRACE globally.",
            cwe_id="CWE-16",
        ))

    return findings


def _probe_path(session: requests.Session, url: str, timeout: int) -> Optional[int]:
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True, verify=False)
        return resp.status_code
    except RequestException:
        return None


def _is_interesting_status(status: int) -> bool:
    """A 200, 401, 403 all indicate the path exists."""
    return status in {200, 201, 204, 206, 301, 302, 307, 308, 401, 403, 405}


def _probe_http_methods(session: requests.Session, url: str, timeout: int) -> list[str]:
    """Send OPTIONS request to enumerate allowed methods."""
    try:
        resp = session.options(url, timeout=timeout, verify=False)
        allow_header = resp.headers.get("Allow", "")
        if allow_header:
            return [m.strip() for m in allow_header.split(",") if m.strip()]
    except RequestException:
        pass
    return []


def _get_remediation(sp: SensitivePath) -> str:
    remediations = {
        "API Exposure": "Require authentication before serving API documentation. "
                        "In production, disable Swagger/GraphiQL UIs or restrict to internal IPs.",
        "Admin Access": "Restrict admin interfaces to internal networks or VPN using security groups, "
                        "NACLs, or ALB IP-based rules. Never expose admin panels to the internet.",
        "Secrets Exposure": "Remove sensitive files from the web root immediately. "
                            "Rotate any credentials that may have been exposed. "
                            "Add these paths to .gitignore and server deny rules.",
        "Source Code": "Block access to .git directories at the web server level. "
                       "Audit git history for committed secrets and rotate them.",
        "Monitoring": "Place monitoring endpoints behind authentication or restrict "
                      "to internal networks only.",
        "Info Disclosure": "Review file content for sensitive path disclosures. "
                           "Remove or restrict access if not needed publicly.",
        "Cloud Exposure": "Verify this service is not the raw Kubernetes API. "
                          "Ensure k8s API servers are not internet-accessible.",
        "HTTP Configuration": "Configure your web server to restrict HTTP methods.",
    }
    return remediations.get(sp.category, "Restrict access to this endpoint.")
