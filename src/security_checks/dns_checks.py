"""
DNS security checks — subdomain takeover detection, dangling CNAMEs, and DNS misconfiguration.
"""
import re

from ..models import Asset, AssetMetadata, RiskLevel, SecurityFinding

# Service CNAME patterns → (service_name, takeover_fingerprints)
# If a CNAME points to one of these services but returns a "not found" page,
# the subdomain may be vulnerable to takeover.
TAKEOVER_FINGERPRINTS: list[tuple[str, list[str]]] = [
    ("AWS S3",           ["NoSuchBucket", "The specified bucket does not exist"]),
    ("AWS Elastic Beanstalk", ["there is no application called"]),
    ("GitHub Pages",     ["There isn't a GitHub Pages site here",
                          "For root URLs (like http://example.com/) you must provide an index.html"]),
    ("Heroku",           ["No such app", "herokucdn.com/error-pages/no-such-app"]),
    ("Netlify",          ["Not Found - Request ID"]),
    ("Vercel",           ["The deployment could not be found on Vercel",
                          "404: NOT_FOUND"]),
    ("Fastly",           ["Fastly error: unknown domain"]),
    ("Shopify",          ["Sorry, this shop is currently unavailable"]),
    ("Tumblr",           ["Whatever you were looking for doesn't currently exist"]),
    ("WordPress",        ["Do you want to register"]),
    ("Azure",            ["ErrorDocument to handle 404 errors", "The resource you are looking for has been removed"]),
    ("Surge.sh",         ["project not found"]),
    ("ReadTheDocs",      ["unknown to Read the Docs"]),
    ("Zendesk",          ["Help Center Closed"]),
    ("HubSpot",          ["Domain is not configured"]),
    ("Ghost",            ["The thing you were looking for is no longer here"]),
    ("Strikingly",       ["page not found on Strikingly"]),
]

# CNAME target patterns that suggest dangling records
CLOUD_CNAME_PATTERNS = [
    (r"\.s3\.amazonaws\.com$",           "AWS S3"),
    (r"\.s3-website.*\.amazonaws\.com$", "AWS S3 Website"),
    (r"\.elasticbeanstalk\.com$",        "AWS Elastic Beanstalk"),
    (r"\.execute-api\..*\.amazonaws\.com$", "AWS API Gateway"),
    (r"\.cloudfront\.net$",              "AWS CloudFront"),
    (r"\.azurewebsites\.net$",           "Azure Web Apps"),
    (r"\.azureedge\.net$",               "Azure CDN"),
    (r"\.github\.io$",                   "GitHub Pages"),
    (r"\.netlify\.app$",                  "Netlify"),
    (r"\.vercel\.app$",                   "Vercel"),
    (r"\.herokuapp\.com$",               "Heroku"),
    (r"\.surge\.sh$",                     "Surge.sh"),
    (r"\.readthedocs\.io$",              "ReadTheDocs"),
    (r"\.myshopify\.com$",              "Shopify"),
]


def run_dns_checks(asset: Asset, metadata: AssetMetadata) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []

    dns = metadata.dns_records
    if not dns:
        return findings

    cname = dns.get("cname")
    hostname = asset.hostname

    # --- Subdomain takeover via dangling CNAME ---
    if cname and cname != hostname:
        cloud_service = _detect_cloud_cname(cname)
        if cloud_service:
            # Check if the target actually resolves / returns content
            takeover_evidence = _check_takeover_fingerprint(metadata)
            if takeover_evidence:
                findings.append(SecurityFinding(
                    check_id="DNS-SUBDOMAIN_TAKEOVER",
                    title=f"Potential Subdomain Takeover via {cloud_service} CNAME",
                    description=f"'{hostname}' has a CNAME pointing to '{cname}' ({cloud_service}), "
                                f"but the target resource appears to be unclaimed. "
                                f"An attacker could register this {cloud_service} resource "
                                f"and serve malicious content from your domain.",
                    risk_level=RiskLevel.CRITICAL,
                    category="Subdomain Takeover",
                    evidence={
                        "hostname": hostname,
                        "cname_target": cname,
                        "cloud_service": cloud_service,
                        "takeover_indicator": takeover_evidence,
                    },
                    remediation=f"1. Remove the dangling DNS record for '{hostname}'. "
                                f"2. If the {cloud_service} resource should exist, re-create and re-claim it. "
                                f"3. Implement a DNS audit process to detect dangling records proactively.",
                    cwe_id="CWE-350",
                    references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover"],
                ))
            else:
                # CNAME to cloud but no takeover fingerprint — flag as review
                findings.append(SecurityFinding(
                    check_id="DNS-CLOUD_CNAME_REVIEW",
                    title=f"CNAME Points to {cloud_service} — Verify Ownership",
                    description=f"'{hostname}' resolves via CNAME to '{cname}' ({cloud_service}). "
                                f"Verify that this cloud resource is still claimed by your organization. "
                                f"Dangling records become takeover vulnerabilities if the resource is deleted.",
                    risk_level=RiskLevel.LOW,
                    category="DNS Configuration",
                    evidence={"cname_target": cname, "cloud_service": cloud_service},
                    remediation="Audit cloud resource ownership. Document and monitor all cloud CNAMEs.",
                    cwe_id="CWE-350",
                ))

    # --- Missing DNS records ---
    ipv4 = dns.get("ipv4", [])
    ipv6 = dns.get("ipv6", [])
    if not ipv4 and not ipv6 and not cname:
        findings.append(SecurityFinding(
            check_id="DNS-NO_RESOLUTION",
            title="Hostname Does Not Resolve",
            description=f"'{hostname}' has no A, AAAA, or CNAME records. "
                        f"This may indicate a stale DNS entry or a recently deleted resource. "
                        f"Stale DNS entries can be claimed by attackers.",
            risk_level=RiskLevel.MEDIUM,
            category="DNS Configuration",
            evidence={"hostname": hostname, "dns_records": dns},
            remediation="Remove stale DNS records. Implement a DNS lifecycle policy "
                        "that removes records when cloud resources are decommissioned.",
            cwe_id="CWE-350",
        ))

    # --- Missing ownership tags ---
    if not asset.owner or asset.owner == "unknown":
        findings.append(SecurityFinding(
            check_id="GOVERNANCE-MISSING_OWNER_TAG",
            title="Asset Has No Owner Tag",
            description=f"The asset '{hostname}' has no 'Owner' tag. "
                        f"Without ownership metadata, security incidents cannot be escalated "
                        f"and the asset may become abandoned/forgotten.",
            risk_level=RiskLevel.MEDIUM,
            category="Governance",
            evidence={"tags": asset.tags, "hostname": hostname},
            remediation="Enforce mandatory tagging via AWS Config rule 'required-tags' or "
                        "AWS Organizations SCP. Required tags: Owner, Team, Environment.",
            cwe_id="CWE-200",
        ))

    if not asset.environment or asset.environment == "unknown":
        findings.append(SecurityFinding(
            check_id="GOVERNANCE-MISSING_ENV_TAG",
            title="Asset Has No Environment Tag",
            description=f"No 'Environment' tag on '{hostname}'. "
                        f"Without environment classification, security controls cannot be "
                        f"applied proportionally (prod vs staging vs dev).",
            risk_level=RiskLevel.LOW,
            category="Governance",
            evidence={"tags": asset.tags},
            remediation="Tag all assets with Environment: production|staging|development.",
            cwe_id="CWE-200",
        ))

    return findings


def _detect_cloud_cname(cname: str) -> str | None:
    """Return the cloud service name if the CNAME matches a known cloud pattern."""
    for pattern, service in CLOUD_CNAME_PATTERNS:
        if re.search(pattern, cname, re.IGNORECASE):
            return service
    return None


def _check_takeover_fingerprint(metadata: AssetMetadata) -> str | None:
    """
    Check HTTP response body for known takeover fingerprints.
    Returns the fingerprint string if found, else None.
    """
    # We'd need the raw response body here — for this prototype we check
    # status code heuristics: a 404 from a cloud CNAME target is a strong signal.
    http = metadata.https_info or metadata.http_info
    if http and http.status_code == 404:
        return f"HTTP 404 from CNAME target (potential unclaimed resource)"
    return None
