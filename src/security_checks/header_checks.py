"""
Security header checks — validates presence and correctness of HTTP security headers.
"""
from ..models import AssetMetadata, RiskLevel, SecurityFinding


# (header_name, expected_pattern_or_None, risk_if_missing, title, remediation, cwe)
REQUIRED_HEADERS = [
    (
        "strict-transport-security",
        "max-age",
        RiskLevel.HIGH,
        "Missing HTTP Strict Transport Security (HSTS)",
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' response header.",
        "CWE-319",
    ),
    (
        "x-content-type-options",
        "nosniff",
        RiskLevel.MEDIUM,
        "Missing X-Content-Type-Options Header",
        "Add 'X-Content-Type-Options: nosniff' to prevent MIME-type sniffing attacks.",
        "CWE-116",
    ),
    (
        "x-frame-options",
        None,
        RiskLevel.MEDIUM,
        "Missing X-Frame-Options Header",
        "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking attacks.",
        "CWE-1021",
    ),
    (
        "content-security-policy",
        None,
        RiskLevel.MEDIUM,
        "Missing Content-Security-Policy Header",
        "Implement a Content-Security-Policy header to mitigate XSS and data injection attacks.",
        "CWE-358",
    ),
    (
        "referrer-policy",
        None,
        RiskLevel.LOW,
        "Missing Referrer-Policy Header",
        "Add 'Referrer-Policy: strict-origin-when-cross-origin' to control referrer information.",
        "CWE-200",
    ),
    (
        "permissions-policy",
        None,
        RiskLevel.LOW,
        "Missing Permissions-Policy Header",
        "Add Permissions-Policy header to restrict access to browser features.",
        "CWE-284",
    ),
]

DANGEROUS_HEADERS = [
    (
        "x-powered-by",
        RiskLevel.LOW,
        "Server Technology Disclosed via X-Powered-By",
        "Remove the X-Powered-By header to prevent technology stack fingerprinting.",
        "CWE-200",
    ),
    (
        "server",
        RiskLevel.LOW,
        "Verbose Server Header Exposes Version Information",
        "Configure the server to return a generic or empty Server header.",
        "CWE-200",
    ),
    (
        "x-aspnet-version",
        RiskLevel.LOW,
        "ASP.NET Version Disclosed",
        "Set <httpRuntime enableVersionHeader='false' /> in web.config.",
        "CWE-200",
    ),
    (
        "x-aspnetmvc-version",
        RiskLevel.LOW,
        "ASP.NET MVC Version Disclosed",
        "Disable version headers in Global.asax: MvcHandler.DisableMvcResponseHeader = true.",
        "CWE-200",
    ),
]

WEAK_CSP_PATTERNS = [
    ("unsafe-inline", "CSP allows 'unsafe-inline' scripts — negates XSS protection"),
    ("unsafe-eval",   "CSP allows 'unsafe-eval' — enables code injection via eval()"),
    ("*",             "CSP uses wildcard '*' source — allows content from any origin"),
    ("data:",         "CSP allows 'data:' URIs — can be abused for XSS"),
]


def run_header_checks(metadata: AssetMetadata) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []

    http_info = metadata.https_info or metadata.http_info
    if not http_info:
        return findings

    headers_lower = {k.lower(): v for k, v in http_info.headers.items()}

    # --- Required security headers ---
    for header_name, expected, risk, title, remediation, cwe in REQUIRED_HEADERS:
        value = headers_lower.get(header_name, "")
        if not value:
            findings.append(SecurityFinding(
                check_id=f"HDR-{header_name.upper().replace('-', '_')}_MISSING",
                title=title,
                description=f"The '{header_name}' header is absent from HTTP responses.",
                risk_level=risk,
                category="Security Headers",
                evidence={"header": header_name, "status_code": http_info.status_code},
                remediation=remediation,
                cwe_id=cwe,
            ))
        elif expected and expected not in value.lower():
            findings.append(SecurityFinding(
                check_id=f"HDR-{header_name.upper().replace('-', '_')}_MISCONFIGURED",
                title=f"Misconfigured {header_name} Header",
                description=f"'{header_name}' is present but may be misconfigured. "
                            f"Expected to contain '{expected}'. Got: '{value}'",
                risk_level=RiskLevel.LOW,
                category="Security Headers",
                evidence={"header": header_name, "value": value},
                remediation=remediation,
                cwe_id=cwe,
            ))

    # --- HSTS specifics ---
    hsts = headers_lower.get("strict-transport-security", "")
    if hsts:
        try:
            max_age_part = next(
                p for p in hsts.split(";") if "max-age" in p.lower()
            )
            max_age = int(max_age_part.strip().split("=")[1])
            if max_age < 31536000:
                findings.append(SecurityFinding(
                    check_id="HDR-HSTS_SHORT_MAX_AGE",
                    title="HSTS max-age Is Too Short",
                    description=f"HSTS max-age is {max_age}s (< 1 year). "
                                f"Browsers may not cache the policy long enough.",
                    risk_level=RiskLevel.LOW,
                    category="Security Headers",
                    evidence={"hsts_value": hsts, "max_age": max_age},
                    remediation="Set max-age to at least 31536000 (1 year).",
                    cwe_id="CWE-319",
                ))
        except (StopIteration, ValueError, IndexError):
            pass

    # --- CSP quality ---
    csp = headers_lower.get("content-security-policy", "")
    if csp:
        for pattern, desc in WEAK_CSP_PATTERNS:
            if pattern in csp:
                findings.append(SecurityFinding(
                    check_id=f"HDR-CSP_WEAK_{pattern.upper().replace('-','_').replace('*','WILDCARD')}",
                    title=f"Weak Content-Security-Policy: {desc.split('—')[0].strip()}",
                    description=desc,
                    risk_level=RiskLevel.MEDIUM,
                    category="Security Headers",
                    evidence={"csp_value": csp[:200], "pattern": pattern},
                    remediation="Tighten the CSP policy to avoid permissive directives.",
                    cwe_id="CWE-358",
                ))

    # --- Information disclosure headers ---
    for header_name, risk, title, remediation, cwe in DANGEROUS_HEADERS:
        value = headers_lower.get(header_name, "")
        if value:
            # Flag server headers that include version numbers
            if header_name == "server" and not any(c.isdigit() for c in value):
                continue  # Generic "nginx" without version is acceptable
            findings.append(SecurityFinding(
                check_id=f"HDR-{header_name.upper().replace('-', '_')}_DISCLOSED",
                title=title,
                description=f"Response header '{header_name}' reveals: '{value}'",
                risk_level=risk,
                category="Information Disclosure",
                evidence={"header": header_name, "value": value},
                remediation=remediation,
                cwe_id=cwe,
            ))

    # --- Missing WAF ---
    if not http_info.waf_detected:
        findings.append(SecurityFinding(
            check_id="HDR-NO_WAF_DETECTED",
            title="No Web Application Firewall Detected",
            description="No WAF or CDN-based protection signals were found in response headers. "
                        "Internet-facing applications should be protected by a WAF.",
            risk_level=RiskLevel.MEDIUM,
            category="Defence in Depth",
            evidence={"headers_checked": list(headers_lower.keys())},
            remediation="Deploy AWS WAF, Cloudflare, or similar WAF in front of this asset.",
            cwe_id="CWE-693",
        ))

    # --- CORS misconfiguration ---
    acao = headers_lower.get("access-control-allow-origin", "")
    acac = headers_lower.get("access-control-allow-credentials", "")
    if acao == "*" and acac.lower() == "true":
        findings.append(SecurityFinding(
            check_id="HDR-CORS_WILDCARD_WITH_CREDENTIALS",
            title="Dangerous CORS Misconfiguration: Wildcard + Credentials",
            description="Access-Control-Allow-Origin: * combined with "
                        "Access-Control-Allow-Credentials: true is invalid per spec "
                        "but some frameworks implement it incorrectly, enabling credential theft.",
            risk_level=RiskLevel.HIGH,
            category="CORS",
            evidence={"acao": acao, "acac": acac},
            remediation="Specify explicit allowed origins instead of wildcard when using credentials.",
            cwe_id="CWE-942",
            references=["https://owasp.org/www-project-web-security-testing-guide/"],
        ))
    elif acao == "*":
        findings.append(SecurityFinding(
            check_id="HDR-CORS_WILDCARD_ORIGIN",
            title="CORS Wildcard Origin Allows Any Domain",
            description="Access-Control-Allow-Origin: * permits any website to read responses. "
                        "Acceptable for public APIs but dangerous for authenticated endpoints.",
            risk_level=RiskLevel.LOW,
            category="CORS",
            evidence={"acao": acao},
            remediation="Restrict CORS to known trusted origins.",
            cwe_id="CWE-942",
        ))

    return findings
