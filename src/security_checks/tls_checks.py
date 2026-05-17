"""
TLS/SSL security checks — validates certificate and protocol configuration.
"""
from ..models import AssetMetadata, RiskLevel, SecurityFinding


def run_tls_checks(metadata: AssetMetadata) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    tls = metadata.tls_info

    # --- No TLS at all ---
    if not tls and metadata.http_info and not metadata.https_info:
        findings.append(SecurityFinding(
            check_id="TLS-NO_HTTPS",
            title="No HTTPS / TLS Detected",
            description="The asset does not appear to serve traffic over HTTPS. "
                        "All HTTP traffic is transmitted in cleartext.",
            risk_level=RiskLevel.CRITICAL,
            category="TLS/SSL",
            evidence={},
            remediation="Obtain a TLS certificate (e.g., via AWS Certificate Manager or Let's Encrypt) "
                        "and configure HTTPS. Redirect all HTTP traffic to HTTPS.",
            cwe_id="CWE-319",
            references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"],
        ))
        return findings

    if not tls:
        return findings

    # --- Expired certificate ---
    if tls.is_expired:
        findings.append(SecurityFinding(
            check_id="TLS-CERT_EXPIRED",
            title="TLS Certificate Is Expired",
            description=f"The TLS certificate expired on {tls.valid_to}. "
                        f"Browsers will display a security warning and block access.",
            risk_level=RiskLevel.CRITICAL,
            category="TLS/SSL",
            evidence={"valid_to": str(tls.valid_to), "issuer": tls.issuer},
            remediation="Renew the certificate immediately. "
                        "Enable auto-renewal via ACM or certbot to prevent future expiry.",
            cwe_id="CWE-298",
        ))

    # --- Near-expiry certificate ---
    elif 0 < tls.days_to_expiry <= 30:
        risk = RiskLevel.HIGH if tls.days_to_expiry <= 14 else RiskLevel.MEDIUM
        findings.append(SecurityFinding(
            check_id="TLS-CERT_EXPIRING_SOON",
            title=f"TLS Certificate Expiring in {tls.days_to_expiry} Days",
            description=f"The certificate will expire on {tls.valid_to}. "
                        f"Plan immediate renewal to avoid service disruption.",
            risk_level=risk,
            category="TLS/SSL",
            evidence={"days_to_expiry": tls.days_to_expiry, "valid_to": str(tls.valid_to)},
            remediation="Renew the certificate. Enable automatic renewal in ACM or certbot.",
            cwe_id="CWE-298",
        ))

    # --- Self-signed certificate ---
    if tls.is_self_signed:
        findings.append(SecurityFinding(
            check_id="TLS-SELF_SIGNED_CERT",
            title="Self-Signed TLS Certificate Detected",
            description="The server is using a self-signed certificate. "
                        "This prevents browsers from validating authenticity and "
                        "is a common sign of misconfigured or developer-facing infrastructure "
                        "inadvertently exposed to the internet.",
            risk_level=RiskLevel.HIGH,
            category="TLS/SSL",
            evidence={"issuer": tls.issuer, "subject": tls.subject},
            remediation="Replace with a CA-signed certificate from ACM, Let's Encrypt, or a trusted CA.",
            cwe_id="CWE-295",
        ))

    # --- Weak/deprecated protocols ---
    weak_protocols = [p for p in tls.protocol_versions
                      if p in {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}]
    if weak_protocols:
        findings.append(SecurityFinding(
            check_id="TLS-WEAK_PROTOCOL",
            title=f"Deprecated TLS Protocol Supported: {', '.join(weak_protocols)}",
            description=f"The server accepts connections using deprecated protocols: "
                        f"{', '.join(weak_protocols)}. These protocols have known vulnerabilities "
                        f"(POODLE, BEAST, etc.) and fail PCI DSS compliance.",
            risk_level=RiskLevel.HIGH,
            category="TLS/SSL",
            evidence={"weak_protocols": weak_protocols},
            remediation="Disable TLS 1.0 and 1.1. Only allow TLS 1.2 and TLS 1.3.",
            cwe_id="CWE-326",
            references=["https://www.pcisecuritystandards.org/"],
        ))

    # --- Weak ciphers ---
    weak_cipher_keywords = ["RC4", "DES", "3DES", "EXPORT", "NULL", "ANON"]
    weak_ciphers = [c for c in tls.cipher_suites
                    if any(kw in c.upper() for kw in weak_cipher_keywords)]
    if weak_ciphers:
        findings.append(SecurityFinding(
            check_id="TLS-WEAK_CIPHERS",
            title="Weak TLS Cipher Suites Supported",
            description=f"Weak cipher suites detected: {', '.join(weak_ciphers)}. "
                        f"These ciphers provide insufficient encryption strength.",
            risk_level=RiskLevel.HIGH,
            category="TLS/SSL",
            evidence={"weak_ciphers": weak_ciphers, "all_ciphers": tls.cipher_suites},
            remediation="Configure the server to only allow strong cipher suites. "
                        "Use Mozilla SSL Configuration Generator for recommended configs.",
            cwe_id="CWE-327",
            references=["https://ssl-config.mozilla.org/"],
        ))

    # --- HTTP not redirecting to HTTPS ---
    if metadata.http_info and metadata.https_info:
        http_redirects = metadata.http_info.redirect_chain
        redirects_to_https = any(
            r.startswith("https://") for r in http_redirects[1:]
        ) if len(http_redirects) > 1 else False

        if not redirects_to_https and metadata.http_info.status_code == 200:
            findings.append(SecurityFinding(
                check_id="TLS-HTTP_NOT_REDIRECTED",
                title="HTTP Traffic Not Redirected to HTTPS",
                description="The server serves content over HTTP without redirecting to HTTPS. "
                            "This allows cleartext connections that can be intercepted.",
                risk_level=RiskLevel.HIGH,
                category="TLS/SSL",
                evidence={
                    "http_status": metadata.http_info.status_code,
                    "redirect_chain": metadata.http_info.redirect_chain,
                },
                remediation="Configure a 301 redirect from HTTP to HTTPS at the load balancer or web server.",
                cwe_id="CWE-319",
            ))

    return findings
