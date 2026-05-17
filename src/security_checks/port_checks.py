"""
Port and network security checks — evaluates open port exposure.
"""
from ..models import AssetMetadata, RiskLevel, SecurityFinding


# Port → (risk_level, title, description, remediation)
HIGH_RISK_PORT_RULES: dict[int, tuple[RiskLevel, str, str, str]] = {
    21: (
        RiskLevel.HIGH,
        "FTP Port Open (21) — Plaintext File Transfer",
        "FTP transmits data including credentials in cleartext. "
        "An internet-facing FTP port is a significant risk for credential theft and data interception.",
        "Replace FTP with SFTP (port 22) or FTPS. Restrict access to known IP ranges via security groups.",
    ),
    22: (
        RiskLevel.MEDIUM,
        "SSH Port Open (22) — Internet-Accessible",
        "SSH port is accessible from the internet. While SSH itself is encrypted, "
        "internet-facing SSH is targeted by automated brute-force and credential-stuffing attacks.",
        "Restrict SSH (port 22) to internal networks/VPN via security group rules. "
        "Use AWS Systems Manager Session Manager as a keyless alternative.",
    ),
    23: (
        RiskLevel.CRITICAL,
        "Telnet Port Open (23) — Plaintext Remote Access",
        "Telnet transmits all data including passwords in plaintext. "
        "This port should never be open on an internet-facing asset.",
        "Immediately close Telnet port. Replace with SSH.",
    ),
    3306: (
        RiskLevel.CRITICAL,
        "MySQL Port Open (3306) — Database Directly Exposed",
        "MySQL database port is directly accessible from the internet. "
        "This enables brute-force attacks, SQL injection directly to the DB layer, "
        "and potential full data exfiltration.",
        "Immediately restrict port 3306 to application subnet only using security groups. "
        "Databases must never be directly internet-accessible.",
    ),
    3389: (
        RiskLevel.CRITICAL,
        "RDP Port Open (3389) — Internet-Accessible Remote Desktop",
        "RDP is a frequent target for ransomware operators. "
        "Internet-facing RDP has led to numerous high-profile breaches.",
        "Immediately restrict RDP to internal networks/VPN. "
        "Use AWS Systems Manager or a jump host instead.",
    ),
    5432: (
        RiskLevel.CRITICAL,
        "PostgreSQL Port Open (5432) — Database Directly Exposed",
        "PostgreSQL database port is directly internet-accessible. "
        "Direct database exposure is a critical security violation.",
        "Restrict port 5432 to application subnet only. "
        "Databases must never be internet-accessible.",
    ),
    5900: (
        RiskLevel.CRITICAL,
        "VNC Port Open (5900) — Remote Desktop Exposed",
        "VNC remote desktop is accessible from the internet. "
        "VNC is often unauthenticated or weakly authenticated.",
        "Immediately close VNC port. Use SSH tunneling or AWS SSM for remote access.",
    ),
    6379: (
        RiskLevel.CRITICAL,
        "Redis Port Open (6379) — Unauthenticated Cache Exposed",
        "Redis is open to the internet. By default, Redis has no authentication. "
        "Internet-facing Redis has been exploited to drop cryptocurrency miners, "
        "exfiltrate data, and achieve code execution via config manipulation.",
        "Immediately restrict Redis port to the application subnet. "
        "Enable Redis AUTH (requirepass) and disable dangerous commands (CONFIG, SLAVEOF).",
    ),
    8080: (
        RiskLevel.LOW,
        "HTTP Alternate Port Open (8080)",
        "An alternate HTTP port is accessible. This is often a development server or "
        "proxy backend inadvertently exposed.",
        "Verify if this port is intentionally public. "
        "If it's a backend service, restrict it to the load balancer subnet.",
    ),
    8888: (
        RiskLevel.CRITICAL,
        "Jupyter Notebook Port Open (8888) — Unauthenticated Code Execution",
        "Port 8888 is commonly used by Jupyter Notebook, which allows arbitrary "
        "Python code execution. Internet-facing Jupyter is a critical RCE vulnerability.",
        "Immediately restrict port 8888. Jupyter should never be internet-accessible. "
        "Use SSH tunneling for local access.",
    ),
    9200: (
        RiskLevel.CRITICAL,
        "Elasticsearch HTTP Port Open (9200) — Unauthenticated Data Exposure",
        "Elasticsearch HTTP port is internet-accessible. "
        "Elasticsearch has no authentication by default in older versions, "
        "enabling full data exfiltration without credentials.",
        "Immediately restrict port 9200. Enable Elasticsearch security features "
        "(TLS + authentication). Never expose Elasticsearch directly to the internet.",
    ),
    11211: (
        RiskLevel.CRITICAL,
        "Memcached Port Open (11211) — Unauthenticated Cache Exposed",
        "Memcached is accessible from the internet with no authentication. "
        "This allows full cache read/write and has been used in amplification DDoS attacks.",
        "Immediately restrict port 11211 to the application subnet. "
        "Memcached must never be internet-accessible.",
    ),
    27017: (
        RiskLevel.CRITICAL,
        "MongoDB Port Open (27017) — Database Directly Exposed",
        "MongoDB is accessible from the internet. "
        "Internet-facing MongoDB (especially with auth disabled) has led to "
        "numerous large-scale data breaches and ransomware attacks.",
        "Immediately restrict port 27017. Enable MongoDB authentication and TLS. "
        "Databases must never be internet-accessible.",
    ),
    50000: (
        RiskLevel.HIGH,
        "Jenkins Port Open (50000) — CI/CD Agent Communication",
        "Jenkins agent communication port is internet-accessible. "
        "This can allow unauthorized agents to connect to the CI/CD master.",
        "Restrict port 50000 to internal build agent subnets only.",
    ),
}


def run_port_checks(metadata: AssetMetadata) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []

    if not metadata.port_scan:
        return findings

    scan = metadata.port_scan
    open_ports = set(scan.open_ports)

    for port, (risk, title, description, remediation) in HIGH_RISK_PORT_RULES.items():
        if port in open_ports:
            findings.append(SecurityFinding(
                check_id=f"PORT-{port}_OPEN",
                title=title,
                description=description,
                risk_level=risk,
                category="Network Exposure",
                evidence={
                    "port": port,
                    "service": scan.port_services.get(port, "unknown"),
                    "all_open_ports": sorted(open_ports),
                },
                remediation=remediation,
                cwe_id="CWE-284",
            ))

    # --- Broad port exposure warning ---
    high_risk_open = [p for p in open_ports
                      if p in HIGH_RISK_PORT_RULES and
                      HIGH_RISK_PORT_RULES[p][0] in (RiskLevel.CRITICAL, RiskLevel.HIGH)]

    if len(open_ports) > 5:
        findings.append(SecurityFinding(
            check_id="PORT-EXCESSIVE_EXPOSURE",
            title=f"Excessive Port Exposure: {len(open_ports)} Ports Open",
            description=f"The asset has {len(open_ports)} open ports: {sorted(open_ports)}. "
                        f"Internet-facing assets should expose the minimum necessary ports "
                        f"(principle of least privilege).",
            risk_level=RiskLevel.MEDIUM,
            category="Network Exposure",
            evidence={"open_ports": sorted(open_ports), "count": len(open_ports)},
            remediation="Audit all open ports. Close any not required for the asset's function. "
                        "Apply security group rules to restrict access to required ports only.",
            cwe_id="CWE-284",
        ))

    return findings
