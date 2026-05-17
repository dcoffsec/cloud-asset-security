"""
Lightweight port scanner — checks a targeted list of security-relevant ports.

Design: We do NOT perform broad nmap-style sweeps. We scan only the ports
relevant to internet-facing web asset security. This avoids noisy scans
and keeps the ephemeral worker runtime short.

For production: run inside an isolated Lambda/Job so the scanner's
IP is known and can be allow-listed in the asset's security group for
legitimate access.
"""
import logging
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..config import get_config
from ..models import PortScanResult

logger = logging.getLogger(__name__)

# Service name mapping for well-known ports
PORT_SERVICES: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    1433: "MSSQL",
    3000: "Node/Dev server",
    3306: "MySQL",
    3389: "RDP",
    4200: "Angular dev",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP-alt",
    8080: "HTTP-proxy",
    8443: "HTTPS-alt",
    8888: "Jupyter/HTTP",
    9000: "PHP-FPM/Portainer",
    9090: "Prometheus",
    9200: "Elasticsearch HTTP",
    9300: "Elasticsearch Transport",
    11211: "Memcached",
    27017: "MongoDB",
    50000: "Jenkins",
}

# Ports that are HIGH risk if open on an internet-facing asset
HIGH_RISK_PORTS: set[int] = {
    21, 22, 23, 3306, 3389, 5432, 5900, 6379, 8888, 9200, 11211, 27017, 50000
}


class PortScanner:
    """
    Scans a targeted set of ports on a host using parallel TCP connect probes.

    Security note: TCP connect scans are logged by the target host. This is
    intentional — we want our scan to be attributable as an internal security
    review, not stealthy like an attacker.
    """

    def __init__(self):
        self.config = get_config()
        self.target_ports = self.config.port_scan_targets

    def scan(self, hostname: str, ports: list[int] | None = None) -> PortScanResult:
        ports = ports or self.target_ports
        start = time.time()
        open_ports: list[int] = []
        port_services: dict[int, str] = {}

        # Parallel probes with a bounded thread pool
        with ThreadPoolExecutor(max_workers=20) as pool:
            futures = {
                pool.submit(self._probe, hostname, port): port
                for port in ports
            }
            for future in as_completed(futures):
                port = futures[future]
                try:
                    if future.result():
                        open_ports.append(port)
                        port_services[port] = PORT_SERVICES.get(port, "unknown")
                except Exception as exc:
                    logger.debug("Port probe error %s:%d — %s", hostname, port, exc)

        open_ports.sort()
        return PortScanResult(
            open_ports=open_ports,
            port_services=port_services,
            scan_time_s=time.time() - start,
        )

    def _probe(self, hostname: str, port: int) -> bool:
        """Returns True if the port accepts a TCP connection."""
        try:
            with socket.create_connection(
                (hostname, port),
                timeout=min(3, self.config.scan_timeout_s)
            ):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    @staticmethod
    def is_high_risk_port(port: int) -> bool:
        return port in HIGH_RISK_PORTS
