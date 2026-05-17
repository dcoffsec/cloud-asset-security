"""
TLS certificate enrichment — extracts certificate details and validates configuration.
"""
import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional

from ..config import get_config
from ..models import TLSInfo

logger = logging.getLogger(__name__)

# Weak/deprecated protocols
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

# Weak cipher patterns
WEAK_CIPHER_PATTERNS = [
    "RC4", "DES", "3DES", "EXPORT", "NULL", "ANON", "MD5",
]


class TLSEnricher:
    """Connects to a host and extracts TLS certificate and configuration details."""

    def __init__(self):
        self.config = get_config()

    def enrich(self, hostname: str, port: int = 443) -> Optional[TLSInfo]:
        """Return TLS details for the given host:port."""
        try:
            return self._fetch_tls_info(hostname, port)
        except Exception as exc:
            logger.debug("TLS enrichment failed for %s:%d — %s", hostname, port, exc)
            return None

    def _fetch_tls_info(self, hostname: str, port: int) -> TLSInfo:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # We inspect manually

        conn = ctx.wrap_socket(
            socket.create_connection((hostname, port),
                                     timeout=self.config.scan_timeout_s),
            server_hostname=hostname,
        )

        try:
            cert = conn.getpeercert()
            cipher = conn.cipher()  # (name, protocol, bits)
            protocol = conn.version()
        finally:
            conn.close()

        info = TLSInfo()

        if cert:
            # Issuer / subject
            info.issuer = self._dn_to_str(cert.get("issuer", ()))
            info.subject = self._dn_to_str(cert.get("subject", ()))

            # Validity
            not_before = cert.get("notBefore", "")
            not_after = cert.get("notAfter", "")
            if not_before:
                info.valid_from = datetime.strptime(
                    not_before, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            if not_after:
                info.valid_to = datetime.strptime(
                    not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                info.is_expired = info.valid_to < now
                info.days_to_expiry = max(0, (info.valid_to - now).days)

            # SANs
            sans = cert.get("subjectAltName", ())
            info.san_domains = [v for t, v in sans if t == "DNS"]
            info.is_wildcard = any(d.startswith("*.") for d in info.san_domains)

            # Self-signed check
            info.is_self_signed = info.issuer == info.subject

        if cipher:
            info.cipher_suites = [cipher[0]] if cipher[0] else []

        if protocol:
            info.protocol_versions = [protocol]

        return info

    @staticmethod
    def _dn_to_str(dn_tuple) -> str:
        """Convert ((('key', 'val'),),) to 'key=val, ...' format."""
        parts = []
        for rdn in dn_tuple:
            for key, val in rdn:
                parts.append(f"{key}={val}")
        return ", ".join(parts)

    def check_weak_protocols(self, hostname: str, port: int = 443) -> list[str]:
        """
        Probe for weak TLS protocol support.
        Returns list of weak protocols the server accepts.

        Note: Python's ssl module won't let you downgrade below TLS 1.2 in most
        system configurations. For thorough testing, invoke testssl.sh or similar.
        """
        weak_found = []

        for proto_name, ssl_version in [
            ("TLSv1", ssl.TLSVersion.TLSv1) if hasattr(ssl.TLSVersion, "TLSv1") else ("", None),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1) if hasattr(ssl.TLSVersion, "TLSv1_1") else ("", None),
        ]:
            if not proto_name or ssl_version is None:
                continue
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.maximum_version = ssl_version
                ctx.minimum_version = ssl_version
                with ctx.wrap_socket(
                    socket.create_connection((hostname, port), timeout=5),
                    server_hostname=hostname,
                ):
                    weak_found.append(proto_name)
            except Exception:
                pass  # Protocol not supported

        return weak_found
