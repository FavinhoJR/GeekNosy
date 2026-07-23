"""Análisis TLS/SSL no intrusivo."""

import asyncio
import socket
import ssl
from datetime import datetime, timezone

from app.config import settings
from app.scanner.http_scanner import normalize_domain


def _get_cert_info(hostname: str, port: int = 443) -> dict:
    ctx = ssl.create_default_context()
    evidence: dict = {
        "hostname": hostname,
        "port": port,
        "valid": False,
        "issuer": None,
        "subject": None,
        "not_before": None,
        "not_after": None,
        "days_until_expiry": None,
        "expiring_soon": False,
        "tls_versions": {},
        "error": None,
    }
    try:
        with socket.create_connection((hostname, port), timeout=settings.scan_timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                evidence["valid"] = True
                evidence["protocol"] = ssock.version()
                evidence["cipher"] = ssock.cipher()
                evidence["alpn_protocol"] = ssock.selected_alpn_protocol()
                if cert:
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    subject = dict(x[0] for x in cert.get("subject", []))
                    evidence["issuer"] = issuer.get("organizationName", str(issuer))
                    evidence["subject"] = subject.get("commonName", str(subject))
                    evidence["subject_alt_names"] = [
                        value for kind, value in cert.get("subjectAltName", []) if kind == "DNS"
                    ]
                    not_after = cert.get("notAfter")
                    not_before = cert.get("notBefore")
                    if not_after:
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                            tzinfo=timezone.utc
                        )
                        evidence["not_after"] = expiry.isoformat()
                        days = (expiry - datetime.now(timezone.utc)).days
                        evidence["days_until_expiry"] = days
                        evidence["expiring_soon"] = days < 30
                    if not_before:
                        nb = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z").replace(
                            tzinfo=timezone.utc
                        )
                        evidence["not_before"] = nb.isoformat()
    except ssl.SSLError as e:
        evidence["error"] = f"SSL error: {e}"
    except (socket.timeout, socket.error, OSError) as e:
        evidence["error"] = str(e)
    return evidence


def _probe_tls_version(hostname: str, tls_version: int) -> bool:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = tls_version
    ctx.maximum_version = tls_version
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                return ssock.version() is not None
    except (ssl.SSLError, socket.error, OSError):
        return False


async def scan_tls(domain: str) -> dict:
    hostname = normalize_domain(domain)
    evidence = await asyncio.to_thread(_get_cert_info, hostname)

    # Probar TLS 1.2 y 1.3
    tls10, tls11, tls12, tls13 = await asyncio.gather(
        asyncio.to_thread(_probe_tls_version, hostname, ssl.TLSVersion.TLSv1),
        asyncio.to_thread(_probe_tls_version, hostname, ssl.TLSVersion.TLSv1_1),
        asyncio.to_thread(_probe_tls_version, hostname, ssl.TLSVersion.TLSv1_2),
        asyncio.to_thread(_probe_tls_version, hostname, ssl.TLSVersion.TLSv1_3),
    )
    evidence["tls_versions"] = {
        "tls_1_0": tls10,
        "tls_1_1": tls11,
        "tls_1_2": tls12,
        "tls_1_3": tls13,
    }

    return evidence


def score_tls(evidence: dict) -> tuple[float, list[str]]:
    """Puntaje TLS 0-100."""
    findings: list[str] = []
    score = 0.0

    if evidence.get("valid"):
        score += 40
    else:
        findings.append("ssl_invalid")
        return 0.0, findings

    if not evidence.get("expiring_soon", True):
        score += 25
    else:
        findings.append("ssl_expiring_soon")

    days = evidence.get("days_until_expiry")
    if days is not None and days > 30:
        score += 15
    elif days is not None and days > 0:
        score += 5

    tls_versions = evidence.get("tls_versions", {})
    if tls_versions.get("tls_1_2"):
        score += 10
    else:
        findings.append("tls12_unsupported")

    if tls_versions.get("tls_1_3"):
        score += 10
    else:
        findings.append("tls13_unsupported")

    if tls_versions.get("tls_1_0") or tls_versions.get("tls_1_1"):
        score -= 20
        findings.append("legacy_tls_enabled")

    return max(0.0, min(100.0, score)), findings
