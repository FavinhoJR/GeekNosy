"""Consultas DNS básicas no intrusivas."""

import asyncio
import dns.resolver

from app.scanner.http_scanner import normalize_domain


async def scan_dns(domain: str) -> dict:
    hostname = normalize_domain(domain)
    evidence: dict = {
        "hostname": hostname,
        "a_records": [],
        "aaaa_records": [],
        "caa_records": [],
        "has_caa": False,
        "mx_records": [],
        "ns_records": [],
        "txt_records": [],
        "spf_records": [],
        "dmarc_records": [],
        "dnssec": False,
        "errors": [],
    }

    for rtype, key in [
        ("A", "a_records"),
        ("AAAA", "aaaa_records"),
        ("MX", "mx_records"),
        ("NS", "ns_records"),
        ("TXT", "txt_records"),
    ]:
        try:
            answers = await asyncio.to_thread(dns.resolver.resolve, hostname, rtype)
            evidence[key] = [str(r) for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            pass
        except Exception as e:
            evidence["errors"].append(f"{rtype}: {e}")

    evidence["spf_records"] = [
        value for value in evidence["txt_records"] if "v=spf1" in value.lower()
    ]
    try:
        answers = await asyncio.to_thread(dns.resolver.resolve, f"_dmarc.{hostname}", "TXT")
        evidence["dmarc_records"] = [str(record) for record in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        pass
    except Exception as e:
        evidence["errors"].append(f"DMARC: {e}")

    try:
        answers = await asyncio.to_thread(dns.resolver.resolve, hostname, "DNSKEY")
        evidence["dnssec"] = bool(list(answers))
    except Exception:
        evidence["dnssec"] = False

    try:
        answers = await asyncio.to_thread(dns.resolver.resolve, hostname, "CAA")
        evidence["caa_records"] = [str(r) for r in answers]
        evidence["has_caa"] = len(evidence["caa_records"]) > 0
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        evidence["has_caa"] = False
    except Exception as e:
        evidence["errors"].append(f"CAA: {e}")

    return evidence


def score_dns(evidence: dict) -> tuple[float, list[str]]:
    findings: list[str] = []
    score = 0.0

    if evidence.get("a_records") or evidence.get("aaaa_records"):
        score += 30
    else:
        findings.append("dns_unresolved")

    if evidence.get("has_caa"):
        score += 15
    else:
        findings.append("no_dns_caa")
    if evidence.get("spf_records"):
        score += 15
    else:
        findings.append("no_spf")
    if evidence.get("dmarc_records"):
        score += 20
    else:
        findings.append("no_dmarc")
    if evidence.get("dnssec"):
        score += 20
    else:
        findings.append("no_dnssec")

    return min(100.0, score), findings
