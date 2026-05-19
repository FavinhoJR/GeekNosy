"""Consultas DNS básicas no intrusivas."""

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
        "errors": [],
    }

    for rtype, key in [("A", "a_records"), ("AAAA", "aaaa_records"), ("MX", "mx_records")]:
        try:
            answers = dns.resolver.resolve(hostname, rtype)
            evidence[key] = [str(r) for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            pass
        except Exception as e:
            evidence["errors"].append(f"{rtype}: {e}")

    try:
        answers = dns.resolver.resolve(hostname, "CAA")
        evidence["caa_records"] = [str(r) for r in answers]
        evidence["has_caa"] = len(evidence["caa_records"]) > 0
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        evidence["has_caa"] = False
    except Exception as e:
        evidence["errors"].append(f"CAA: {e}")

    return evidence


def score_dns(evidence: dict) -> tuple[float, list[str]]:
    findings: list[str] = []
    score = 50.0  # base por resolución

    if evidence.get("a_records") or evidence.get("aaaa_records"):
        score += 30
    else:
        score = 20

    if evidence.get("has_caa"):
        score += 20
    else:
        findings.append("no_dns_caa")

    return min(100.0, score), findings
