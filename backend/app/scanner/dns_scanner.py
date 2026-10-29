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
        "cname_records": [],
        "spf_records": [],
        "dmarc_records": [],
        "dkim_records": {},
        "dnssec": False,
        "errors": [],
    }

    for rtype, key in [
        ("A", "a_records"),
        ("AAAA", "aaaa_records"),
        ("MX", "mx_records"),
        ("NS", "ns_records"),
        ("TXT", "txt_records"),
        ("CNAME", "cname_records"),
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

    for selector in ("default", "selector1", "selector2", "google", "k1"):
        try:
            answers = await asyncio.to_thread(
                dns.resolver.resolve, f"{selector}._domainkey.{hostname}", "TXT"
            )
            values = [str(record) for record in answers if "v=dkim1" in str(record).lower()]
            if values:
                evidence["dkim_records"][selector] = values
        except Exception:
            continue

    try:
        answers = await asyncio.to_thread(dns.resolver.resolve, hostname, "CAA")
        evidence["caa_records"] = [str(r) for r in answers]
        evidence["has_caa"] = len(evidence["caa_records"]) > 0
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        evidence["has_caa"] = False
    except Exception as e:
        evidence["errors"].append(f"CAA: {e}")

    return evidence


def build_dns_finding_details(evidence: dict) -> list[dict]:
    findings = []
    hostname = evidence.get("hostname")

    def add(check_id, title, severity, confidence, recommendation, references, matcher, extra=None):
        import hashlib
        payload = {"hostname": hostname, "matcher": matcher, **(extra or {})}
        findings.append(
            {
                "id": check_id,
                "title": title,
                "severity": severity,
                "confidence": confidence,
                "intrusiveness": "passive",
                "version": "1.0.0",
                "recommendation": recommendation,
                "references": references,
                "fingerprint": hashlib.sha256(f"{check_id}:{hostname}".encode()).hexdigest(),
                "template_hash": "builtin-dns",
                "evidence": payload,
                "standards": {
                    "owasp_top_10": ["OWASP-A05:2021"],
                    "owasp_asvs": ["OWASP-ASVS-14.4"],
                    "pci_dss": ["1.2.5", "6.3.3"],
                    "soc2": ["CC6.6"],
                    "nist_csf": ["ID.RA-1", "PR.PS-1"],
                },
            }
        )

    dmarc = " ".join(evidence.get("dmarc_records", [])).lower()
    if dmarc and ("p=none" in dmarc or "pct=0" in dmarc):
        add(
            "dmarc_monitor_only",
            "DMARC está en modo de observación",
            "low",
            "high",
            "Evolucione gradualmente a p=quarantine o p=reject después de validar sus fuentes legítimas.",
            ["CWE-290"],
            "dmarc-policy-none",
        )
    if not evidence.get("dkim_records"):
        add(
            "dkim_not_observed",
            "No se observó DKIM en selectores comunes",
            "info",
            "low",
            "Verifique el selector real del proveedor; publique una clave DKIM y habilite firma de correo.",
            ["CWE-290"],
            "common-dkim-selectors",
        )
    if not evidence.get("dnssec"):
        add(
            "dnssec_not_observed",
            "No se observó DNSKEY para DNSSEC",
            "low",
            "medium",
            "Habilite DNSSEC en la zona y valide la cadena de confianza con el registrador.",
            ["CWE-350"],
            "dnskey-missing",
        )

    takeover_providers = (
        "github.io", "herokuapp.com", "azurewebsites.net", "cloudfront.net",
        "pages.dev", "readthedocs.io", "netlify.app", "vercel.app",
    )
    risky = [record for record in evidence.get("cname_records", []) if any(p in record.lower() for p in takeover_providers)]
    if risky:
        add(
            "third_party_cname_review",
            "CNAME hacia proveedor externo requiere revisión de propiedad",
            "info",
            "medium",
            "Confirme que el recurso del proveedor siga asignado. La presencia del CNAME por sí sola no prueba takeover.",
            ["CWE-284"],
            "third-party-cname",
            {"records": risky},
        )
    return findings


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
