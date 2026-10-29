"""Passive JavaScript component inventory with optional OSV enrichment."""

import hashlib
import re

import httpx


LIBRARY_PATTERNS = {
    "jquery": r"jquery(?:[.-](?:min\.)?)?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    "bootstrap": r"bootstrap(?:[.-](?:bundle\.)?(?:min\.)?)?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    "lodash": r"lodash(?:[.-](?:min\.)?)?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    "axios": r"axios(?:[.-](?:min\.)?)?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    "moment": r"moment(?:[.-](?:min\.)?)?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
}


def extract_js_components(html: str) -> list[dict]:
    sources = re.findall(r"<script[^>]+src=[\"']([^\"']+)[\"']", html or "", re.I)
    components = []
    for source in sources:
        lowered = source.lower()
        for package, pattern in LIBRARY_PATTERNS.items():
            match = re.search(pattern, lowered)
            if match:
                components.append({"package": package, "version": match.group(1), "source": source[:500]})
    deduped = {(item["package"], item["version"]): item for item in components}
    return list(deduped.values())


async def enrich_with_osv(components: list[dict]) -> list[dict]:
    findings = []
    async with httpx.AsyncClient(timeout=5.0) as client:
        for component in components[:6]:
            try:
                response = await client.post(
                    "https://api.osv.dev/v1/query",
                    json={
                        "package": {"name": component["package"], "ecosystem": "npm"},
                        "version": component["version"],
                    },
                )
                response.raise_for_status()
                advisories = response.json().get("vulns", [])
            except (httpx.HTTPError, ValueError):
                continue
            if not advisories:
                continue
            advisory_ids = [item.get("id") for item in advisories[:20] if item.get("id")]
            key = f"{component['package']}:{component['version']}"
            findings.append(
                {
                    "id": f"outdated_js_{component['package']}",
                    "title": f"OSV reporta avisos para {component['package']} {component['version']}",
                    "severity": "high",
                    "confidence": "high",
                    "intrusiveness": "passive-external-intelligence",
                    "version": "1.0.0",
                    "recommendation": "Actualice a una versión mantenida y confirme que los avisos aplican al bundle desplegado.",
                    "references": ["OWASP-A06:2021", "CWE-1104", *advisory_ids],
                    "fingerprint": hashlib.sha256(key.encode()).hexdigest(),
                    "template_hash": "builtin-osv",
                    "evidence": {**component, "advisory_ids": advisory_ids},
                    "standards": {
                        "owasp_top_10": ["OWASP-A06:2021"],
                        "owasp_asvs": ["OWASP-ASVS-14.2"],
                        "pci_dss": ["6.3.3"],
                        "soc2": ["CC7.1"],
                        "nist_csf": ["ID.RA-1", "PR.PS-2"],
                    },
                }
            )
    return findings
