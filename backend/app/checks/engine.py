"""Versioned passive check engine with optional signed YAML templates."""

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from app.config import settings


@dataclass(frozen=True)
class CheckDefinition:
    id: str
    name: str
    severity: str
    confidence: str
    intrusiveness: str
    version: str
    recommendation: str
    references: list[str]


class CheckEngine:
    def __init__(self):
        self.template_dir = Path(__file__).parent / "templates"
        self.templates = self._load_templates()

    def _load_templates(self) -> list[dict]:
        templates = []
        if not self.template_dir.exists():
            return templates
        for path in sorted(self.template_dir.glob("*.yaml")):
            raw = path.read_bytes()
            data = yaml.safe_load(raw) or {}
            signature = data.pop("signature", None)
            if settings.template_signing_secret:
                canonical = yaml.safe_dump(data, sort_keys=True).encode()
                expected = hmac.new(
                    settings.template_signing_secret.encode(), canonical, hashlib.sha256
                ).hexdigest()
                if not signature or not hmac.compare_digest(signature, expected):
                    continue
            data["_template_hash"] = hashlib.sha256(raw).hexdigest()
            data["_template_file"] = path.name
            templates.append(data)
        return templates

    def run(self, result: dict, intensity: str = "standard") -> list[dict]:
        findings = self._builtin_checks(result)
        findings.extend(self._template_checks(result, intensity))
        deduped = {}
        for finding in findings:
            deduped[finding["id"]] = finding
        return list(deduped.values())

    def _finding(
        self,
        definition: CheckDefinition,
        evidence: dict[str, Any],
        *,
        template_hash: str = "builtin",
    ) -> dict:
        fingerprint_source = json.dumps(
            [definition.id, evidence.get("url"), evidence.get("matcher")],
            sort_keys=True,
        )
        return {
            "id": definition.id,
            "title": definition.name,
            "severity": definition.severity,
            "confidence": definition.confidence,
            "intrusiveness": definition.intrusiveness,
            "version": definition.version,
            "recommendation": definition.recommendation,
            "references": definition.references,
            "template_hash": template_hash,
            "fingerprint": hashlib.sha256(fingerprint_source.encode()).hexdigest(),
            "evidence": evidence,
        }

    def _builtin_checks(self, result: dict) -> list[dict]:
        headers = result.get("headers", {})
        url = result.get("url_evaluated")
        body = result.get("body_preview") or ""
        findings = []

        csp = headers.get("content-security-policy", "").lower()
        if csp and ("unsafe-inline" in csp or re.search(r"(?:^|;)\s*default-src\s+\*", csp)):
            findings.append(
                self._finding(
                    CheckDefinition(
                        "weak_csp",
                        "Content-Security-Policy permisiva",
                        "medium",
                        "high",
                        "passive",
                        "1.0.0",
                        "Elimine comodines y unsafe-inline; use nonces o hashes.",
                        ["CWE-693", "OWASP-ASVS-v5.0.0-3.4.3"],
                    ),
                    {"url": url, "matcher": "csp-permissive", "value": csp[:500]},
                )
            )

        acao = headers.get("access-control-allow-origin", "")
        credentials = headers.get("access-control-allow-credentials", "").lower()
        if acao == "*" and credentials == "true":
            findings.append(
                self._finding(
                    CheckDefinition(
                        "cors_wildcard_credentials",
                        "CORS combina origen comodín y credenciales",
                        "high",
                        "high",
                        "passive",
                        "1.0.0",
                        "Use una allowlist explícita de orígenes y no combine * con credenciales.",
                        ["CWE-942", "OWASP-WSTG-v42-CLNT-07"],
                    ),
                    {"url": url, "matcher": "acao-star-with-credentials"},
                )
            )

        cache_control = headers.get("cache-control", "").lower()
        sensitive_path = any(
            token in (result.get("path") or "").lower()
            for token in ("login", "admin", "account", "dashboard")
        )
        if sensitive_path and result.get("http_code") == 200 and not any(
            token in cache_control for token in ("no-store", "private")
        ):
            findings.append(
                self._finding(
                    CheckDefinition(
                        "sensitive_cacheable_response",
                        "Respuesta sensible potencialmente almacenable",
                        "medium",
                        "medium",
                        "passive",
                        "1.0.0",
                        "Use Cache-Control: no-store en respuestas autenticadas o sensibles.",
                        ["CWE-525"],
                    ),
                    {"url": url, "matcher": "sensitive-path-cache-control", "value": cache_control},
                )
            )

        if body and re.search(r"<script[^>]+src=[\"'][^\"']+\.js\.map", body, re.I):
            findings.append(
                self._finding(
                    CheckDefinition(
                        "source_map_reference",
                        "Referencia pública a source map",
                        "low",
                        "medium",
                        "passive",
                        "1.0.0",
                        "Retire source maps de producción o restrinja su acceso.",
                        ["CWE-540"],
                    ),
                    {"url": url, "matcher": "script-source-map-reference"},
                )
            )

        server = headers.get("server", "")
        if re.search(r"\d+\.\d+", server):
            findings.append(
                self._finding(
                    CheckDefinition(
                        "server_version_exposed",
                        "Versión exacta del servidor expuesta",
                        "low",
                        "high",
                        "passive",
                        "1.0.0",
                        "Reduzca la información de versión en la cabecera Server.",
                        ["CWE-200", "OWASP-WSTG-v42-INFO-02"],
                    ),
                    {"url": url, "matcher": "server-version", "value": server[:200]},
                )
            )
        return findings

    def _template_checks(self, result: dict, intensity: str) -> list[dict]:
        findings = []
        rank = {"passive": 0, "fast": 1, "standard": 2, "bug_bounty": 3, "deep": 4, "custom": 4}
        for template in self.templates:
            if rank.get(intensity, 2) < rank.get(template.get("minimum_intensity", "passive"), 0):
                continue
            match = template.get("match", {})
            status = match.get("status")
            if status is not None and result.get("http_code") not in (
                status if isinstance(status, list) else [status]
            ):
                continue
            path_pattern = match.get("path_regex")
            if path_pattern and not re.search(path_pattern, result.get("path", ""), re.I):
                continue
            header_missing = match.get("header_missing")
            if header_missing and header_missing.lower() in result.get("headers", {}):
                continue
            header = match.get("header")
            contains = match.get("contains")
            if header and contains and contains.lower() not in result.get("headers", {}).get(
                header.lower(), ""
            ).lower():
                continue
            definition = CheckDefinition(
                template["id"],
                template["name"],
                template.get("severity", "info"),
                template.get("confidence", "medium"),
                template.get("intrusiveness", "passive"),
                str(template.get("version", "1")),
                template.get("recommendation", ""),
                template.get("references", []),
            )
            findings.append(
                self._finding(
                    definition,
                    {
                        "url": result.get("url_evaluated"),
                        "matcher": template.get("_template_file"),
                    },
                    template_hash=template["_template_hash"],
                )
            )
        return findings


check_engine = CheckEngine()
