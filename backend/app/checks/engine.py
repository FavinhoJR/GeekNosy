"""Versioned passive check engine with optional signed YAML templates."""

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

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
        standards = {
            "owasp_top_10": [ref for ref in definition.references if ref.startswith("OWASP-A")],
            "owasp_asvs": [ref for ref in definition.references if "ASVS" in ref],
            "cwe": [ref for ref in definition.references if ref.startswith("CWE-")],
            "pci_dss": ["6.2.4", "6.3.3"],
            "soc2": ["CC6.6", "CC7.1"],
            "nist_csf": ["ID.RA-1", "PR.PS-1", "DE.CM-1"],
        }
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
            "standards": standards,
            "remediation": {
                "summary": definition.recommendation,
                "verification": "Repita el escaneo y valide la evidencia sobre el mismo alcance.",
            },
        }

    def _builtin_checks(self, result: dict) -> list[dict]:
        headers = result.get("headers", {})
        url = result.get("url_evaluated")
        body = result.get("body_preview") or ""
        findings = []

        csp = headers.get("content-security-policy", "").lower()
        csp_tokens = set(re.split(r"[\s;]+", csp)) if csp else set()
        csp_weaknesses = []
        if csp:
            if "'unsafe-inline'" in csp_tokens or "unsafe-inline" in csp_tokens:
                csp_weaknesses.append("unsafe-inline")
            if "'unsafe-eval'" in csp_tokens or "unsafe-eval" in csp_tokens:
                csp_weaknesses.append("unsafe-eval")
            if "*" in csp_tokens:
                csp_weaknesses.append("wildcard")
            if not re.search(r"(?:^|;)\s*default-src\s+", csp):
                csp_weaknesses.append("missing-default-src")
        if csp_weaknesses:
            findings.append(
                self._finding(
                    CheckDefinition(
                        "weak_csp",
                        "Content-Security-Policy permisiva",
                        "medium",
                        "high",
                        "passive",
                        "1.0.0",
                        "Elimine comodines, unsafe-inline y unsafe-eval; defina default-src y use nonces o hashes.",
                        ["CWE-693", "OWASP-A05:2021", "OWASP-ASVS-v5.0.0-3.4.3"],
                    ),
                    {"url": url, "matcher": "csp-permissive", "weaknesses": csp_weaknesses, "value": csp[:500]},
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

        if acao.lower() == "null":
            findings.append(
                self._finding(
                    CheckDefinition(
                        "cors_null_origin",
                        "CORS permite el origen null",
                        "medium",
                        "high",
                        "passive",
                        "1.0.0",
                        "Retire null de los orígenes permitidos y valide una allowlist exacta.",
                        ["CWE-942", "OWASP-A05:2021", "OWASP-ASVS-4.2"],
                    ),
                    {"url": url, "matcher": "acao-null"},
                )
            )

        hsts = headers.get("strict-transport-security", "").lower()
        if hsts:
            max_age_match = re.search(r"max-age\s*=\s*(\d+)", hsts)
            max_age = int(max_age_match.group(1)) if max_age_match else 0
            missing_preload = max_age < 31536000 or "includesubdomains" not in hsts or "preload" not in hsts
            if missing_preload:
                findings.append(
                    self._finding(
                        CheckDefinition(
                            "hsts_not_preload_ready",
                            "HSTS no cumple los criterios técnicos de preload",
                            "low",
                            "high",
                            "passive",
                            "1.0.0",
                            "Use max-age de al menos un año, includeSubDomains y preload antes de solicitar inclusión.",
                            ["CWE-319", "OWASP-A02:2021", "OWASP-ASVS-9.1"],
                        ),
                        {"url": url, "matcher": "hsts-preload-directives", "max_age": max_age},
                    )
                )

        referrer = headers.get("referrer-policy", "").lower()
        if referrer in {"unsafe-url", "no-referrer-when-downgrade"}:
            findings.append(
                self._finding(
                    CheckDefinition(
                        "weak_referrer_policy",
                        "Referrer-Policy expone más contexto del necesario",
                        "low",
                        "high",
                        "passive",
                        "1.0.0",
                        "Use strict-origin-when-cross-origin o no-referrer según el flujo.",
                        ["CWE-200", "OWASP-ASVS-14.4"],
                    ),
                    {"url": url, "matcher": "weak-referrer-policy", "value": referrer},
                )
            )

        permissions = headers.get("permissions-policy", "").lower()
        if permissions and "*" in permissions:
            findings.append(
                self._finding(
                    CheckDefinition(
                        "broad_permissions_policy",
                        "Permissions-Policy contiene permisos globales",
                        "low",
                        "medium",
                        "passive",
                        "1.0.0",
                        "Permita únicamente las capacidades y orígenes estrictamente necesarios.",
                        ["CWE-284", "OWASP-ASVS-14.4"],
                    ),
                    {"url": url, "matcher": "permissions-policy-wildcard", "value": permissions[:500]},
                )
            )

        corp = headers.get("cross-origin-resource-policy", "").lower()
        if result.get("path") in ("/", "") and corp not in {"same-origin", "same-site"}:
            findings.append(
                self._finding(
                    CheckDefinition(
                        "corp_not_restrictive",
                        "Cross-Origin-Resource-Policy ausente o permisiva",
                        "info",
                        "medium",
                        "passive",
                        "1.0.0",
                        "Defina same-origin o same-site cuando los recursos no deban compartirse públicamente.",
                        ["CWE-346", "OWASP-ASVS-14.4"],
                    ),
                    {"url": url, "matcher": "corp-policy", "value": corp or "missing"},
                )
            )

        origin_host = (urlparse(url).hostname or "").lower()
        asset_tags = re.findall(r"<(?:script|link)\b[^>]+>", body, re.I)
        missing_sri = []
        for tag in asset_tags:
            match = re.search(r"(?:src|href)=[\"']([^\"']+)", tag, re.I)
            if not match:
                continue
            asset = match.group(1)
            parsed_asset = urlparse(asset)
            if parsed_asset.scheme in {"http", "https"} and parsed_asset.hostname and parsed_asset.hostname.lower() != origin_host:
                if not re.search(r"\bintegrity=[\"']", tag, re.I):
                    missing_sri.append(asset[:300])
        if missing_sri:
            findings.append(
                self._finding(
                    CheckDefinition(
                        "external_assets_without_sri",
                        "Recursos externos sin Subresource Integrity",
                        "medium",
                        "high",
                        "passive",
                        "1.0.0",
                        "Añada integrity con SHA-384/512 y crossorigin, o aloje el recurso bajo su control.",
                        ["CWE-353", "OWASP-A08:2021", "OWASP-ASVS-14.2"],
                    ),
                    {"url": url, "matcher": "external-assets-no-sri", "assets": missing_sri[:20]},
                )
            )

        secret_patterns = {
            "aws-access-key": r"\bAKIA[0-9A-Z]{16}\b",
            "google-api-key": r"\bAIza[0-9A-Za-z_-]{35}\b",
            "github-token": r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b",
            "private-key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            "generic-secret": r"(?i)(?:api[_-]?key|secret|token)\s*[:=]\s*[\"'][A-Za-z0-9_\-]{20,}[\"']",
        }
        matched_secret_types = [name for name, pattern in secret_patterns.items() if re.search(pattern, body)]
        if matched_secret_types:
            findings.append(
                self._finding(
                    CheckDefinition(
                        "public_secret_pattern",
                        "Patrón de secreto detectado en contenido público",
                        "critical",
                        "medium",
                        "passive",
                        "1.0.0",
                        "Revoque el valor, retírelo del bundle y use secretos del lado servidor. GeekNosy no almacena el valor coincidente.",
                        ["CWE-798", "OWASP-A07:2021", "OWASP-ASVS-14.1"],
                    ),
                    {"url": url, "matcher": "redacted-secret-pattern", "types": matched_secret_types},
                )
            )

        title = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        if title and re.search(r"index of\s*/", title.group(1), re.I):
            findings.append(
                self._finding(
                    CheckDefinition(
                        "directory_listing",
                        "Listado de directorio público",
                        "medium",
                        "high",
                        "passive",
                        "1.0.0",
                        "Deshabilite autoindex/directory browsing y publique un recurso índice explícito.",
                        ["CWE-548", "OWASP-A05:2021", "OWASP-ASVS-14.3"],
                    ),
                    {"url": url, "matcher": "index-of-title"},
                )
            )

        path = (result.get("path") or "").lower()
        if result.get("http_code") == 200 and path in {"/.env", "/config.json", "/config.js", "/.git/config", "/backup.zip"}:
            findings.append(
                self._finding(
                    CheckDefinition(
                        "exposed_configuration_resource",
                        "Recurso de configuración o respaldo accesible",
                        "critical",
                        "high",
                        "passive",
                        "1.0.0",
                        "Retire el recurso del webroot, bloquee el patrón y rote cualquier credencial potencialmente expuesta.",
                        ["CWE-538", "OWASP-A05:2021", "OWASP-ASVS-14.3"],
                    ),
                    {"url": url, "matcher": "exposure-path-status", "path": path},
                )
            )

        for cookie in result.get("cookies", []):
            name = cookie.get("name", "")
            reasons = []
            if name.startswith("__Host-") and (not cookie.get("secure") or cookie.get("domain") or cookie.get("path") != "/"):
                reasons.append("invalid-__Host-prefix")
            if name.startswith("__Secure-") and not cookie.get("secure"):
                reasons.append("invalid-__Secure-prefix")
            if str(cookie.get("samesite") or "").lower() == "none" and not cookie.get("secure"):
                reasons.append("SameSite=None-without-Secure")
            try:
                if int(cookie.get("max_age") or 0) > 31536000:
                    reasons.append("lifetime-over-one-year")
            except ValueError:
                pass
            if reasons:
                findings.append(
                    self._finding(
                        CheckDefinition(
                            f"cookie_policy_{hashlib.sha256(name.encode()).hexdigest()[:10]}",
                            "Cookie con atributos inconsistentes",
                            "medium",
                            "high",
                            "passive",
                            "1.0.0",
                            "Corrija prefijos, Secure, SameSite, Path, Domain y duración según el uso de la cookie.",
                            ["CWE-614", "CWE-1004", "OWASP-A07:2021", "OWASP-ASVS-3.4"],
                        ),
                        {"url": url, "matcher": "cookie-attribute-policy", "cookie": name, "reasons": reasons},
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
