"""Policy-as-code enforcement for scan requests."""

from functools import lru_cache

import yaml

from app.config import settings
from app.schemas import ScanRequest


@lru_cache(maxsize=1)
def load_policy() -> dict:
    path = settings.policy_file
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError("La política configurada debe ser un objeto YAML")
    return data


def enforce_policy(request: ScanRequest) -> None:
    policy = load_policy()
    if not policy:
        return
    scope = policy.get("scope", {})
    if scope.get("require_authorization", True) and not request.authorization_confirmed:
        raise ValueError("La política requiere confirmación de autorización")
    max_domains = int(scope.get("max_domains_per_job", settings.max_domains_per_job))
    if len(request.domains) > max_domains:
        raise ValueError(f"La política limita el trabajo a {max_domains} dominios")

    network = policy.get("network", {})
    max_rps = float(network.get("max_requests_per_second", settings.per_host_requests_per_second))
    if request.requests_per_second and request.requests_per_second > max_rps:
        raise ValueError(f"La política limita la velocidad a {max_rps:g} solicitudes por segundo")

    section = policy.get(request.execution_mode, {})
    if request.execution_mode == "passive":
        allowed = set(section.get("allowed_intensities", []))
        if allowed and request.intensity not in allowed:
            raise ValueError("La intensidad solicitada no está permitida por la política")
    else:
        allowed = set(section.get("allowed_checks", []))
        denied = sorted(set(request.active_checks) - allowed)
        if denied:
            raise ValueError(f"Checks activos no permitidos por política: {', '.join(denied)}")
        if section.get("require_reference", True) and not request.authorization_reference:
            raise ValueError("La política requiere una referencia de autorización")
