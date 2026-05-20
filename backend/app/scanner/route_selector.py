"""Selección inteligente de rutas según perfil y tecnología detectada."""

from app.route_profiles import (
    EXPOSURE_PATHS,
    ROUTE_PROFILES,
    ROUTE_PROFILE_MODES,
    TECH_PROFILE_MAP,
)


def normalize_path(path: str) -> str:
    p = path.strip()
    if not p:
        return "/"
    if not p.startswith("/"):
        p = "/" + p
    return p


def dedupe_paths(paths: list[str], max_count: int) -> list[tuple[str, str]]:
    """
    Elimina duplicados preservando orden. Retorna lista de (path, profile_source).
    profile_source indica el primer perfil que aportó la ruta.
    """
    seen: set[str] = set()
    result: list[tuple[str, str]] = []
    for path, profile in paths:
        norm = normalize_path(path)
        key = norm.rstrip("/") or "/"
        if key in seen:
            continue
        seen.add(key)
        result.append((norm, profile))
        if len(result) >= max_count:
            break
    return result


def _paths_from_profiles(profiles: list[str]) -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []
    for profile in profiles:
        for path in ROUTE_PROFILES.get(profile, []):
            items.append((path, profile))
    return items


def select_route_profiles(
    route_profile: str,
    mode: str,
    detected_technologies: list[str],
    include_exposure_checks: bool,
    include_default_paths: bool,
    custom_paths: list[str] | None,
    max_paths: int = 40,
) -> dict:
    """
    Construye lista ordenada de rutas a evaluar.
    """
    if route_profile not in ROUTE_PROFILE_MODES:
        route_profile = "auto"

    effective = route_profile
    if route_profile == "auto":
        effective = "standard"

    profiles_to_use: list[str] = []

    if not include_default_paths:
        profiles_to_use = []
    elif effective == "minimal":
        profiles_to_use = ["core"]
    elif effective == "standard":
        profiles_to_use = ["core"]
        for tech in detected_technologies:
            if tech in TECH_PROFILE_MAP:
                profiles_to_use.append(TECH_PROFILE_MAP[tech])
            elif tech in ROUTE_PROFILES and tech not in ("core", "common", "exposure_checks"):
                profiles_to_use.append(tech)
    elif effective == "advanced":
        profiles_to_use = ["core", "common"]
        for tech in detected_technologies:
            if tech in ROUTE_PROFILES and tech not in ("core", "common", "exposure_checks"):
                if tech not in profiles_to_use:
                    profiles_to_use.append(tech)
        if "api_docs" in detected_technologies or _has_api_signal(detected_technologies):
            if "api_docs" not in profiles_to_use:
                profiles_to_use.append("api_docs")
    elif effective == "all":
        profiles_to_use = [
            "core",
            "common",
            "wordpress",
            "joomla",
            "drupal",
            "laravel_php",
            "django_python",
            "node_frontend",
            "aspnet_iis",
            "api_docs",
        ]

    if include_exposure_checks and include_default_paths:
        profiles_to_use.append("exposure_checks")

    # Fase 1: solo core para detección inicial (orchestrator llamará dos veces)
    path_items = _paths_from_profiles(profiles_to_use)

    if custom_paths:
        for cp in custom_paths:
            path_items.append((normalize_path(cp), "custom"))

    final = dedupe_paths(path_items, max_paths)

    return {
        "route_profile": route_profile,
        "effective_profile": effective,
        "selected_profiles": list(dict.fromkeys(profiles_to_use)),
        "paths": [{"path": p, "profile": prof} for p, prof in final],
        "total_before_cap": len(path_items),
        "total_selected": len(final),
        "max_paths_per_domain": max_paths,
    }


def get_core_paths() -> list[tuple[str, str]]:
    return [(p, "core") for p in ROUTE_PROFILES["core"]]


def select_paths_after_detection(
    route_profile: str,
    mode: str,
    detected_technologies: list[str],
    include_exposure_checks: bool,
    include_default_paths: bool,
    custom_paths: list[str] | None,
    max_paths: int,
) -> dict:
    """Selección completa tras detección de tecnología."""
    return select_route_profiles(
        route_profile=route_profile,
        mode=mode,
        detected_technologies=detected_technologies,
        include_exposure_checks=include_exposure_checks,
        include_default_paths=include_default_paths,
        custom_paths=custom_paths,
        max_paths=max_paths,
    )


def _has_api_signal(technologies: list[str]) -> bool:
    return "api_docs" in technologies or "node_frontend" in technologies


def is_exposure_path(path: str) -> bool:
    norm = normalize_path(path)
    return norm in EXPOSURE_PATHS or any(
        norm.endswith(p.lstrip("/")) for p in EXPOSURE_PATHS if p != norm
    )
