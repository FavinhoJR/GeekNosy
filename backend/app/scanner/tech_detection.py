"""Detección de tecnología a partir de señales públicas no intrusivas."""

import re
from typing import Any

# Señales por ruta conocida (status que indica posible presencia)
PROBE_PATHS = {
    "wordpress": ["/wp-login.php", "/wp-json/", "/xmlrpc.php"],
    "joomla": ["/administrator/", "/web/administrator/"],
    "drupal": ["/core/", "/CHANGELOG.txt"],
    "laravel_php": ["/vendor/", "/storage/"],
    "django_python": ["/admin/", "/static/"],
    "aspnet_iis": ["/swagger", "/Account/Login"],
    "api_docs": ["/swagger", "/openapi.json", "/graphql"],
}


def _body_signals(body: str) -> set[str]:
    detected: set[str] = set()
    if not body:
        return detected
    b = body.lower()[:12000]
    patterns = {
        "wordpress": [r"wp-content", r"wp-includes", r"wordpress", r"/wp-json/"],
        "joomla": [r"joomla", r"option=com_", r"/administrator/"],
        "drupal": [r"drupal", r"sites/default", r"drupal.js"],
        "laravel_php": [r"laravel", r"illuminate"],
        "django_python": [r"csrfmiddlewaretoken", r"django", r"__admin__"],
        "node_frontend": [r"react", r"__next", r"ng-version", r"vue", r"vite"],
        "aspnet_iis": [r"asp.net", r"__viewstate", r"iis", r"webforms"],
    }
    for tech, pats in patterns.items():
        if any(re.search(p, b) for p in pats):
            detected.add(tech)
    if re.search(r"swagger|openapi|graphql", b):
        detected.add("api_docs")
    return detected


def _header_signals(headers: dict, cookies: list[dict]) -> set[str]:
    detected: set[str] = set()
    server = headers.get("server", "").lower()
    powered = headers.get("x-powered-by", "").lower()
    combined = f"{server} {powered}"

    if "wordpress" in powered or "wp-" in combined:
        detected.add("wordpress")
    if "php" in powered or "php/" in combined:
        detected.add("laravel_php")
    if "asp.net" in powered or "iis" in server or "microsoft-iis" in server:
        detected.add("aspnet_iis")
    if "nginx" in server or "apache" in server:
        pass  # genérico

    cookie_names = " ".join(c.get("name", "").lower() for c in cookies)
    if "laravel_session" in cookie_names or "xsrf-token" in cookie_names:
        detected.add("laravel_php")
    if "csrftoken" in cookie_names or "sessionid" in cookie_names and "django" in powered:
        detected.add("django_python")
    if "asp.net_sessionid" in cookie_names or "__requestverificationtoken" in cookie_names:
        detected.add("aspnet_iis")
    if "wordpress" in cookie_names or "wp-settings" in cookie_names:
        detected.add("wordpress")

    generator = headers.get("x-generator", "").lower()
    if "wordpress" in generator:
        detected.add("wordpress")
    if "joomla" in generator:
        detected.add("joomla")
    if "drupal" in generator:
        detected.add("drupal")

    return detected


def _path_probe_signals(path_results: list[dict]) -> set[str]:
    """Usa resultados de rutas ya evaluadas para inferir tecnología."""
    detected: set[str] = set()
    by_path: dict[str, dict] = {}
    for r in path_results:
        p = r.get("path", "")
        by_path[p] = r

    for tech, paths in PROBE_PATHS.items():
        for p in paths:
            res = by_path.get(p)
            if res and res.get("http_code") in (200, 301, 302, 303, 307, 308, 401, 403):
                detected.add(tech)
                break

    # Joomla paths específicos
    joomla_paths = ["/administrator/", "/component/users"]
    if any(
        by_path.get(p, {}).get("http_code") in (200, 301, 302, 403)
        for p in joomla_paths
    ):
        detected.add("joomla")

    return detected


def detect_technologies(
    root_result: dict | None,
    path_results: list[dict] | None = None,
    body_preview: str = "",
) -> dict[str, Any]:
    """
    Detecta perfiles tecnológicos aplicables.
    Solo usa señales públicas: headers, cookies (nombres), fragmento HTML, rutas conocidas.
    """
    detected: set[str] = set()
    headers = (root_result or {}).get("headers", {})
    cookies = (root_result or {}).get("cookies", [])

    detected |= _header_signals(headers, cookies)
    detected |= _body_signals(body_preview)
    if path_results:
        detected |= _path_probe_signals(path_results)

    # api_docs como categoría separada si hay swagger/graphql
    if "api_docs" in detected:
        detected.add("api_docs")

    # Normalizar: laravel y django pueden coexistir con php genérico
    tech_list = sorted(detected)
    return {
        "technologies": tech_list,
        "primary": tech_list[0] if tech_list else None,
        "signals_used": ["headers", "cookies", "body_preview", "path_probes"],
    }
