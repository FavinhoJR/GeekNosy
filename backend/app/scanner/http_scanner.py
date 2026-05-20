"""Escaneo HTTP/HTTPS no intrusivo."""

import asyncio
from urllib.parse import urljoin, urlparse

import httpx

from app.config import settings
from app.scanner.route_selector import is_exposure_path

RESPONSE_TYPE_MAP = {
    200: "main",
    301: "redirect",
    302: "redirect",
    303: "redirect",
    307: "redirect",
    308: "redirect",
    403: "blocked",
    404: "not_found",
}


def normalize_domain(domain: str) -> str:
    domain = domain.strip()
    if domain.startswith(("http://", "https://")):
        parsed = urlparse(domain)
        return parsed.netloc or parsed.path.split("/")[0]
    return domain.split("/")[0]


def build_base_url(domain: str) -> str:
    d = normalize_domain(domain)
    return f"https://{d}"


def classify_response(status_code: int) -> str:
    if status_code in RESPONSE_TYPE_MAP:
        return RESPONSE_TYPE_MAP[status_code]
    if 200 <= status_code < 300:
        return "success"
    if 300 <= status_code < 400:
        return "redirect"
    if status_code == 403:
        return "blocked"
    if status_code == 404:
        return "not_found"
    if status_code >= 500:
        return "server_error"
    return "other"


def parse_cookies(set_cookie_headers: list[str], mask_values: bool = True) -> list[dict]:
    """Parsea cookies sin exponer valores en reportes."""
    cookies = []
    for header in set_cookie_headers:
        parts = [p.strip() for p in header.split(";")]
        if not parts:
            continue
        name_value = parts[0].split("=", 1)
        name = name_value[0] if name_value else ""
        flags = {p.split("=")[0].lower(): True for p in parts[1:] if p}
        entry = {
            "name": name,
            "secure": "secure" in flags,
            "httponly": "httponly" in flags,
            "samesite": next(
                (p.split("=", 1)[1] for p in parts[1:] if p.lower().startswith("samesite=")),
                None,
            ),
        }
        if not mask_values and len(name_value) > 1:
            entry["value"] = "[redacted]"
        cookies.append(entry)
    return cookies


def normalize_headers(headers: httpx.Headers) -> dict[str, str]:
    return {k.lower(): v for k, v in headers.items()}


async def fetch_path(
    url: str,
    path: str = "/",
    profile: str = "core",
    follow_redirects: bool = True,
    method: str = "GET",
    max_redirects: int | None = None,
    capture_body_preview: bool = False,
) -> dict:
    """
    Solicitud HTTP/HTTPS defensiva (GET o HEAD).
    No descarga contenido completo en rutas sensibles.
    """
    exposure = is_exposure_path(path)
    if exposure:
        method = "HEAD"
        capture_body_preview = False
        follow_redirects = True
        max_redirects = min(max_redirects or settings.max_redirects, 3)

    max_hops = max_redirects if max_redirects is not None else settings.max_redirects
    timeout = settings.path_timeout if path != "/" else settings.scan_timeout

    redirect_chain: list[dict] = []
    headers_found: dict[str, str] = {}
    cookies: list[dict] = []
    final_url = url
    status_code = 0
    error = None
    content_type = None
    content_length = None
    body_preview = ""

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            verify=True,
            headers={"User-Agent": settings.user_agent},
        ) as client:
            current = url
            hops = 0
            while hops <= max_hops:
                req_method = method if hops == 0 else "GET"
                if exposure:
                    req_method = "HEAD"

                resp = await client.request(req_method, current)
                redirect_chain.append(
                    {
                        "url": str(current),
                        "status_code": resp.status_code,
                        "location": resp.headers.get("location"),
                    }
                )
                if (
                    follow_redirects
                    and resp.status_code in (301, 302, 303, 307, 308)
                    and resp.headers.get("location")
                    and hops < max_hops
                ):
                    current = urljoin(str(current), resp.headers["location"])
                    hops += 1
                    continue

                status_code = resp.status_code
                final_url = str(resp.url) if hasattr(resp, "url") else str(current)
                headers_found = normalize_headers(resp.headers)
                content_type = headers_found.get("content-type")
                cl = headers_found.get("content-length")
                content_length = int(cl) if cl and cl.isdigit() else None

                set_cookies = []
                if hasattr(resp.headers, "get_list"):
                    set_cookies = resp.headers.get_list("set-cookie")
                elif "set-cookie" in headers_found:
                    set_cookies = [headers_found["set-cookie"]]
                cookies = parse_cookies(set_cookies)

                if capture_body_preview and method == "GET" and not exposure:
                    try:
                        text = resp.text[: settings.max_body_preview]
                        body_preview = text
                    except Exception:
                        body_preview = ""
                break
    except httpx.HTTPError as e:
        error = str(e)
        status_code = 0

    response_type = classify_response(status_code)
    if path in ("/", "") and status_code == 200:
        response_type = "main"

    return {
        "url_evaluated": url,
        "path": path,
        "profile": profile,
        "final_url": final_url,
        "http_code": status_code,
        "response_type": response_type,
        "redirect_chain": redirect_chain,
        "headers": headers_found,
        "cookies": cookies,
        "content_type": content_type,
        "content_length": content_length,
        "method": method if not exposure else "HEAD",
        "body_preview": body_preview if capture_body_preview else None,
        "error": error,
    }


async def fetch_url(url: str, follow_redirects: bool = True) -> dict:
    """Compatibilidad: fetch ruta raíz."""
    return await fetch_path(url, path="/", profile="core", follow_redirects=follow_redirects)


async def fetch_paths_batch(
    domain: str,
    path_items: list[tuple[str, str]],
    skip_paths: set[str] | None = None,
) -> list[dict]:
    """Evalúa rutas con rate limit entre solicitudes."""
    base = build_base_url(domain)
    skip_paths = skip_paths or set()
    results: list[dict] = []

    for path, profile in path_items:
        norm = path if path.startswith("/") else f"/{path}"
        if norm in skip_paths:
            continue
        url = base.rstrip("/") + (norm if norm != "/" else "/")
        capture_body = norm in ("/", "")
        result = await fetch_path(
            url,
            path=norm,
            profile=profile,
            capture_body_preview=capture_body,
        )
        result["_domain"] = domain
        results.append(result)
        await asyncio.sleep(settings.path_rate_limit_ms / 1000.0)

    return results


async def check_http_to_https_redirect(domain: str) -> dict:
    d = normalize_domain(domain)
    http_url = f"http://{d}/"
    try:
        async with httpx.AsyncClient(
            timeout=settings.scan_timeout,
            follow_redirects=False,
            verify=False,
            headers={"User-Agent": settings.user_agent},
        ) as client:
            resp = await client.get(http_url)
            location = resp.headers.get("location", "")
            redirects_to_https = (
                resp.status_code in (301, 302, 303, 307, 308)
                and location.lower().startswith("https://")
            )
            return {
                "http_url": http_url,
                "status_code": resp.status_code,
                "location": location,
                "redirects_to_https": redirects_to_https,
            }
    except httpx.HTTPError as e:
        return {"http_url": http_url, "error": str(e), "redirects_to_https": False}


async def fetch_well_known(domain: str, path: str) -> dict:
    base = build_base_url(domain)
    url = urljoin(base, path)
    result = await fetch_path(url, path=path, profile="core")
    return {
        "path": path,
        "url": url,
        "found": result["http_code"] == 200,
        "http_code": result["http_code"],
    }
