"""Escaneo HTTP/HTTPS no intrusivo."""

import re
from urllib.parse import urljoin, urlparse

import httpx

from app.config import settings

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


def parse_cookies(set_cookie_headers: list[str]) -> list[dict]:
    cookies = []
    for header in set_cookie_headers:
        parts = [p.strip() for p in header.split(";")]
        if not parts:
            continue
        name_value = parts[0].split("=", 1)
        name = name_value[0] if name_value else ""
        value = name_value[1] if len(name_value) > 1 else ""
        flags = {p.split("=")[0].lower(): True for p in parts[1:] if p}
        cookies.append(
            {
                "name": name,
                "value": value[:50] + "..." if len(value) > 50 else value,
                "secure": "secure" in flags,
                "httponly": "httponly" in flags,
                "samesite": next(
                    (p.split("=", 1)[1] for p in parts[1:] if p.lower().startswith("samesite=")),
                    None,
                ),
            }
        )
    return cookies


def normalize_headers(headers: httpx.Headers) -> dict[str, str]:
    return {k.lower(): v for k, v in headers.items()}


async def fetch_url(
    url: str,
    follow_redirects: bool = True,
) -> dict:
    """Obtiene una URL de forma no intrusiva."""
    redirect_chain: list[dict] = []
    headers_found: dict[str, str] = {}
    cookies: list[dict] = []
    final_url = url
    status_code = 0
    error = None

    try:
        async with httpx.AsyncClient(
            timeout=settings.scan_timeout,
            follow_redirects=False,
            verify=True,
            headers={"User-Agent": settings.user_agent},
        ) as client:
            current = url
            hops = 0
            while hops < settings.max_redirects:
                resp = await client.get(current)
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
                ):
                    current = urljoin(str(current), resp.headers["location"])
                    hops += 1
                    continue
                status_code = resp.status_code
                final_url = str(resp.url) if hasattr(resp, "url") else str(current)
                headers_found = normalize_headers(resp.headers)
                set_cookies = []
                if hasattr(resp.headers, "get_list"):
                    set_cookies = resp.headers.get_list("set-cookie")
                elif "set-cookie" in resp.headers:
                    raw = resp.headers.get("set-cookie", "")
                    set_cookies = [raw] if raw else []
                cookies = parse_cookies(set_cookies)
                break
    except httpx.HTTPError as e:
        error = str(e)
        status_code = 0

    response_type = classify_response(status_code)

    return {
        "url_evaluated": url,
        "final_url": final_url,
        "http_code": status_code,
        "response_type": response_type,
        "redirect_chain": redirect_chain,
        "headers": headers_found,
        "cookies": cookies,
        "error": error,
    }


async def check_http_to_https_redirect(domain: str) -> dict:
    """Verifica redirección HTTP -> HTTPS."""
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
    result = await fetch_url(url, follow_redirects=True)
    return {
        "path": path,
        "url": url,
        "found": result["http_code"] == 200,
        "http_code": result["http_code"],
    }
