"""Escaneo HTTP/HTTPS no intrusivo."""

import asyncio
import hashlib
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from collections.abc import Awaitable, Callable
from urllib.parse import urljoin, urlparse

import httpx

from app.config import settings
from app.scanner.route_selector import is_exposure_path
from app.target_policy import TargetPolicyError, validate_url

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


class NetworkRateLimiter:
    def __init__(self):
        self._global = asyncio.Semaphore(settings.max_concurrent_requests)
        self._hosts: dict[str, asyncio.Semaphore] = defaultdict(
            lambda: asyncio.Semaphore(settings.max_concurrent_per_host)
        )
        self._last_request: dict[str, float] = {}
        self._lock = asyncio.Lock()

    @asynccontextmanager
    async def slot(self, host: str, requests_per_second: float | None = None):
        rate = requests_per_second or settings.per_host_requests_per_second
        async with self._global, self._hosts[host]:
            async with self._lock:
                now = time.monotonic()
                delay = max(0.0, self._last_request.get(host, 0.0) + (1 / rate) - now)
                if delay:
                    await asyncio.sleep(delay)
                self._last_request[host] = time.monotonic()
            yield


network_limiter = NetworkRateLimiter()


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
        attributes = {}
        for part in parts[1:]:
            if not part:
                continue
            key, _, value = part.partition("=")
            attributes[key.lower()] = value or True
        entry = {
            "name": name,
            "secure": "secure" in attributes,
            "httponly": "httponly" in attributes,
            "samesite": attributes.get("samesite") if isinstance(attributes.get("samesite"), str) else None,
            "domain": attributes.get("domain") if isinstance(attributes.get("domain"), str) else None,
            "path": attributes.get("path") if isinstance(attributes.get("path"), str) else None,
            "max_age": attributes.get("max-age") if isinstance(attributes.get("max-age"), str) else None,
            "expires": attributes.get("expires") if isinstance(attributes.get("expires"), str) else None,
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
    authorized_host: str | None = None,
    requests_per_second: float | None = None,
    request_headers: dict[str, str] | None = None,
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
    body_sha256 = None
    body_bytes_read = 0
    resolved_ips: list[str] = []
    duration_ms = 0.0
    started = time.perf_counter()

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            verify=True,
            transport=httpx.AsyncHTTPTransport(retries=2),
            headers={"User-Agent": settings.user_agent, **(request_headers or {})},
        ) as client:
            current = url
            hops = 0
            while hops <= max_hops:
                validated = await validate_url(current, expected_host=authorized_host)
                authorized_host = authorized_host or validated.hostname
                resolved_ips = list(validated.resolved_ips)
                current = validated.normalized_url
                req_method = method if hops == 0 else "GET"
                if exposure:
                    req_method = "HEAD"

                async with network_limiter.slot(
                    validated.hostname, requests_per_second
                ):
                    async with client.stream(req_method, current) as resp:
                        redirect_chain.append(
                            {
                                "url": str(current),
                                "status_code": resp.status_code,
                                "location": resp.headers.get("location"),
                                "resolved_ips": list(validated.resolved_ips),
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
                        final_url = str(resp.url)
                        headers_found = normalize_headers(resp.headers)
                        content_type = headers_found.get("content-type")
                        cl = headers_found.get("content-length")
                        content_length = int(cl) if cl and cl.isdigit() else None

                        set_cookies = (
                            resp.headers.get_list("set-cookie")
                            if hasattr(resp.headers, "get_list")
                            else []
                        )
                        cookies = parse_cookies(set_cookies)

                        if req_method == "GET" and not exposure:
                            chunks = bytearray()
                            async for chunk in resp.aiter_bytes():
                                remaining = settings.max_response_bytes - len(chunks)
                                if remaining <= 0:
                                    break
                                chunks.extend(chunk[:remaining])
                                if len(chunks) >= settings.max_response_bytes:
                                    break
                            body_bytes_read = len(chunks)
                            body_sha256 = hashlib.sha256(chunks).hexdigest()
                            if capture_body_preview:
                                encoding = resp.encoding or "utf-8"
                                body_preview = bytes(chunks[: settings.max_body_preview]).decode(
                                    encoding, errors="replace"
                                )
                        break
    except (httpx.HTTPError, TargetPolicyError, ValueError) as e:
        error = str(e)
        status_code = 0
    finally:
        duration_ms = round((time.perf_counter() - started) * 1000, 2)

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
        "body_sha256": body_sha256,
        "body_bytes_read": body_bytes_read,
        "resolved_ips": resolved_ips,
        "duration_ms": duration_ms,
        "error": error,
    }


async def fetch_url(url: str, follow_redirects: bool = True) -> dict:
    """Compatibilidad: fetch ruta raíz."""
    return await fetch_path(url, path="/", profile="core", follow_redirects=follow_redirects)


async def fetch_paths_batch(
    domain: str,
    path_items: list[tuple[str, str]],
    skip_paths: set[str] | None = None,
    requests_per_second: float | None = None,
    cancel_callback: Callable[[], Awaitable[bool] | bool] | None = None,
    request_headers: dict[str, str] | None = None,
) -> list[dict]:
    """Evalúa rutas con rate limit entre solicitudes."""
    base = build_base_url(domain)
    skip_paths = skip_paths or set()
    jobs = []
    for path, profile in path_items:
        norm = path if path.startswith("/") else f"/{path}"
        if norm in skip_paths:
            continue
        url = base.rstrip("/") + (norm if norm != "/" else "/")
        capture_body = norm in ("/", "")
        jobs.append(
            {
                "url": url,
                "path": norm,
                "profile": profile,
                "capture_body_preview": capture_body,
            }
        )

    results = []
    for offset in range(0, len(jobs), settings.max_concurrent_per_host):
        if cancel_callback:
            state = cancel_callback()
            if asyncio.iscoroutine(state):
                state = await state
            if state:
                raise asyncio.CancelledError("Cancelación solicitada")
        batch = await asyncio.gather(*[
            fetch_path(
                item["url"],
                path=item["path"],
                profile=item["profile"],
                capture_body_preview=item["capture_body_preview"],
                authorized_host=normalize_domain(domain),
                requests_per_second=requests_per_second,
                request_headers=request_headers,
            )
            for item in jobs[offset : offset + settings.max_concurrent_per_host]
        ])
        for result in batch:
            result["_domain"] = domain
            results.append(result)
    return results


async def check_http_to_https_redirect(domain: str) -> dict:
    d = normalize_domain(domain)
    http_url = f"http://{d}/"
    try:
        async with httpx.AsyncClient(
            timeout=settings.scan_timeout,
            follow_redirects=False,
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
