"""Strict target normalization and SSRF/scope protection."""

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

from app.config import settings


class TargetPolicyError(ValueError):
    pass


@dataclass(frozen=True)
class ValidatedTarget:
    hostname: str
    port: int
    scheme: str
    normalized_url: str
    resolved_ips: tuple[str, ...]


def _normalize_hostname(hostname: str) -> str:
    value = hostname.rstrip(".").lower()
    try:
        return value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise TargetPolicyError("Nombre de dominio internacional inválido") from exc


def _ip_is_forbidden(ip: ipaddress._BaseAddress) -> bool:
    return any(
        (
            ip.is_private,
            ip.is_loopback,
            ip.is_link_local,
            ip.is_multicast,
            ip.is_reserved,
            ip.is_unspecified,
        )
    )


def _host_in_scope(hostname: str, ips: tuple[str, ...]) -> bool:
    if settings.allowed_domains:
        domain_allowed = any(
            hostname == allowed.lower().lstrip(".")
            or hostname.endswith("." + allowed.lower().lstrip("."))
            for allowed in settings.allowed_domains
        )
        if not domain_allowed:
            return False
    if settings.allowed_cidrs:
        networks = [ipaddress.ip_network(cidr, strict=False) for cidr in settings.allowed_cidrs]
        if not any(ipaddress.ip_address(ip) in network for ip in ips for network in networks):
            return False
    return True


async def resolve_public_ips(hostname: str, port: int) -> tuple[str, ...]:
    try:
        literal = ipaddress.ip_address(hostname)
        ips = (str(literal),)
    except ValueError:
        loop = asyncio.get_running_loop()
        try:
            records = await asyncio.wait_for(
                loop.getaddrinfo(hostname, port, type=socket.SOCK_STREAM),
                timeout=5,
            )
        except (OSError, asyncio.TimeoutError) as exc:
            raise TargetPolicyError(f"No se pudo resolver el objetivo: {hostname}") from exc
        ips = tuple(sorted({record[4][0] for record in records}))

    if not ips:
        raise TargetPolicyError("El objetivo no tiene direcciones IP resolubles")
    if not settings.allow_private_targets:
        forbidden = [ip for ip in ips if _ip_is_forbidden(ipaddress.ip_address(ip))]
        if forbidden:
            raise TargetPolicyError(
                "Destino privado, local, reservado o link-local bloqueado por política"
            )
    return ips


async def validate_url(url: str, *, expected_host: str | None = None) -> ValidatedTarget:
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        raise TargetPolicyError("Solo se permiten esquemas HTTP y HTTPS")
    if parsed.username or parsed.password:
        raise TargetPolicyError("No se permiten credenciales en la URL")
    if not parsed.hostname:
        raise TargetPolicyError("La URL no contiene un host válido")

    hostname = _normalize_hostname(parsed.hostname)
    if expected_host and hostname != _normalize_hostname(expected_host):
        raise TargetPolicyError("La redirección salió del host autorizado")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port not in settings.allowed_ports:
        raise TargetPolicyError(f"Puerto {port} no autorizado")
    ips = await resolve_public_ips(hostname, port)
    if not _host_in_scope(hostname, ips):
        raise TargetPolicyError("El objetivo está fuera del alcance configurado")

    host_authority = f"[{hostname}]" if ":" in hostname else hostname
    authority = host_authority if port in (80, 443) else f"{host_authority}:{port}"
    normalized = f"{parsed.scheme}://{authority}{parsed.path or '/'}"
    if parsed.query:
        normalized += f"?{parsed.query}"
    return ValidatedTarget(hostname, port, parsed.scheme, normalized, ips)


async def normalize_and_validate_domain(raw: str) -> ValidatedTarget:
    candidate = raw.strip()
    if not candidate:
        raise TargetPolicyError("Dominio vacío")
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    parsed = urlsplit(candidate)
    root = f"{parsed.scheme}://{parsed.netloc}/"
    return await validate_url(root)
