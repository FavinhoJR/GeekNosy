"""Authentication, authorization confirmation and API request throttling."""

import asyncio
import hashlib
import hmac
import time
from collections import defaultdict, deque

from fastapi import Depends, Header, HTTPException, Request, status

from app.config import settings


class SlidingWindowLimiter:
    def __init__(self):
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def check(self, key: str, limit: int, window_seconds: float = 60.0) -> None:
        if limit <= 0:
            return
        now = time.monotonic()
        async with self._lock:
            events = self._events[key]
            while events and events[0] <= now - window_seconds:
                events.popleft()
            if len(events) >= limit:
                retry_after = max(1, int(window_seconds - (now - events[0])))
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Límite de solicitudes excedido",
                    headers={"Retry-After": str(retry_after)},
                )
            events.append(now)


api_limiter = SlidingWindowLimiter()


def _key_fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


async def require_api_key(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> str:
    """Require an API key when keys are configured; otherwise use local development identity."""
    if settings.api_keys:
        if not x_api_key or not any(
            hmac.compare_digest(x_api_key, configured) for configured in settings.api_keys
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key inválida o ausente",
            )
        identity = f"key:{_key_fingerprint(x_api_key)}"
    else:
        identity = f"dev:{request.client.host if request.client else 'local'}"

    await api_limiter.check(identity, limit=120)
    return identity


async def optional_identity(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> str:
    if settings.api_keys:
        return await require_api_key(request, x_api_key)
    return f"dev:{request.client.host if request.client else 'local'}"


AuthenticatedIdentity = Depends(require_api_key)
