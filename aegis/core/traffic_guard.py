"""
High-Traffic Protection, Rate Limiting, Security Headers & Live Visitor Telemetry.

Designed to keep Commit Guardian resilient under 100K+ user traffic spikes on both
512 MB single-container deployments and horizontally scaled clusters:
  - O(1) memory-bounded sliding-window per-IP rate limiter (max 20,000 tracked IPs)
  - Route-tiered budgets (read/static, chat, heavy scan/autofix)
  - Standard defensive HTTP response headers (X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy)
  - Privacy-preserving live traffic telemetry (hashed unique visitor count, active WebSockets, 429 blocks)
"""

from __future__ import annotations

import hashlib
import os
import secrets
import time
from collections import OrderedDict, deque
from datetime import datetime, timezone
from typing import Deque, Dict, Tuple

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

# Route class -> (max_requests_per_window, window_seconds)
RATE_LIMIT_RULES: Dict[str, Tuple[int, float]] = {
    "scan": (12, 60.0),    # Heavy SAST / repo clone / autofix
    "chat": (45, 60.0),    # AI chat turns
    "read": (240, 60.0),   # Pages, config, metrics, health
}

MAX_TRACKED_IPS = 20_000
MAX_UNIQUE_VISITOR_HASHES = 50_000
MAX_ACTIVE_CHAT_WS = 500


class TrafficTelemetry:
    """Bounded in-memory live traffic & online-session counters for /dashboard."""

    def __init__(self) -> None:
        self._salt = secrets.token_bytes(16)
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.total_requests = 0
        self.page_views = 0
        self.chat_requests = 0
        self.scan_requests = 0
        self.demo_cache_hits = 0
        self.rate_limited_429 = 0
        self.active_ws_users = 0
        self.peak_ws_users = 0
        self._visitor_hashes: OrderedDict[str, float] = OrderedDict()

    def record_request(self, client_ip: str, path: str, bucket: str) -> None:
        self.total_requests += 1
        if path in ("/", "/dashboard"):
            self.page_views += 1
        elif bucket == "chat":
            self.chat_requests += 1
        elif bucket == "scan":
            self.scan_requests += 1

        if client_ip and path != "/health":
            h = hashlib.sha256(self._salt + client_ip.encode("utf-8", errors="ignore")).hexdigest()[:16]
            now = time.monotonic()
            if h in self._visitor_hashes:
                self._visitor_hashes.move_to_end(h)
                self._visitor_hashes[h] = now
            else:
                self._visitor_hashes[h] = now
                if len(self._visitor_hashes) > MAX_UNIQUE_VISITOR_HASHES:
                    self._visitor_hashes.popitem(last=False)

    def ws_connected(self) -> bool:
        if self.active_ws_users >= MAX_ACTIVE_CHAT_WS:
            return False
        self.active_ws_users += 1
        if self.active_ws_users > self.peak_ws_users:
            self.peak_ws_users = self.active_ws_users
        return True

    def ws_disconnected(self) -> None:
        self.active_ws_users = max(0, self.active_ws_users - 1)

    def snapshot(self) -> Dict[str, object]:
        return {
            "started_at": self.started_at,
            "active_online": self.active_ws_users,
            "peak_online": self.peak_ws_users,
            "unique_visitors": len(self._visitor_hashes),
            "total_requests": self.total_requests,
            "page_views": self.page_views,
            "chat_requests": self.chat_requests,
            "scan_requests": self.scan_requests,
            "demo_cache_hits": self.demo_cache_hits,
            "rate_limited_429": self.rate_limited_429,
        }

    def reset(self) -> None:
        self.total_requests = 0
        self.page_views = 0
        self.chat_requests = 0
        self.scan_requests = 0
        self.demo_cache_hits = 0
        self.rate_limited_429 = 0
        self.active_ws_users = 0
        self.peak_ws_users = 0
        self._visitor_hashes.clear()


class SlidingWindowRateLimiter:
    """Memory-bounded per-(IP, bucket) sliding-window rate limiter."""

    def __init__(self, max_entries: int = MAX_TRACKED_IPS) -> None:
        self._max_entries = max_entries
        self._hits: OrderedDict[Tuple[str, str], Deque[float]] = OrderedDict()

    def allow(self, client_ip: str, bucket: str) -> Tuple[bool, int]:
        limit, window = RATE_LIMIT_RULES.get(bucket, RATE_LIMIT_RULES["read"])
        now = time.monotonic()
        key = (client_ip, bucket)
        q = self._hits.get(key)
        if q is None:
            q = deque()
            self._hits[key] = q
            if len(self._hits) > self._max_entries:
                self._hits.popitem(last=False)
        else:
            self._hits.move_to_end(key)

        cutoff = now - window
        while q and q[0] <= cutoff:
            q.popleft()

        if len(q) >= limit:
            retry_after = max(1, int(window - (now - q[0])) + 1)
            return False, retry_after

        q.append(now)
        return True, 0

    def clear(self) -> None:
        self._hits.clear()


traffic_telemetry = TrafficTelemetry()
rate_limiter = SlidingWindowRateLimiter()


def _extract_client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        first = xff.split(",")[0].strip()
        if first:
            return first
    return request.client.host if request.client else "unknown"


def _classify_bucket(path: str, method: str) -> str:
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        if path.startswith(("/api/scan", "/api/v1/scan", "/api/repo/autofix", "/api/v1/pr")):
            return "scan"
        if path.startswith("/api/chat"):
            return "chat"
    return "read"


def _rate_limit_enabled() -> bool:
    if os.environ.get("AEGIS_ENABLE_RATE_LIMIT") == "1":
        return True
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return False
    return True


class TrafficGuardMiddleware(BaseHTTPMiddleware):
    """Applies per-IP rate limiting, security headers, and bounded live traffic counters."""

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        client_ip = _extract_client_ip(request)
        bucket = _classify_bucket(path, request.method)
        traffic_telemetry.record_request(client_ip, path, bucket)

        if path != "/health" and _rate_limit_enabled():
            allowed, retry_after = rate_limiter.allow(client_ip, bucket)
            if not allowed:
                traffic_telemetry.rate_limited_429 += 1
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "Too many requests — rate limit exceeded. Please retry shortly.",
                        "retry_after_seconds": retry_after,
                        "bucket": bucket,
                    },
                    headers={"Retry-After": str(retry_after)},
                )

        response = await call_next(request)
        # Attach defensive security headers without overriding stricter page-specific CSP
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        return response
