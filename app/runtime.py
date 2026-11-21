"""Runtime layer shared by every service in this portfolio.

Six controls, the same six every time: constant-time API-key auth, per-caller
sliding-window rate limiting, request IDs, one JSON log line per request,
Prometheus metrics, and a readiness probe that fails closed.

None of it is clever. It is the part that has to hold after the demo.
"""
from __future__ import annotations

import hmac
import json
import logging
import os
import signal
import sys
import time
import uuid
from collections import defaultdict, deque
from typing import Callable

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

SERVICE = os.environ.get("SERVICE_NAME", "service")
VERSION = os.environ.get("SERVICE_VERSION", "1.0.0")
RATE_LIMIT = int(os.environ.get("RATE_LIMIT_PER_MIN", "120"))

OPEN_PATHS = {"/healthz", "/readyz", "/version", "/metrics"}


class JsonFormatter(logging.Formatter):
    """One JSON object per line, so a log shipper needs no parser config."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": round(record.created, 3),
            "level": record.levelname,
            "service": SERVICE,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key in ("request_id", "method", "path", "status", "duration_ms", "caller"):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, separators=(",", ":"))


def configure_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(os.environ.get("LOG_LEVEL", "INFO"))


class RateLimiter:
    """Sliding window per caller. In-memory on purpose: one process, one budget.

    A shared store replaces this the moment there is more than one replica.
    """

    def __init__(self, limit: int = RATE_LIMIT, window: float = 60.0) -> None:
        self.limit = limit
        self.window = window
        self.hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, caller: str) -> bool:
        now = time.monotonic()
        queue = self.hits[caller]
        while queue and now - queue[0] > self.window:
            queue.popleft()
        if len(queue) >= self.limit:
            return False
        queue.append(now)
        return True

    def retry_after(self, caller: str) -> int:
        queue = self.hits[caller]
        if not queue:
            return 1
        return max(1, int(self.window - (time.monotonic() - queue[0])))


class Metrics:
    def __init__(self) -> None:
        self.requests: dict[tuple[str, str, int], int] = defaultdict(int)
        self.rejected: dict[str, int] = defaultdict(int)
        self.started = time.time()

    def render(self) -> str:
        lines = [
            "# HELP http_requests_total Requests handled, by method, path and status.",
            "# TYPE http_requests_total counter",
        ]
        for (method, path, status), count in sorted(self.requests.items()):
            lines.append(
                f'http_requests_total{{method="{method}",path="{path}",status="{status}"}} {count}'
            )
        lines += [
            "# HELP http_requests_rejected_total Requests refused before handling.",
            "# TYPE http_requests_rejected_total counter",
        ]
        for reason, count in sorted(self.rejected.items()):
            lines.append(f'http_requests_rejected_total{{reason="{reason}"}} {count}')
        lines += [
            "# HELP process_uptime_seconds Seconds since the process started.",
            "# TYPE process_uptime_seconds gauge",
            f"process_uptime_seconds {time.time() - self.started:.0f}",
        ]
        return "\n".join(lines) + "\n"


def api_keys() -> list[str]:
    """Fail closed: no configured key means the service refuses to start."""
    raw = os.environ.get("SECOPS_API_KEYS", "")
    keys = [item.strip() for item in raw.split(",") if item.strip()]
    if not keys:
        raise RuntimeError(
            "SECOPS_API_KEYS is unset. Refusing to start unauthenticated; "
            "set it to a comma-separated list of keys."
        )
    return keys


def _presented_key(request: Request) -> str:
    header = request.headers.get("x-api-key")
    if header:
        return header
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return ""


def _identify(presented: str, keys: list[str]) -> str | None:
    for key in keys:
        if hmac.compare_digest(presented, key):
            return key[:6]
    return None


def install_runtime(app: FastAPI, ready_check: Callable[[], bool] | None = None) -> None:
    state = {
        "limiter": RateLimiter(),
        "metrics": Metrics(),
        "keys": api_keys(),
        "ready": True,
        "ready_check": ready_check,
    }
    app.state.runtime = state
    log = logging.getLogger("runtime")

    def _drain(*_args: object) -> None:
        state["ready"] = False
        log.info("readiness withdrawn, draining")

    signal.signal(signal.SIGTERM, _drain)

    @app.middleware("http")
    async def _middleware(request: Request, call_next):  # type: ignore[no-untyped-def]
        metrics: Metrics = state["metrics"]
        path = request.url.path
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:12]
        started = time.perf_counter()

        if path not in OPEN_PATHS:
            presented = _presented_key(request)
            if not presented:
                metrics.rejected["missing_key"] += 1
                return JSONResponse(
                    {"error": "unauthorized", "request_id": request_id}, status_code=401
                )
            caller = _identify(presented, state["keys"])
            if caller is None:
                metrics.rejected["bad_key"] += 1
                return JSONResponse(
                    {"error": "unauthorized", "request_id": request_id}, status_code=401
                )
            limiter: RateLimiter = state["limiter"]
            if not limiter.allow(caller):
                metrics.rejected["rate_limited"] += 1
                return JSONResponse(
                    {"error": "rate_limited", "request_id": request_id},
                    status_code=429,
                    headers={"Retry-After": str(limiter.retry_after(caller))},
                )
        else:
            caller = "open"

        response = await call_next(request)
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        metrics.requests[(request.method, path, response.status_code)] += 1
        response.headers["x-request-id"] = request_id
        log.info(
            "request",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": path,
                "status": response.status_code,
                "duration_ms": duration_ms,
                "caller": caller,
            },
        )
        return response

    @app.get("/healthz", include_in_schema=False)
    def healthz():
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    def readyz():
        if not state["ready"]:
            return JSONResponse({"status": "draining"}, status_code=503)
        check = state["ready_check"]
        if check is not None and not check():
            return JSONResponse({"status": "not_ready"}, status_code=503)
        return {"status": "ready"}

    @app.get("/version", include_in_schema=False)
    def version():
        return {
            "service": SERVICE,
            "version": VERSION,
            "commit": os.environ.get("GIT_COMMIT", "dev"),
        }

    @app.get("/metrics", include_in_schema=False)
    def metrics():
        return PlainTextResponse(state["metrics"].render())
