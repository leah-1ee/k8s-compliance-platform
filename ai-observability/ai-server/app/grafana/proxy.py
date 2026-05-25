from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response
from slowapi import Limiter

from app.grafana.promql_inject import PromQLInjectionError, inject_cluster_label


PROMETHEUS_URL = os.getenv(
    "PROMETHEUS_URL",
    "http://monitoring-kube-prometheus-prometheus.monitoring.svc.cluster.local:9090",
).rstrip("/")
AUDIT_LOG_PATH = Path(os.getenv("GRAFANA_PROXY_AUDIT_LOG", "/var/log/proxy/audit.log"))
PROMETHEUS_PROXY_RATE_LIMIT = os.getenv("GRAFANA_PROMETHEUS_PROXY_RATE_LIMIT", "600/minute")
logger = logging.getLogger("ai-server.grafana.proxy")
router = APIRouter()


def _rate_limit_key(request: Request) -> str:
    token = _bearer_token(request)
    payload = _decode_jwt_payload_without_verification(token)
    user_id = str(payload.get("user_id") or payload.get("sub") or "").strip()
    return user_id or (request.client.host if request.client else "anonymous")


limiter = Limiter(key_func=_rate_limit_key)


@router.api_route("/grafana/prometheus/{cluster_id}/{path:path}", methods=["GET", "POST"])
@limiter.limit(PROMETHEUS_PROXY_RATE_LIMIT)
async def prometheus_proxy(request: Request, cluster_id: str, path: str) -> Response:
    user_id = ""
    original_query = ""
    injected_query = ""
    status_code = 500
    try:
        claims = _verify_proxy_jwt(_bearer_token(request))
        user_id = str(claims["user_id"])
        token_cluster_id = str(claims["cluster_id"])
        if cluster_id != token_cluster_id:
            status_code = 403
            return JSONResponse(status_code=status_code, content={"error": "cluster_id mismatch"})

        outbound_url = f"{PROMETHEUS_URL}/{path.lstrip('/')}"
        params = list(request.query_params.multi_items())
        body = await request.body()
        headers = _forward_headers(request)

        if request.method == "GET":
            params, original_query, injected_query = _rewrite_query_params(params, cluster_id)
            response = await _forward_request("GET", outbound_url, params=params, headers=headers)
        else:
            content_type = request.headers.get("content-type", "")
            if "application/x-www-form-urlencoded" in content_type:
                data, original_query, injected_query = _rewrite_form_items(
                    parse_qsl(body.decode("utf-8"), keep_blank_values=True),
                    cluster_id,
                )
                response = await _forward_request(
                    "POST",
                    outbound_url,
                    params=params,
                    content=urlencode(data).encode("utf-8"),
                    headers=headers,
                )
            else:
                params, original_query, injected_query = _rewrite_query_params(params, cluster_id)
                response = await _forward_request("POST", outbound_url, params=params, content=body, headers=headers)

        status_code = response.status_code
        return Response(
            content=response.content,
            status_code=response.status_code,
            media_type=response.headers.get("content-type"),
            headers=_response_headers(response),
        )
    except PromQLInjectionError as error:
        status_code = 400
        return JSONResponse(status_code=status_code, content={"error": str(error)})
    except AuthError as error:
        status_code = error.status_code
        return JSONResponse(status_code=status_code, content={"error": error.message})
    except httpx.HTTPError as error:
        status_code = 502
        return JSONResponse(status_code=status_code, content={"error": f"Prometheus request failed: {error}"})
    except Exception as error:
        logger.exception("Grafana Prometheus proxy failed cluster_id=%s path=%s", cluster_id, path)
        status_code = 500
        return JSONResponse(status_code=status_code, content={"error": f"Prometheus proxy failed: {error}"})
    finally:
        _write_audit_log(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "user_id": user_id,
                "cluster_id": cluster_id,
                "original_query": original_query,
                "injected_query": injected_query,
                "status_code": status_code,
            }
        )


async def _forward_request(method: str, url: str, **kwargs: Any) -> httpx.Response:
    async with httpx.AsyncClient(timeout=10) as client:
        return await client.request(method, url, **kwargs)


def _rewrite_query_params(params: list[tuple[str, str]], cluster_id: str) -> tuple[list[tuple[str, str]], str, str]:
    rewritten: list[tuple[str, str]] = []
    original_query = ""
    injected_query = ""
    for key, value in params:
        if key == "query":
            original_query = value
            injected_query = inject_cluster_label(value, cluster_id)
            rewritten.append((key, injected_query))
        elif key == "match[]":
            original_query = original_query or value
            injected = inject_cluster_label(value, cluster_id)
            injected_query = injected_query or injected
            rewritten.append((key, injected))
        else:
            rewritten.append((key, value))
    return rewritten, original_query, injected_query


def _rewrite_form_items(items: list[tuple[str, Any]], cluster_id: str) -> tuple[list[tuple[str, Any]], str, str]:
    rewritten: list[tuple[str, Any]] = []
    original_query = ""
    injected_query = ""
    for key, value in items:
        text_value = str(value)
        if key == "query":
            original_query = text_value
            injected_query = inject_cluster_label(text_value, cluster_id)
            rewritten.append((key, injected_query))
        elif key == "match[]":
            original_query = original_query or text_value
            injected = inject_cluster_label(text_value, cluster_id)
            injected_query = injected_query or injected
            rewritten.append((key, injected))
        else:
            rewritten.append((key, value))
    return rewritten, original_query, injected_query


def _bearer_token(request: Request) -> str:
    authorization = request.headers.get("authorization", "")
    if not authorization.lower().startswith("bearer "):
        return ""
    return authorization.split(" ", 1)[1].strip()


def _verify_proxy_jwt(token: str) -> dict[str, Any]:
    secret = os.getenv("JWT_SECRET", "").strip()
    if not secret:
        raise AuthError(503, "JWT_SECRET is not configured")
    if not token:
        raise AuthError(401, "missing bearer token")
    parts = token.split(".")
    if len(parts) != 3:
        raise AuthError(401, "invalid token")
    header = _json_b64decode(parts[0])
    payload = _json_b64decode(parts[1])
    if header.get("alg") != "HS256":
        raise AuthError(401, "invalid token algorithm")
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    expected = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(_b64decode(parts[2]), expected):
        raise AuthError(401, "invalid token signature")
    expires_at = int(payload.get("exp") or 0)
    if expires_at and expires_at < int(time.time()):
        raise AuthError(401, "expired token")
    user_id = str(payload.get("user_id") or payload.get("sub") or "").strip()
    cluster_id = str(payload.get("cluster_id") or "").strip()
    if not user_id or not cluster_id:
        raise AuthError(401, "token missing user_id or cluster_id")
    return {"user_id": user_id, "cluster_id": cluster_id}


def _decode_jwt_payload_without_verification(token: str) -> dict[str, Any]:
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        return _json_b64decode(parts[1])
    except (ValueError, json.JSONDecodeError):
        return {}


def _json_b64decode(value: str) -> dict[str, Any]:
    decoded = _b64decode(value)
    parsed = json.loads(decoded.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("JWT segment must be an object")
    return parsed


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(f"{value}{padding}".encode("ascii"))


def _forward_headers(request: Request) -> dict[str, str]:
    headers: dict[str, str] = {}
    content_type = request.headers.get("content-type")
    accept = request.headers.get("accept")
    if content_type:
        headers["content-type"] = content_type
    if accept:
        headers["accept"] = accept
    return headers


def _response_headers(response: httpx.Response) -> dict[str, str]:
    headers: dict[str, str] = {}
    for key in ("cache-control",):
        value = response.headers.get(key)
        if value:
            headers[key] = value
    return headers


def _write_audit_log(entry: dict[str, Any]) -> None:
    try:
        AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_LOG_PATH.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, separators=(",", ":"), ensure_ascii=False) + "\n")
    except OSError:
        pass


class AuthError(Exception):
    def __init__(self, status_code: int, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.message = message
