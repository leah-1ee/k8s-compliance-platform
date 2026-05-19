from __future__ import annotations

import os
from typing import Any

import httpx
from fastapi import APIRouter, Cookie, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

from app import storage


GRAFANA_URL = os.getenv("GRAFANA_URL_INTERNAL", "http://grafana.monitoring.svc.cluster.local:3000").rstrip("/")
SESSION_COOKIE_NAME = "compliance_ai_session"
router = APIRouter()


@router.api_route("/grafana-ui", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def grafana_ui_root() -> RedirectResponse:
    return RedirectResponse("/grafana-ui/", status_code=307)


@router.api_route("/grafana-ui/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def grafana_ui_proxy(
    request: Request,
    path: str,
    compliance_ai_session: str | None = Cookie(default=None),
) -> Response:
    user = storage.get_user_by_session(compliance_ai_session or "")
    if user is None:
        return JSONResponse(status_code=401, content={"error": "login required"})

    upstream_path = f"/grafana-ui/{path}".rstrip("/") if path else "/grafana-ui/"
    if request.url.query:
        upstream_path = f"{upstream_path}?{request.url.query}"
    try:
        response = await _forward_grafana_request(
            request,
            upstream_path=upstream_path,
            user=user,
        )
    except httpx.HTTPError as error:
        return JSONResponse(status_code=502, content={"error": f"Grafana request failed: {error}"})

    headers = _response_headers(response)
    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=headers,
        media_type=response.headers.get("content-type"),
    )


async def _forward_grafana_request(request: Request, upstream_path: str, user: dict[str, Any]) -> httpx.Response:
    body = await request.body()
    headers = _request_headers(request, user)
    async with httpx.AsyncClient(base_url=GRAFANA_URL, timeout=30, follow_redirects=False) as client:
        return await client.request(
            request.method,
            upstream_path,
            content=body if body else None,
            headers=headers,
        )


def _request_headers(request: Request, user: dict[str, Any]) -> dict[str, str]:
    headers: dict[str, str] = {
        "X-WEBAUTH-USER": str(user.get("email") or user.get("id") or ""),
        "X-WEBAUTH-EMAIL": str(user.get("email") or ""),
        "X-WEBAUTH-NAME": str(user.get("name") or user.get("email") or ""),
        "X-Forwarded-Host": request.headers.get("host", ""),
        "X-Forwarded-Proto": request.url.scheme,
        "X-Forwarded-Prefix": "/grafana-ui",
    }
    for key in ("accept", "accept-encoding", "content-type", "cookie", "user-agent"):
        value = request.headers.get(key)
        if value:
            headers[key] = value
    return headers


def _response_headers(response: httpx.Response) -> dict[str, str]:
    headers: dict[str, str] = {}
    for key, value in response.headers.items():
        lower = key.lower()
        if lower in {"content-length", "content-encoding", "transfer-encoding", "connection"}:
            continue
        if lower == "location":
            headers[key] = _rewrite_location(value)
        else:
            headers[key] = value
    return headers


def _rewrite_location(value: str) -> str:
    if value.startswith(GRAFANA_URL):
        return value.replace(GRAFANA_URL, "", 1) or "/grafana-ui/"
    if value.startswith("/") and not value.startswith("/grafana-ui"):
        return f"/grafana-ui{value}"
    return value
