from __future__ import annotations

import os
import unicodedata
from typing import Any

import httpx
from fastapi import APIRouter, Cookie, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

from app import storage
from app.grafana.admin_session import admin_user_from_token


GRAFANA_URL = os.getenv("GRAFANA_URL_INTERNAL", "http://grafana.monitoring.svc.cluster.local:3000").rstrip("/")
SESSION_COOKIE_NAME = "compliance_ai_session"
router = APIRouter()


@router.api_route("/grafana-ui", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def grafana_ui_root() -> RedirectResponse:
    return RedirectResponse("/grafana-ui/", status_code=307)


@router.api_route("/public/{path:path}", methods=["GET"])
async def grafana_public_asset_proxy(
    request: Request,
    path: str,
    compliance_ai_session: str | None = Cookie(default=None),
    kubeowl_admin_grafana: str | None = Cookie(default=None),
) -> Response:
    return await _proxy_grafana_path(
        request=request,
        path=f"public/{path}",
        compliance_ai_session=compliance_ai_session,
        kubeowl_admin_grafana=kubeowl_admin_grafana,
    )


@router.api_route(
    "/api/login/ping",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
@router.api_route(
    "/api/plugins/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
@router.api_route(
    "/api/user/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
@router.api_route(
    "/api/ds/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
@router.api_route(
    "/api/annotations",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
@router.api_route(
    "/api/annotations/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
@router.api_route(
    "/apis/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
@router.api_route("/avatar/{path:path}", methods=["GET"])
async def grafana_root_api_proxy(
    request: Request,
    compliance_ai_session: str | None = Cookie(default=None),
    kubeowl_admin_grafana: str | None = Cookie(default=None),
) -> Response:
    return await _proxy_grafana_path(
        request=request,
        path=request.url.path.lstrip("/"),
        compliance_ai_session=compliance_ai_session,
        kubeowl_admin_grafana=kubeowl_admin_grafana,
    )


@router.api_route("/grafana-ui/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def grafana_ui_proxy(
    request: Request,
    path: str,
    compliance_ai_session: str | None = Cookie(default=None),
    kubeowl_admin_grafana: str | None = Cookie(default=None),
) -> Response:
    return await _proxy_grafana_path(
        request=request,
        path=path,
        compliance_ai_session=compliance_ai_session,
        kubeowl_admin_grafana=kubeowl_admin_grafana,
    )


async def _proxy_grafana_path(
    request: Request,
    path: str,
    compliance_ai_session: str | None,
    kubeowl_admin_grafana: str | None,
) -> Response:
    user = admin_user_from_token(kubeowl_admin_grafana)
    if user is None:
        user = storage.get_user_by_session(compliance_ai_session or "")
    if user is None:
        return JSONResponse(status_code=401, content={"error": "login required"})

    upstream_path = _upstream_path(path, request.url.query)
    try:
        response = await _forward_grafana_request(
            request,
            upstream_path=upstream_path,
            user=user,
        )
    except httpx.HTTPError as error:
        return JSONResponse(status_code=502, content={"error": f"Grafana request failed: {error}"})

    content = _response_content(response)
    headers = _response_headers(response)
    return Response(
        content=content,
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
    email = _ascii_header_value(user.get("email") or user.get("id") or "")
    name = _ascii_header_value(user.get("name") or user.get("email") or "") or email
    headers: dict[str, str] = {
        "X-WEBAUTH-USER": email,
        "X-WEBAUTH-EMAIL": email,
        "X-WEBAUTH-NAME": name,
        "X-Forwarded-Host": _ascii_header_value(request.headers.get("host", "")),
        "X-Forwarded-Proto": _ascii_header_value(request.url.scheme),
        "X-Forwarded-Prefix": "/grafana-ui",
    }
    for key in ("accept", "content-type", "cookie", "user-agent"):
        value = request.headers.get(key)
        if value:
            headers[key] = _ascii_header_value(value)
    return headers


def _upstream_path(path: str, query: str) -> str:
    upstream_path = f"/{path}".rstrip("/") if path else "/"
    if not upstream_path:
        upstream_path = "/"
    if query:
        upstream_path = f"{upstream_path}?{query}"
    return upstream_path


def _ascii_header_value(value: Any) -> str:
    normalized = unicodedata.normalize("NFKD", str(value or ""))
    return normalized.encode("ascii", "ignore").decode("ascii").strip()


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


def _response_content(response: httpx.Response) -> bytes:
    content_type = response.headers.get("content-type", "")
    lower_content_type = content_type.lower()
    if not any(
        item in lower_content_type
        for item in ("text/html", "javascript", "text/css", "application/json")
    ):
        return response.content
    try:
        text = response.content.decode(response.encoding or "utf-8")
    except UnicodeDecodeError:
        return response.content
    if "text/html" in lower_content_type:
        text = _rewrite_html(text)
    else:
        text = _rewrite_asset_text(text)
    return text.encode(response.encoding or "utf-8")


def _rewrite_html(html: str) -> str:
    replacements = {
        '<base href="/">': '<base href="/grafana-ui/">',
        '<base href="/grafana-ui//">': '<base href="/grafana-ui/">',
        'src="/public/': 'src="/grafana-ui/public/',
        'href="/public/': 'href="/grafana-ui/public/',
        'content="/public/': 'content="/grafana-ui/public/',
        'url(/public/': 'url(/grafana-ui/public/',
        'src="public/': 'src="/grafana-ui/public/',
        'href="public/': 'href="/grafana-ui/public/',
        '"appSubUrl":""': '"appSubUrl":"/grafana-ui"',
        '"appSubUrl":"/"': '"appSubUrl":"/grafana-ui"',
    }
    rewritten = html
    for old, new in replacements.items():
        rewritten = rewritten.replace(old, new)
    return rewritten


def _rewrite_asset_text(text: str) -> str:
    replacements = {
        '"/public/build/': '"/grafana-ui/public/build/',
        "'/public/build/": "'/grafana-ui/public/build/",
        "`/public/build/": "`/grafana-ui/public/build/",
        '=/public/build/': '=/grafana-ui/public/build/',
        '(/public/build/': '(/grafana-ui/public/build/',
        'url(/public/': 'url(/grafana-ui/public/',
    }
    rewritten = text
    for old, new in replacements.items():
        rewritten = rewritten.replace(old, new)
    return rewritten


def _rewrite_location(value: str) -> str:
    rewritten = value
    if value.startswith(GRAFANA_URL):
        rewritten = value.replace(GRAFANA_URL, "", 1) or "/"
    if rewritten.startswith("/") and not rewritten.startswith("/grafana-ui"):
        return f"/grafana-ui{rewritten}"
    return rewritten
