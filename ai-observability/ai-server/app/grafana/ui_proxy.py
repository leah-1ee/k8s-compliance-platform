from __future__ import annotations

import os
import re
import unicodedata
from typing import Any

import httpx
from fastapi import APIRouter, Cookie, Request, WebSocket
from fastapi.responses import JSONResponse, RedirectResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from app import storage
from app.grafana.admin_session import admin_user_from_token


GRAFANA_URL = os.getenv("GRAFANA_URL_INTERNAL", "http://grafana.monitoring.svc.cluster.local:3000").rstrip("/")
SESSION_COOKIE_NAME = "compliance_ai_session"
router = APIRouter()
GRAFANA_PUBLIC_DIRS = ("build", "fonts", "img", "plugins", "app", "locales")
GRAFANA_PUBLIC_PATH_RE = re.compile(
    rf"(?<!/grafana-ui)/public/({'|'.join(GRAFANA_PUBLIC_DIRS)})/"
)
GRAFANA_RELATIVE_PUBLIC_PATH_RE = re.compile(
    rf"(?P<prefix>[\"'`=(])public/({'|'.join(GRAFANA_PUBLIC_DIRS)})/"
)
GRAFANA_LIVE_WEBSOCKET_PATHS = {"/api/live/ws", "/grafana-ui/api/live/ws"}


class GrafanaLiveWebSocketMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "websocket" and scope.get("path") in GRAFANA_LIVE_WEBSOCKET_PATHS:
            await send({"type": "websocket.accept"})
            await send({"type": "websocket.close", "code": 1000})
            return
        await self.app(scope, receive, send)


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
    "/api/access-control/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
@router.api_route(
    "/api/datasources/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
@router.api_route(
    "/api/login/ping",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
@router.api_route(
    "/api/frontend/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
@router.api_route(
    "/api/library-elements/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
@router.api_route(
    "/api/library-elements",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
@router.api_route(
    "/api/live/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
@router.api_route(
    "/api/org",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
@router.api_route(
    "/api/org/{path:path}",
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
    "/api/search",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
@router.api_route(
    "/api/search/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
@router.api_route(
    "/api/folders",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
@router.api_route(
    "/api/folders/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
@router.api_route(
    "/api/dashboards/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
@router.api_route(
    "/api/browse/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
@router.api_route(
    "/api/ds/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
@router.api_route(
    "/api/prometheus/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
@router.api_route(
    "/api/query-history/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
@router.api_route(
    "/api/query-history",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
@router.api_route(
    "/api/ruler/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
@router.api_route(
    "/api/frontend-metrics",
    methods=["POST"],
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


@router.websocket("/api/live/ws")
@router.websocket("/grafana-ui/api/live/ws")
async def grafana_live_websocket_disabled(websocket: WebSocket) -> None:
    await websocket.accept()
    await websocket.close(code=1000)


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
    if path.startswith("public/") or path == "public":
        user = {}
    else:
        user = admin_user_from_token(kubeowl_admin_grafana)
        if user is None:
            user = storage.get_user_by_session(compliance_ai_session or "")
        if user is None:
            return JSONResponse(status_code=401, content={"error": "login required"})

    if _is_grafana_live_path(path):
        return Response(status_code=204)

    upstream_path = _upstream_path(path, request.url.query)
    try:
        response = await _forward_grafana_request(
            request,
            upstream_path=upstream_path,
            user=user,
        )
    except httpx.HTTPError as error:
        return JSONResponse(status_code=502, content={"error": f"Grafana request failed: {error}"})

    if (
        request.method.upper() == "GET"
        and response.status_code == 404
        and _is_grafana_splash_user_storage_path(path)
    ):
        return JSONResponse(content=_empty_grafana_user_storage(path))

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
        "X-Forwarded-Host": _ascii_header_value(request.headers.get("host", "")),
        "X-Forwarded-Proto": _ascii_header_value(request.url.scheme),
        "X-Forwarded-Prefix": "/grafana-ui",
    }
    if email:
        headers["X-WEBAUTH-USER"] = email
        headers["X-WEBAUTH-EMAIL"] = email
        headers["X-WEBAUTH-NAME"] = name
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


def _is_grafana_live_path(path: str) -> bool:
    normalized = path.strip("/")
    return normalized == "api/live/ws" or normalized.startswith("api/live/")


def _is_grafana_splash_user_storage_path(path: str) -> bool:
    normalized = path.strip("/")
    return (
        normalized.startswith("apis/userstorage.grafana.app/")
        and "/user-storage/grafana-splash-screen" in normalized
    )


def _empty_grafana_user_storage(path: str) -> dict[str, Any]:
    parts = path.strip("/").split("/")
    api_version = "userstorage.grafana.app/v0alpha1"
    namespace = "default"
    name = "grafana-splash-screen"
    if len(parts) >= 3:
        api_version = f"{parts[1]}/{parts[2]}"
    if "namespaces" in parts:
        index = parts.index("namespaces")
        if index + 1 < len(parts):
            namespace = parts[index + 1]
    if "user-storage" in parts:
        index = parts.index("user-storage")
        if index + 1 < len(parts):
            name = parts[index + 1]
    return {
        "apiVersion": api_version,
        "kind": "UserStorage",
        "metadata": {
            "name": name,
            "namespace": namespace,
        },
        "spec": {
            "data": {},
        },
    }


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
    return _rewrite_asset_text(rewritten)


def _rewrite_asset_text(text: str) -> str:
    rewritten = GRAFANA_PUBLIC_PATH_RE.sub(r"/grafana-ui/public/\1/", text)
    rewritten = GRAFANA_RELATIVE_PUBLIC_PATH_RE.sub(r"\g<prefix>/grafana-ui/public/\2/", rewritten)
    rewritten = rewritten.replace('"liveEnabled":true', '"liveEnabled":false')
    rewritten = rewritten.replace('"liveEnabled": true', '"liveEnabled": false')
    rewritten = rewritten.replace("liveEnabled:true", "liveEnabled:false")
    for asset_dir in GRAFANA_PUBLIC_DIRS:
        rewritten = rewritten.replace(
            f"\\/public\\/{asset_dir}\\/",
            f"\\/grafana-ui\\/public\\/{asset_dir}\\/",
        )
    return rewritten


def _rewrite_location(value: str) -> str:
    rewritten = value
    if value.startswith(GRAFANA_URL):
        rewritten = value.replace(GRAFANA_URL, "", 1) or "/"
    if rewritten.startswith("/") and not rewritten.startswith("/grafana-ui"):
        return f"/grafana-ui{rewritten}"
    return rewritten
