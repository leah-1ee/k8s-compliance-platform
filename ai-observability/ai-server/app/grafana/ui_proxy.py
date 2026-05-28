from __future__ import annotations

import asyncio
import os
import re
import unicodedata
from dataclasses import dataclass
from typing import Any

import httpx
from fastapi import APIRouter, Cookie, Request, WebSocket
from fastapi.responses import JSONResponse, RedirectResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from app import storage
from app.grafana.admin_session import admin_user_from_token


GRAFANA_URL = os.getenv("GRAFANA_URL_INTERNAL", "http://grafana.monitoring.svc.cluster.local:3000").rstrip("/")
CLIENT_GRAFANA_URL = os.getenv("GRAFANA_CLIENT_URL_INTERNAL", GRAFANA_URL).rstrip("/")
ADMIN_GRAFANA_URL = os.getenv("GRAFANA_ADMIN_URL_INTERNAL", GRAFANA_URL).rstrip("/")
SESSION_COOKIE_NAME = "compliance_ai_session"
CLIENT_GRAFANA_PREFIX = "/grafana-ui"
ADMIN_GRAFANA_PREFIX = "/admin-grafana"
router = APIRouter()
GRAFANA_PUBLIC_DIRS = ("build", "fonts", "img", "plugins", "app", "locales")
GRAFANA_PUBLIC_PATH_RE = re.compile(
    rf"(?<!/grafana-ui)(?<!/admin-grafana)/public/({'|'.join(GRAFANA_PUBLIC_DIRS)})/"
)
GRAFANA_RELATIVE_PUBLIC_PATH_RE = re.compile(
    rf"(?P<prefix>[\"'`=(])public/({'|'.join(GRAFANA_PUBLIC_DIRS)})/"
)
GRAFANA_LIVE_WEBSOCKET_PATHS = {
    "/api/live/ws",
    f"{CLIENT_GRAFANA_PREFIX}/api/live/ws",
    f"{ADMIN_GRAFANA_PREFIX}/api/live/ws",
}
GRAFANA_RETRY_STATUS_CODES = {502, 503, 504}


@dataclass(frozen=True)
class GrafanaProxyContext:
    name: str
    upstream_url: str
    public_prefix: str
    user_header: str
    email_header: str
    name_header: str
    admin: bool = False


CLIENT_GRAFANA_CONTEXT = GrafanaProxyContext(
    name="client",
    upstream_url=CLIENT_GRAFANA_URL,
    public_prefix=CLIENT_GRAFANA_PREFIX,
    user_header="X-KUBEOWL-CLIENT-USER",
    email_header="X-KUBEOWL-CLIENT-EMAIL",
    name_header="X-KUBEOWL-CLIENT-NAME",
)
ADMIN_GRAFANA_CONTEXT = GrafanaProxyContext(
    name="admin",
    upstream_url=ADMIN_GRAFANA_URL,
    public_prefix=ADMIN_GRAFANA_PREFIX,
    user_header="X-KUBEOWL-ADMIN-USER",
    email_header="X-KUBEOWL-ADMIN-EMAIL",
    name_header="X-KUBEOWL-ADMIN-NAME",
    admin=True,
)


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
    return RedirectResponse(f"{CLIENT_GRAFANA_PREFIX}/", status_code=307)


@router.api_route("/admin-grafana", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def admin_grafana_root() -> RedirectResponse:
    return RedirectResponse(f"{ADMIN_GRAFANA_PREFIX}/", status_code=307)


@router.api_route("/public/{path:path}", methods=["GET"])
async def grafana_public_asset_proxy(
    request: Request,
    path: str,
    compliance_ai_session: str | None = Cookie(default=None),
) -> Response:
    return await _proxy_grafana_path(
        request=request,
        path=f"public/{path}",
        context=CLIENT_GRAFANA_CONTEXT,
        compliance_ai_session=compliance_ai_session,
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
) -> Response:
    return await _proxy_grafana_path(
        request=request,
        path=request.url.path.lstrip("/"),
        context=CLIENT_GRAFANA_CONTEXT,
        compliance_ai_session=compliance_ai_session,
    )


@router.websocket("/api/live/ws")
@router.websocket("/grafana-ui/api/live/ws")
@router.websocket("/admin-grafana/api/live/ws")
async def grafana_live_websocket_disabled(websocket: WebSocket) -> None:
    await websocket.accept()
    await websocket.close(code=1000)


@router.api_route("/grafana-ui/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def grafana_ui_proxy(
    request: Request,
    path: str,
    compliance_ai_session: str | None = Cookie(default=None),
) -> Response:
    return await _proxy_grafana_path(
        request=request,
        path=path,
        context=CLIENT_GRAFANA_CONTEXT,
        compliance_ai_session=compliance_ai_session,
    )


@router.api_route("/admin-grafana/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def admin_grafana_proxy(
    request: Request,
    path: str,
    kubeowl_admin_grafana: str | None = Cookie(default=None),
) -> Response:
    return await _proxy_grafana_path(
        request=request,
        path=path,
        context=ADMIN_GRAFANA_CONTEXT,
        kubeowl_admin_grafana=kubeowl_admin_grafana,
    )


async def _proxy_grafana_path(
    request: Request,
    path: str,
    context: GrafanaProxyContext,
    compliance_ai_session: str | None = None,
    kubeowl_admin_grafana: str | None = None,
) -> Response:
    if path.startswith("public/") or path == "public":
        user = {}
    elif context.admin:
        user = admin_user_from_token(kubeowl_admin_grafana)
        if user is None:
            return JSONResponse(status_code=401, content={"error": "admin grafana token required"})
    else:
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
            context=context,
        )
    except httpx.HTTPError as error:
        return JSONResponse(status_code=502, content={"error": f"Grafana request failed: {error}"})

    if (
        request.method.upper() == "GET"
        and response.status_code == 404
        and _is_grafana_splash_user_storage_path(path)
    ):
        return JSONResponse(content=_empty_grafana_user_storage(path))

    content = _response_content(response, context)
    headers = _response_headers(response, context)
    return Response(
        content=content,
        status_code=response.status_code,
        headers=headers,
        media_type=response.headers.get("content-type"),
    )


async def _forward_grafana_request(
    request: Request,
    upstream_path: str,
    user: dict[str, Any],
    context: GrafanaProxyContext = CLIENT_GRAFANA_CONTEXT,
) -> httpx.Response:
    body = await request.body()
    headers = _request_headers(request, user, context)
    async with httpx.AsyncClient(base_url=context.upstream_url, timeout=30, follow_redirects=False) as client:
        last_error: httpx.HTTPError | None = None
        for attempt in range(3):
            try:
                response = await client.request(
                    request.method,
                    upstream_path,
                    content=body if body else None,
                    headers=headers,
                )
            except httpx.HTTPError as error:
                last_error = error
                if attempt == 2:
                    raise
            else:
                if response.status_code not in GRAFANA_RETRY_STATUS_CODES or attempt == 2:
                    return response
            await asyncio.sleep(0.2 * (attempt + 1))
    if last_error is not None:
        raise last_error
    raise httpx.HTTPError("Grafana request failed without a response")


def _request_headers(
    request: Request,
    user: dict[str, Any],
    context: GrafanaProxyContext = CLIENT_GRAFANA_CONTEXT,
) -> dict[str, str]:
    email = _ascii_header_value(user.get("email") or user.get("id") or "")
    name = _ascii_header_value(user.get("name") or user.get("email") or "") or email
    headers: dict[str, str] = {
        "X-Forwarded-Host": _ascii_header_value(request.headers.get("host", "")),
        "X-Forwarded-Proto": _ascii_header_value(request.url.scheme),
        "X-Forwarded-Prefix": context.public_prefix,
    }
    if email:
        headers[context.user_header] = email
        headers[context.email_header] = email
        headers[context.name_header] = name
    for key in ("accept", "content-type", "user-agent"):
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


def _response_headers(
    response: httpx.Response,
    context: GrafanaProxyContext = CLIENT_GRAFANA_CONTEXT,
) -> dict[str, str]:
    headers: dict[str, str] = {}
    for key, value in response.headers.items():
        lower = key.lower()
        if lower in {"content-length", "content-encoding", "transfer-encoding", "connection", "set-cookie"}:
            continue
        if lower == "location":
            headers[key] = _rewrite_location(value, context)
        else:
            headers[key] = value
    return headers


def _response_content(
    response: httpx.Response,
    context: GrafanaProxyContext = CLIENT_GRAFANA_CONTEXT,
) -> bytes:
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
        text = _rewrite_html(text, context.public_prefix)
    else:
        text = _rewrite_asset_text(text, context.public_prefix)
    return text.encode(response.encoding or "utf-8")


def _rewrite_html(html: str, public_prefix: str = CLIENT_GRAFANA_PREFIX) -> str:
    replacements = {
        '<base href="/">': f'<base href="{public_prefix}/">',
        f'<base href="{public_prefix}//">': f'<base href="{public_prefix}/">',
        'src="/public/': f'src="{public_prefix}/public/',
        'href="/public/': f'href="{public_prefix}/public/',
        'content="/public/': f'content="{public_prefix}/public/',
        'url(/public/': f'url({public_prefix}/public/',
        'src="public/': f'src="{public_prefix}/public/',
        'href="public/': f'href="{public_prefix}/public/',
        '"appSubUrl":""': f'"appSubUrl":"{public_prefix}"',
        '"appSubUrl":"/"': f'"appSubUrl":"{public_prefix}"',
    }
    rewritten = html
    for old, new in replacements.items():
        rewritten = rewritten.replace(old, new)
    return _rewrite_asset_text(rewritten, public_prefix)


def _rewrite_asset_text(text: str, public_prefix: str = CLIENT_GRAFANA_PREFIX) -> str:
    rewritten = GRAFANA_PUBLIC_PATH_RE.sub(rf"{public_prefix}/public/\1/", text)
    rewritten = GRAFANA_RELATIVE_PUBLIC_PATH_RE.sub(rf"\g<prefix>{public_prefix}/public/\2/", rewritten)
    rewritten = rewritten.replace('"liveEnabled":true', '"liveEnabled":false')
    rewritten = rewritten.replace('"liveEnabled": true', '"liveEnabled": false')
    rewritten = rewritten.replace("liveEnabled:true", "liveEnabled:false")
    for asset_dir in GRAFANA_PUBLIC_DIRS:
        rewritten = rewritten.replace(
            f"\\/public\\/{asset_dir}\\/",
            f"\\/{public_prefix.strip('/')}\\/public\\/{asset_dir}\\/",
        )
    return rewritten


def _rewrite_location(
    value: str,
    context: GrafanaProxyContext = CLIENT_GRAFANA_CONTEXT,
) -> str:
    rewritten = value
    if value.startswith(context.upstream_url):
        rewritten = value.replace(context.upstream_url, "", 1) or "/"
    if rewritten.startswith("/") and not rewritten.startswith(context.public_prefix):
        return f"{context.public_prefix}{rewritten}"
    return rewritten
