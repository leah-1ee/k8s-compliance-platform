import logging
import os
import secrets
import shlex
from contextvars import ContextVar
from pathlib import Path
from urllib.parse import urlencode, urlparse

import httpx
from fastapi import Cookie, FastAPI, Header, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.analyzer import analyze_violation
from app.classifier import classify_event
from app.policy_generator import generate_policy
from app.policy_generator import SUPPORTED_POLICY_EXAMPLES, UnsupportedPolicyError
from app import storage
from app.runtime_client import (
    apply_policy_manifest,
    build_dashboard_summary,
    build_report,
    get_runtime_event,
    list_runtime_events,
    record_falco_event,
    record_gatekeeper_event,
)
from app.schemas import (
    ClassificationRequest,
    ClassificationResponse,
    PolicyGenerationRequest,
    PolicyGenerationResponse,
    ViolationAnalysisRequest,
    ViolationAnalysisResponse,
)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("ai-server")
STATIC_DIR = Path(__file__).resolve().parent / "static"
DEFAULT_GRAFANA_URL = "https://compliance-grafana.shares.zrok.io"
RATE_LIMIT_MESSAGE = "Rate limit exceeded. Add your own API key above to continue."
SESSION_COOKIE_NAME = "compliance_ai_session"
OAUTH_STATE_COOKIE_NAME = "compliance_ai_oauth_state"
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
current_request: ContextVar[Request | None] = ContextVar("current_request", default=None)


def sanitize_llm_api_key(value: str | None) -> str:
    # 사용자 키 정규화
    if not value:
        return ""
    normalized = "".join(ch for ch in value.strip() if ch.isprintable())[:4096]
    if any(ch.isspace() for ch in normalized):
        return ""
    if len(normalized) < 8:
        return ""
    return normalized


def sanitize_llm_provider(value: str | None) -> str | None:
    # 제공자 헤더 검증
    normalized = (value or "").strip().lower()
    if normalized in {"openai", "anthropic", "google", "xai"}:
        return normalized
    return None


def has_user_llm_key() -> bool:
    # 사용자 키 여부
    request = current_request.get()
    if request is None:
        return False
    return bool(sanitize_llm_api_key(request.headers.get("x-llm-api-key")))


def is_admin_token(value: str | None) -> bool:
    expected = os.getenv("ADMIN_TOKEN", "").strip()
    if not expected:
        return False
    provided = _bearer_or_raw_token(value)
    return secrets.compare_digest(provided, expected)


def require_admin(value: str | None):
    if not is_admin_token(value):
        return JSONResponse(status_code=401, content={"error": "admin token required"})
    return None


def current_user(session_token: str | None) -> dict | None:
    return storage.get_user_by_session(session_token or "")


def require_user(session_token: str | None) -> tuple[dict | None, JSONResponse | None]:
    user = current_user(session_token)
    if user is None:
        return None, JSONResponse(status_code=401, content={"error": "login required"})
    return user, None


def auth_configured() -> bool:
    return bool(os.getenv("GOOGLE_CLIENT_ID", "").strip() and os.getenv("GOOGLE_CLIENT_SECRET", "").strip())


def dev_auth_enabled() -> bool:
    return os.getenv("DEV_AUTH_ENABLED", "").strip().lower() in {"true", "1", "yes"}


def public_base_url(request: Request) -> str:
    configured = os.getenv("PUBLIC_BASE_URL", "").strip()
    if configured:
        return configured.rstrip("/")
    return str(request.base_url).rstrip("/")


def oauth_redirect_uri(request: Request) -> str:
    return f"{public_base_url(request)}/auth/google/callback"


def session_cookie_secure(request: Request) -> bool:
    configured = os.getenv("SESSION_COOKIE_SECURE", "").strip().lower()
    if configured in {"true", "1", "yes"}:
        return True
    if configured in {"false", "0", "no"}:
        return False
    return public_base_url(request).startswith("https://")


def set_session_cookie(response: Response, request: Request, token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        httponly=True,
        secure=session_cookie_secure(request),
        samesite="lax",
        max_age=60 * 60 * 24 * 30,
        path="/",
    )


def clear_session_cookie(response: Response, request: Request) -> None:
    response.delete_cookie(
        SESSION_COOKIE_NAME,
        httponly=True,
        secure=session_cookie_secure(request),
        samesite="lax",
        path="/",
    )


def _bearer_or_raw_token(value: str | None) -> str:
    normalized = (value or "").strip()
    if normalized.lower().startswith("bearer "):
        return normalized.split(" ", 1)[1].strip()
    return normalized


def _manifest_guidance(
    namespace: str = "",
    pod: str = "",
    cluster: str = "",
    container: str = "",
    manifest: str = "",
) -> dict:
    ns = (namespace or "").strip()
    pod_name = (pod or "").strip()
    cluster_name = (cluster or "").strip()
    container_name = (container or "").strip()
    context = {
        "cluster": cluster_name,
        "namespace": ns,
        "pod": pod_name,
        "container": container_name,
    }
    guidance = (
        "중앙 AI 서버는 사용자 클러스터의 Kubernetes API 권한을 가정하지 않습니다. "
        "아래 명령을 이벤트가 발생한 사용자 클러스터의 kubeconfig context에서 실행하세요."
    )
    if pod_name and ns:
        command = f"kubectl get pod {shlex.quote(pod_name)} -n {shlex.quote(ns)} -o yaml"
        return {
            "manifest": manifest,
            "error": "",
            "kubectl_command": command,
            "manifest_guidance": guidance,
            "resource_context": context,
        }
    if pod_name:
        command = f"kubectl get pod {shlex.quote(pod_name)} --all-namespaces -o yaml"
        return {
            "manifest": manifest,
            "error": "이벤트에 namespace가 없어 전체 namespace에서 pod 이름으로 조회하는 명령을 제공합니다.",
            "kubectl_command": command,
            "manifest_guidance": guidance,
            "resource_context": context,
        }
    if ns:
        command = f"kubectl get pods -n {shlex.quote(ns)} -o wide"
        return {
            "manifest": manifest,
            "error": "이벤트에 pod 이름이 없어 namespace의 pod 목록을 확인하는 명령을 제공합니다.",
            "kubectl_command": command,
            "manifest_guidance": guidance,
            "resource_context": context,
        }
    return {
        "manifest": manifest,
        "error": "이벤트에 namespace와 pod 이름이 없어 특정 manifest 조회 명령을 만들 수 없습니다.",
        "kubectl_command": "",
        "manifest_guidance": guidance,
        "resource_context": context,
    }


limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="Compliance AI Server",
    version="0.1.0",
    description="Falco 이벤트 분류 및 컴플라이언스 AI API",
)
app.state.limiter = limiter
app.add_exception_handler(
    RateLimitExceeded,
    lambda request, exc: JSONResponse(
        status_code=429,
        content={"error": RATE_LIMIT_MESSAGE},
    ),
)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.middleware("http")
async def bind_current_request(request: Request, call_next):
    # 요청 컨텍스트
    token = current_request.set(request)
    try:
        return await call_next(request)
    finally:
        current_request.reset(token)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/config")
def config() -> dict[str, str]:
    # UI 설정
    return {
        "grafana_url": os.getenv("GRAFANA_URL", DEFAULT_GRAFANA_URL).strip(),
        "response_server_url": os.getenv("RESPONSE_SERVER_URL", "http://response-server:8080").strip(),
        "auth_provider": "google" if auth_configured() else "",
    }


@app.get("/me")
def me(compliance_ai_session: str | None = Cookie(default=None)) -> dict:
    # 현재 로그인 사용자
    user = current_user(compliance_ai_session)
    return {
        "authenticated": user is not None,
        "user": _public_user(user) if user else None,
        "auth": {
            "google_configured": auth_configured(),
            "dev_enabled": dev_auth_enabled(),
        },
    }


@app.get("/auth/google/login")
def google_login(request: Request):
    # Google OAuth 시작
    client_id = os.getenv("GOOGLE_CLIENT_ID", "").strip()
    if not auth_configured():
        return JSONResponse(status_code=503, content={"error": "Google OAuth is not configured"})
    state = secrets.token_urlsafe(24)
    params = {
        "client_id": client_id,
        "redirect_uri": oauth_redirect_uri(request),
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "online",
        "prompt": "select_account",
    }
    response = RedirectResponse(f"{GOOGLE_AUTH_URL}?{urlencode(params)}", status_code=302)
    response.set_cookie(
        OAUTH_STATE_COOKIE_NAME,
        state,
        httponly=True,
        secure=session_cookie_secure(request),
        samesite="lax",
        max_age=600,
        path="/",
    )
    return response


@app.get("/auth/google/callback")
def google_callback(
    request: Request,
    code: str = "",
    state: str = "",
    compliance_ai_oauth_state: str | None = Cookie(default=None),
):
    # Google OAuth 콜백
    if not auth_configured():
        return JSONResponse(status_code=503, content={"error": "Google OAuth is not configured"})
    if not state or not compliance_ai_oauth_state or not secrets.compare_digest(state, compliance_ai_oauth_state):
        return JSONResponse(status_code=400, content={"error": "invalid oauth state"})
    if not code:
        return JSONResponse(status_code=400, content={"error": "missing oauth code"})

    try:
        token_response = httpx.post(
            GOOGLE_TOKEN_URL,
            data={
                "code": code,
                "client_id": os.getenv("GOOGLE_CLIENT_ID", "").strip(),
                "client_secret": os.getenv("GOOGLE_CLIENT_SECRET", "").strip(),
                "redirect_uri": oauth_redirect_uri(request),
                "grant_type": "authorization_code",
            },
            timeout=10,
        )
        token_response.raise_for_status()
        access_token = token_response.json().get("access_token", "")
        if not access_token:
            return JSONResponse(status_code=502, content={"error": "Google OAuth token response missing access_token"})
        userinfo_response = httpx.get(
            GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        userinfo_response.raise_for_status()
        profile = userinfo_response.json()
    except httpx.HTTPError as error:
        return JSONResponse(status_code=502, content={"error": f"Google OAuth request failed: {error}"})

    try:
        user = storage.upsert_user(
            provider="google",
            provider_subject=str(profile.get("sub", "")),
            email=str(profile.get("email", "")),
            name=str(profile.get("name", "")),
            picture=str(profile.get("picture", "")),
        )
    except ValueError as error:
        return JSONResponse(status_code=400, content={"error": str(error)})

    session_token = storage.create_session(user["id"])
    response = RedirectResponse("/ui", status_code=302)
    set_session_cookie(response, request, session_token)
    response.delete_cookie(
        OAUTH_STATE_COOKIE_NAME,
        httponly=True,
        secure=session_cookie_secure(request),
        samesite="lax",
        path="/",
    )
    return response


@app.post("/logout")
def logout(request: Request, compliance_ai_session: str | None = Cookie(default=None)):
    # 세션 로그아웃
    storage.delete_session(compliance_ai_session or "")
    response = JSONResponse({"status": "logged_out"})
    clear_session_cookie(response, request)
    return response


@app.get("/auth/dev-login")
def dev_login(request: Request):
    # Google OAuth 설정 전 개발/시연용 로그인. 운영에서는 DEV_AUTH_ENABLED를 끈다.
    if not dev_auth_enabled():
        return JSONResponse(status_code=503, content={"error": "dev auth is disabled"})
    email = os.getenv("DEV_AUTH_EMAIL", "demo@school.test").strip().lower()
    name = os.getenv("DEV_AUTH_NAME", "Demo User").strip()
    try:
        user = storage.upsert_user(
            provider="dev",
            provider_subject=email,
            email=email,
            name=name,
        )
    except ValueError as error:
        return JSONResponse(status_code=400, content={"error": str(error)})
    session_token = storage.create_session(user["id"])
    response = RedirectResponse("/ui", status_code=302)
    set_session_cookie(response, request, session_token)
    return response


@app.post("/classify", response_model=ClassificationResponse)
def classify(payload: ClassificationRequest) -> ClassificationResponse:
    # 이벤트 분류
    result = classify_event(payload)
    logger.info(
        "classification severity=%s confidence=%.2f rule=%s",
        result.severity,
        result.confidence,
        payload.rule[:120],
    )
    return result


@app.post("/analyze-violation", response_model=ViolationAnalysisResponse)
@limiter.limit("5/hour", exempt_when=has_user_llm_key)
def analyze(
    request: Request,
    payload: ViolationAnalysisRequest,
    x_llm_provider: str | None = Header(default=None),
    x_llm_api_key: str | None = Header(default=None),
) -> ViolationAnalysisResponse:
    # 위반 분석
    _ = request
    return analyze_violation(
        payload,
        llm_provider=sanitize_llm_provider(x_llm_provider),
        llm_api_key=sanitize_llm_api_key(x_llm_api_key),
    )


@app.get("/runtime-events")
def runtime_events(
    limit: int = 50,
    cluster: str = "",
    cluster_kind: str = "",
    source: str = "",
    include_legacy: bool = False,
    exclude_infra: bool = False,
    compliance_ai_session: str | None = Cookie(default=None),
) -> dict:
    # Falco/Gatekeeper 최근 위반 이벤트 목록
    user, auth_error = require_user(compliance_ai_session)
    if auth_error:
        return auth_error
    assert user is not None
    return list_runtime_events(
        limit=limit,
        cluster=cluster,
        cluster_kind=cluster_kind,
        source=source,
        include_legacy=include_legacy,
        user_id=user["id"],
        exclude_infra=exclude_infra,
    )


@app.get("/dashboard-summary")
def dashboard_summary(compliance_ai_session: str | None = Cookie(default=None)) -> dict:
    user, auth_error = require_user(compliance_ai_session)
    if auth_error:
        return auth_error
    assert user is not None
    return build_dashboard_summary(user_id=user["id"])


@app.get("/runtime-events/{event_id}")
def runtime_event(event_id: str, compliance_ai_session: str | None = Cookie(default=None)):
    # 위반 이벤트 상세
    user, auth_error = require_user(compliance_ai_session)
    if auth_error:
        return auth_error
    assert user is not None
    event = get_runtime_event(event_id, user_id=user["id"])
    if event is None:
        return JSONResponse(status_code=404, content={"error": f"event {event_id} not found"})
    return event


@app.post("/ingest/falco-events")
def ingest_falco_events(payload: dict, authorization: str | None = Header(default=None)) -> dict:
    # Falco Sidekick이 전송한 이벤트를 클러스터 토큰으로 인증 후 수집
    cluster_token = _bearer_or_raw_token(authorization)
    cluster = storage.find_cluster_by_token(cluster_token)
    if cluster is None:
        return JSONResponse(status_code=401, content={"error": "valid cluster token required"})
    cluster_kind = cluster.get("kind", "customer")
    if cluster_kind != "demo" and storage.is_demo_cluster_name(cluster["name"]):
        cluster = storage.update_cluster_kind(cluster["id"], "demo") or cluster
        cluster_kind = "demo"
    event = record_falco_event(
        payload,
        cluster_id=cluster["id"],
        cluster_name=cluster["name"],
        cluster_kind=cluster_kind,
        source="sidekick",
    )
    storage.mark_cluster_seen(cluster["id"], event.get("timestamp", ""))
    _notify_slack_for_event(cluster, event)
    return {"status": "recorded", "event": event}


@app.get("/api/clusters")
def user_list_clusters(
    include_deleted: bool = False,
    compliance_ai_session: str | None = Cookie(default=None),
) -> dict:
    # 로그인 사용자의 클러스터 목록
    user, auth_error = require_user(compliance_ai_session)
    if auth_error:
        return auth_error
    assert user is not None
    return {"clusters": storage.list_clusters(user_id=user["id"], include_deleted=include_deleted)}


@app.post("/api/clusters")
def user_create_cluster(
    request: Request,
    payload: dict,
    compliance_ai_session: str | None = Cookie(default=None),
):
    # 로그인 사용자가 자기 클러스터를 등록하고 Sidekick 설치 명령을 받는다.
    user, auth_error = require_user(compliance_ai_session)
    if auth_error:
        return auth_error
    assert user is not None
    try:
        cluster = storage.create_cluster(
            str(payload.get("name", "")),
            kind="customer",
            user_id=user["id"],
        )
    except ValueError as error:
        return JSONResponse(status_code=400, content={"error": str(error)})
    except Exception as error:
        if "UNIQUE" in str(error).upper():
            return JSONResponse(status_code=409, content={"error": "cluster name already exists"})
        raise
    cluster["install_command"] = _sidekick_install_command(request, cluster["token"])
    return {"cluster": cluster}


@app.post("/api/clusters/{cluster_id}/rotate-token")
def user_rotate_cluster_token(
    request: Request,
    cluster_id: str,
    compliance_ai_session: str | None = Cookie(default=None),
):
    # 사용자가 자기 클러스터의 ingest token을 재발급한다.
    user, auth_error = require_user(compliance_ai_session)
    if auth_error:
        return auth_error
    assert user is not None
    cluster = storage.get_cluster(cluster_id)
    if cluster is None or cluster.get("user_id") != user["id"]:
        return JSONResponse(status_code=404, content={"error": "cluster not found"})
    rotated = storage.rotate_cluster_token(cluster_id)
    if rotated is None:
        return JSONResponse(status_code=404, content={"error": "cluster not found"})
    rotated["install_command"] = _sidekick_install_command(request, rotated["token"])
    return {"cluster": rotated}


@app.delete("/api/clusters/{cluster_id}")
def user_trash_cluster(
    cluster_id: str,
    compliance_ai_session: str | None = Cookie(default=None),
) -> dict:
    user, auth_error = require_user(compliance_ai_session)
    if auth_error:
        return auth_error
    assert user is not None
    cluster = storage.trash_cluster(cluster_id, user["id"])
    if cluster is None:
        return JSONResponse(status_code=404, content={"error": "cluster not found"})
    return {"cluster": cluster}


@app.post("/api/clusters/{cluster_id}/restore")
def user_restore_cluster(
    cluster_id: str,
    compliance_ai_session: str | None = Cookie(default=None),
) -> dict:
    user, auth_error = require_user(compliance_ai_session)
    if auth_error:
        return auth_error
    assert user is not None
    cluster = storage.restore_cluster(cluster_id, user["id"])
    if cluster is None:
        return JSONResponse(status_code=404, content={"error": "cluster not found"})
    return {"cluster": cluster}


@app.get("/api/slack-settings")
def get_slack_settings(compliance_ai_session: str | None = Cookie(default=None)) -> dict:
    # 로그인 사용자의 Slack 알림 설정
    user, auth_error = require_user(compliance_ai_session)
    if auth_error:
        return auth_error
    assert user is not None
    return {"settings": storage.get_slack_settings(user["id"])}


@app.post("/api/slack-settings")
def save_slack_settings(payload: dict, compliance_ai_session: str | None = Cookie(default=None)) -> dict:
    # 사용자별 Slack incoming webhook URL 저장
    user, auth_error = require_user(compliance_ai_session)
    if auth_error:
        return auth_error
    assert user is not None
    webhook_url = str(payload.get("webhook_url", "")).strip()
    if webhook_url and not _is_valid_slack_webhook_url(webhook_url):
        return JSONResponse(status_code=400, content={"error": "valid Slack webhook URL required"})
    return {"settings": storage.save_slack_settings(user["id"], webhook_url)}


@app.post("/api/slack-settings/test")
def test_slack_settings(compliance_ai_session: str | None = Cookie(default=None)) -> dict:
    # 저장된 Slack webhook으로 테스트 메시지를 전송한다.
    user, auth_error = require_user(compliance_ai_session)
    if auth_error:
        return auth_error
    assert user is not None
    settings = storage.get_slack_settings(user["id"])
    webhook_url = settings.get("webhook_url", "")
    if not webhook_url:
        return JSONResponse(status_code=400, content={"error": "Slack webhook URL is not configured"})
    try:
        _post_slack_message(
            webhook_url,
            {
                "text": "Compliance AI Slack notification test",
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "*Compliance AI* Slack 알림 테스트가 성공했습니다.",
                        },
                    }
                ],
            },
        )
    except httpx.HTTPError as error:
        return JSONResponse(status_code=502, content={"error": f"Slack webhook request failed: {error}"})
    return {"status": "sent"}


@app.post("/api/clusters/{cluster_id}/slack")
def set_cluster_slack(
    cluster_id: str,
    payload: dict,
    compliance_ai_session: str | None = Cookie(default=None),
) -> dict:
    # 클러스터별 Slack 알림 on/off
    user, auth_error = require_user(compliance_ai_session)
    if auth_error:
        return auth_error
    assert user is not None
    cluster = storage.set_cluster_slack_enabled(
        cluster_id,
        user["id"],
        bool(payload.get("enabled")),
    )
    if cluster is None:
        return JSONResponse(status_code=404, content={"error": "cluster not found"})
    return {"cluster": cluster}


@app.post("/api/clusters/{cluster_id}/policy-applies")
def apply_generated_policy_to_cluster(
    cluster_id: str,
    payload: dict,
    compliance_ai_session: str | None = Cookie(default=None),
) -> dict:
    # 로그인 사용자의 생성 정책을 소유 클러스터에 적용하거나 안전한 kubectl fallback을 반환한다.
    user, auth_error = require_user(compliance_ai_session)
    if auth_error:
        return auth_error
    assert user is not None
    cluster = storage.get_cluster(cluster_id)
    if cluster is None or cluster.get("user_id") != user["id"]:
        return JSONResponse(status_code=404, content={"error": "cluster not found"})
    if cluster.get("status") != "active":
        return JSONResponse(status_code=409, content={"error": "cluster must be active before applying policies"})
    manifest = str(payload.get("manifest", "")).strip()
    if not manifest:
        return JSONResponse(status_code=400, content={"error": "manifest is required"})
    try:
        result = apply_policy_manifest(manifest, cluster)
    except ValueError as error:
        return JSONResponse(status_code=400, content={"error": str(error)})
    status = str(result.get("status", "unknown"))
    history = storage.save_policy_apply_history(
        user_id=user["id"],
        cluster_id=cluster["id"],
        policy_type=str(result.get("policy_type") or payload.get("policy_type") or "unknown"),
        policy_name=str(result.get("policy_name") or payload.get("policy_name") or "unknown"),
        manifest=manifest,
        status=status,
        error=str(result.get("error", "")),
        result=result,
    )
    response = {
        "status": status,
        "cluster": {
            "id": cluster["id"],
            "name": cluster["name"],
            "kind": cluster["kind"],
            "status": cluster["status"],
        },
        "history": history,
        **result,
    }
    if status == "invalid_manifest":
        return JSONResponse(status_code=400, content=response)
    return response


@app.get("/admin", response_class=FileResponse)
def admin() -> FileResponse:
    # 관리자 콘솔
    return FileResponse(STATIC_DIR / "admin.html")


@app.get("/admin/api/clusters")
def admin_list_clusters(x_admin_token: str | None = Header(default=None)):
    auth_error = require_admin(x_admin_token)
    if auth_error:
        return auth_error
    return {"clusters": storage.list_clusters()}


@app.get("/admin/api/users")
def admin_list_users(x_admin_token: str | None = Header(default=None)):
    auth_error = require_admin(x_admin_token)
    if auth_error:
        return auth_error
    return {"users": storage.list_users()}


@app.get("/admin/api/users/{user_id}/clusters")
def admin_list_user_clusters(user_id: str, x_admin_token: str | None = Header(default=None)):
    auth_error = require_admin(x_admin_token)
    if auth_error:
        return auth_error
    user = storage.get_user(user_id)
    if user is None:
        return JSONResponse(status_code=404, content={"error": "user not found"})
    return {"user": _public_user(user), "clusters": storage.list_clusters(user_id=user_id)}


@app.post("/admin/api/clusters")
def admin_create_cluster(
    request: Request,
    payload: dict,
    x_admin_token: str | None = Header(default=None),
):
    auth_error = require_admin(x_admin_token)
    if auth_error:
        return auth_error
    try:
        cluster = storage.create_cluster(
            str(payload.get("name", "")),
            kind=str(payload.get("kind", "customer")),
        )
    except ValueError as error:
        return JSONResponse(status_code=400, content={"error": str(error)})
    except Exception as error:
        if "UNIQUE" in str(error).upper():
            return JSONResponse(status_code=409, content={"error": "cluster name already exists"})
        raise
    cluster["install_command"] = _sidekick_install_command(request, cluster["token"])
    return {"cluster": cluster}


@app.post("/admin/api/clusters/{cluster_id}/mark-demo")
def admin_mark_demo_cluster(cluster_id: str, x_admin_token: str | None = Header(default=None)):
    auth_error = require_admin(x_admin_token)
    if auth_error:
        return auth_error
    cluster = storage.update_cluster_kind(cluster_id, "demo")
    if cluster is None:
        return JSONResponse(status_code=404, content={"error": "cluster not found"})
    return {"cluster": cluster}


@app.post("/admin/api/clusters/{cluster_id}/mark-customer")
def admin_mark_customer_cluster(cluster_id: str, x_admin_token: str | None = Header(default=None)):
    auth_error = require_admin(x_admin_token)
    if auth_error:
        return auth_error
    cluster = storage.update_cluster_kind(cluster_id, "customer")
    if cluster is None:
        return JSONResponse(status_code=404, content={"error": "cluster not found"})
    return {"cluster": cluster}


@app.post("/admin/api/clusters/{cluster_id}/rotate-token")
def admin_rotate_cluster_token(
    request: Request,
    cluster_id: str,
    x_admin_token: str | None = Header(default=None),
):
    auth_error = require_admin(x_admin_token)
    if auth_error:
        return auth_error
    cluster = storage.rotate_cluster_token(cluster_id)
    if cluster is None:
        return JSONResponse(status_code=404, content={"error": "cluster not found"})
    cluster["install_command"] = _sidekick_install_command(request, cluster["token"])
    return {"cluster": cluster}


@app.post("/admin/api/clusters/{cluster_id}/disable")
def admin_disable_cluster(cluster_id: str, x_admin_token: str | None = Header(default=None)):
    auth_error = require_admin(x_admin_token)
    if auth_error:
        return auth_error
    cluster = storage.disable_cluster(cluster_id)
    if cluster is None:
        return JSONResponse(status_code=404, content={"error": "cluster not found"})
    return {"cluster": cluster}


@app.get("/resource-manifest")
def resource_manifest(
    namespace: str = "",
    pod: str = "",
    event_id: str = "",
    compliance_ai_session: str | None = Cookie(default=None),
) -> dict:
    # 사용자 클러스터에서 직접 실행할 매니페스트 조회 명령 안내
    user, auth_error = require_user(compliance_ai_session)
    if auth_error:
        return auth_error
    assert user is not None
    if event_id:
        event = get_runtime_event(event_id, user_id=user["id"])
        if event is None:
            return JSONResponse(status_code=404, content={"error": f"event {event_id} not found"})
        return _manifest_guidance(
            namespace=event.get("namespace", ""),
            pod=event.get("pod_name", ""),
            cluster=event.get("cluster", ""),
            container=event.get("container_name", ""),
            manifest=event.get("resource_manifest", ""),
        )
    return _manifest_guidance(namespace=namespace, pod=pod)


@app.post("/analyze-runtime-event/{event_id}", response_model=ViolationAnalysisResponse)
@limiter.limit("5/hour", exempt_when=has_user_llm_key)
def analyze_runtime_event(
    request: Request,
    event_id: str,
    x_llm_provider: str | None = Header(default=None),
    x_llm_api_key: str | None = Header(default=None),
    compliance_ai_session: str | None = Cookie(default=None),
):
    # 저장된 이벤트와 매니페스트를 결합해 상세 분석
    _ = request
    user, auth_error = require_user(compliance_ai_session)
    if auth_error:
        return auth_error
    assert user is not None
    event = get_runtime_event(event_id, user_id=user["id"])
    if event is None:
        return JSONResponse(status_code=404, content={"error": f"event {event_id} not found"})
    resource_manifest = event.get("resource_manifest", "")
    manifest_result = _manifest_guidance(
        namespace=event.get("namespace", ""),
        pod=event.get("pod_name", ""),
        cluster=event.get("cluster", ""),
        container=event.get("container_name", ""),
        manifest=resource_manifest,
    )
    payload = ViolationAnalysisRequest(
        cluster=event.get("cluster") or os.getenv("CLUSTER_NAME", "current-cluster"),
        rule=event.get("rule", ""),
        priority=event.get("priority", ""),
        output=event.get("classification_reason", "") or event.get("output", ""),
        output_fields={
            "k8s.ns.name": event.get("namespace", ""),
            "k8s.pod.name": event.get("pod_name", ""),
            "container.name": event.get("container_name", ""),
            "container.image.repository": event.get("image", ""),
            "user.name": event.get("user", ""),
            "proc.cmdline": event.get("command", ""),
        },
        tags=[event.get("source", "runtime")],
        time=event.get("timestamp", ""),
        resource_manifest=manifest_result.get("manifest", ""),
        use_llm=has_user_llm_key(),
    )
    result = analyze_violation(
        payload,
        llm_provider=sanitize_llm_provider(x_llm_provider),
        llm_api_key=sanitize_llm_api_key(x_llm_api_key),
    )
    if not resource_manifest and not result.llm_error:
        command = manifest_result.get("kubectl_command", "")
        result.llm_error = (
            f"{manifest_result.get('error') or manifest_result.get('manifest_guidance')} 실행 명령: {command}"
            if command
            else manifest_result.get("error", "")
        )
    return result


@app.post("/gatekeeper-events")
def gatekeeper_events(payload: dict) -> dict:
    # Gatekeeper deny/audit 이벤트 push 수집
    event = record_gatekeeper_event(payload)
    return {"status": "recorded", "event": event}


@app.get("/compliance-report")
def compliance_report(
    cluster_kind: str = "",
    include_legacy: bool = False,
    x_llm_provider: str | None = Header(default=None),
    x_llm_api_key: str | None = Header(default=None),
    compliance_ai_session: str | None = Cookie(default=None),
) -> dict:
    # AI 리포트 탭용 JSON 리포트
    user, auth_error = require_user(compliance_ai_session)
    if auth_error:
        return auth_error
    assert user is not None
    return build_report(
        cluster_kind=cluster_kind,
        include_legacy=include_legacy,
        user_id=user["id"],
        llm_provider=sanitize_llm_provider(x_llm_provider),
        llm_api_key=sanitize_llm_api_key(x_llm_api_key),
    )


def _sidekick_install_command(request: Request, token: str) -> str:
    public_base_url = os.getenv("PUBLIC_BASE_URL", str(request.base_url).rstrip("/")).rstrip("/")
    ingest_url = f"{public_base_url}/ingest/falco-events"
    return "\n".join(
        [
            "helm repo add falcosecurity https://falcosecurity.github.io/charts",
            "helm repo update",
            "helm upgrade --install falco falcosecurity/falco \\",
            "  -n falco \\",
            "  --create-namespace \\",
            "  --set falcosidekick.enabled=true \\",
            f'  --set falcosidekick.config.webhook.address="{ingest_url}" \\',
            f'  --set falcosidekick.config.webhook.customHeaders="Authorization:Bearer {token}" \\',
            '  --set falcosidekick.config.webhook.minimumpriority="warning"',
        ]
    )


def _public_user(user: dict | None) -> dict | None:
    if not user:
        return None
    return {
        "id": user.get("id", ""),
        "email": user.get("email", ""),
        "name": user.get("name", ""),
        "picture": user.get("picture", ""),
        "provider": user.get("provider", ""),
    }


def _is_valid_slack_webhook_url(value: str) -> bool:
    parsed = urlparse(value)
    if parsed.scheme != "https":
        return False
    if parsed.netloc not in {"hooks.slack.com", "hooks.slack-gov.com"}:
        return False
    return parsed.path.startswith("/services/")


def _should_notify_slack(event: dict) -> bool:
    severity = str(event.get("severity", "")).strip().lower()
    priority = str(event.get("priority", "")).strip().lower()
    return severity in {"high", "critical"} or priority in {"high", "critical"}


def _post_slack_message(webhook_url: str, payload: dict) -> None:
    response = httpx.post(webhook_url, json=payload, timeout=5)
    response.raise_for_status()


def _notify_slack_for_event(cluster: dict, event: dict) -> None:
    if not cluster.get("user_id") or not cluster.get("slack_enabled", True):
        return
    if not _should_notify_slack(event):
        return
    settings = storage.get_slack_settings(cluster["user_id"])
    webhook_url = settings.get("webhook_url", "")
    if not webhook_url:
        return
    try:
        _post_slack_message(webhook_url, _slack_event_payload(cluster, event))
    except httpx.HTTPError as error:
        logger.warning(
            "slack notification failed cluster_id=%s event_id=%s error=%s",
            cluster.get("id", ""),
            event.get("id", ""),
            error,
        )


def _slack_event_payload(cluster: dict, event: dict) -> dict:
    severity = str(event.get("severity") or event.get("priority") or "unknown").upper()
    rule = str(event.get("rule") or "Unknown runtime rule")
    namespace = str(event.get("namespace") or "unknown")
    pod_name = str(event.get("pod_name") or "unknown")
    cluster_name = str(event.get("cluster") or cluster.get("name") or "unknown")
    text = f"[{severity}] {rule} on {cluster_name}/{namespace}/{pod_name}"
    return {
        "text": text,
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{severity} runtime event*\n{rule}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Cluster*\n{cluster_name}"},
                    {"type": "mrkdwn", "text": f"*Namespace*\n{namespace}"},
                    {"type": "mrkdwn", "text": f"*Pod*\n{pod_name}"},
                    {"type": "mrkdwn", "text": f"*Container*\n{event.get('container_name') or 'unknown'}"},
                ],
            },
        ],
    }


@app.post("/generate-policy", response_model=PolicyGenerationResponse)
@limiter.limit("5/hour", exempt_when=has_user_llm_key)
def generate(
    request: Request,
    payload: PolicyGenerationRequest,
    x_llm_provider: str | None = Header(default=None),
    x_llm_api_key: str | None = Header(default=None),
) -> PolicyGenerationResponse:
    # 정책 생성
    _ = request
    try:
        return generate_policy(
            payload,
            llm_provider=sanitize_llm_provider(x_llm_provider),
            llm_api_key=sanitize_llm_api_key(x_llm_api_key),
        )
    except UnsupportedPolicyError as error:
        return JSONResponse(
            status_code=400,
            content={
                "error": str(error),
                "examples": SUPPORTED_POLICY_EXAMPLES,
            },
        )


@app.get("/ui", response_class=FileResponse)
def ui() -> FileResponse:
    # 웹 콘솔
    return FileResponse(STATIC_DIR / "index.html")
