import logging
import os
import secrets
from contextvars import ContextVar
from pathlib import Path

from fastapi import FastAPI, Header, Request
from fastapi.responses import FileResponse, JSONResponse
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
    build_report,
    fetch_resource_manifest,
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


def _bearer_or_raw_token(value: str | None) -> str:
    normalized = (value or "").strip()
    if normalized.lower().startswith("bearer "):
        return normalized.split(" ", 1)[1].strip()
    return normalized


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
    }


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
) -> dict:
    # Falco/Gatekeeper 최근 위반 이벤트 목록
    return list_runtime_events(
        limit=limit,
        cluster=cluster,
        cluster_kind=cluster_kind,
        source=source,
        include_legacy=include_legacy,
    )


@app.get("/runtime-events/{event_id}")
def runtime_event(event_id: str):
    # 위반 이벤트 상세
    event = get_runtime_event(event_id)
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
    event = record_falco_event(
        payload,
        cluster_id=cluster["id"],
        cluster_name=cluster["name"],
        cluster_kind=cluster.get("kind", "customer"),
        source="sidekick",
    )
    storage.mark_cluster_seen(cluster["id"], event.get("timestamp", ""))
    return {"status": "recorded", "event": event}


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
def resource_manifest(namespace: str = "", pod: str = "") -> dict[str, str]:
    # Kubernetes API에서 관련 Pod 매니페스트 조회
    return fetch_resource_manifest(namespace, pod)


@app.post("/analyze-runtime-event/{event_id}", response_model=ViolationAnalysisResponse)
@limiter.limit("5/hour", exempt_when=has_user_llm_key)
def analyze_runtime_event(
    request: Request,
    event_id: str,
    x_llm_provider: str | None = Header(default=None),
    x_llm_api_key: str | None = Header(default=None),
):
    # 저장된 이벤트와 매니페스트를 결합해 상세 분석
    _ = request
    event = get_runtime_event(event_id)
    if event is None:
        return JSONResponse(status_code=404, content={"error": f"event {event_id} not found"})
    resource_manifest = event.get("resource_manifest", "")
    manifest_result = {"manifest": resource_manifest, "error": ""}
    if not resource_manifest:
        manifest_result = fetch_resource_manifest(event.get("namespace", ""), event.get("pod_name", ""))
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
    if manifest_result.get("error") and not result.llm_error:
        result.llm_error = manifest_result["error"]
    return result


@app.post("/gatekeeper-events")
def gatekeeper_events(payload: dict) -> dict:
    # Gatekeeper deny/audit 이벤트 push 수집
    event = record_gatekeeper_event(payload)
    return {"status": "recorded", "event": event}


@app.get("/compliance-report")
def compliance_report(cluster_kind: str = "", include_legacy: bool = False) -> dict:
    # AI 리포트 탭용 JSON 리포트
    return build_report(cluster_kind=cluster_kind, include_legacy=include_legacy)


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
