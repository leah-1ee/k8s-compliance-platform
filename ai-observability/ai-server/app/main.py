import logging
import os
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
RATE_LIMIT_MESSAGE = "Rate limit exceeded. Please provide your own API key to continue."
current_request: ContextVar[Request | None] = ContextVar("current_request", default=None)


def has_user_llm_key() -> bool:
    # 사용자 키 여부
    request = current_request.get()
    if request is None:
        return False
    return bool(request.headers.get("x-llm-api-key", "").strip())


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
    return {"grafana_url": os.getenv("GRAFANA_URL", DEFAULT_GRAFANA_URL).strip()}


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
    _ = (request, x_llm_provider, x_llm_api_key)
    return analyze_violation(payload)


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
    return generate_policy(
        payload,
        llm_provider=x_llm_provider,
        llm_api_key=x_llm_api_key,
    )


@app.get("/ui", response_class=FileResponse)
def ui() -> FileResponse:
    # 웹 콘솔
    return FileResponse(STATIC_DIR / "index.html")
