import logging
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

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

app = FastAPI(
    title="Compliance AI Server",
    version="0.1.0",
    description="Falco 이벤트 분류 및 컴플라이언스 AI API",
)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/config")
def config() -> dict[str, str]:
    # UI 설정
    return {"grafana_url": os.getenv("GRAFANA_URL", "").strip()}


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
def analyze(payload: ViolationAnalysisRequest) -> ViolationAnalysisResponse:
    # 위반 분석
    return analyze_violation(payload)


@app.post("/generate-policy", response_model=PolicyGenerationResponse)
def generate(payload: PolicyGenerationRequest) -> PolicyGenerationResponse:
    # 정책 생성
    return generate_policy(payload)


@app.get("/ui", response_class=FileResponse)
def ui() -> FileResponse:
    # 웹 콘솔
    return FileResponse(STATIC_DIR / "index.html")
