# KubeOwl

KubeOwl은 Policy-as-Code 기반 Kubernetes 컴플라이언스 자동화 플랫폼입니다.  
Gatekeeper 정책 생성, Falco 런타임 탐지, AI 분석, 대시보드, 관리자 검토 흐름을 한 번에 다룹니다.

## 공개 진입점

- `/` - 랜딩 페이지
- `/docs` - 공개 문서
- `/ui` - 사용자 콘솔
- `/admin` - 관리자 콘솔

## 핵심 구성

- OPA / Gatekeeper
- Falco / Falco Sidekick
- FastAPI
- Prometheus / Grafana
- LLM 기반 정책 생성과 이벤트 분석

## 현재 작업 기준

- 현재 이미지 기준은 `docker.io/leeon3345/compliance-ai-server:0.2.10` 입니다.
- 로컬 테스트는 프로젝트 루트에서 `.venv/bin/python -m pytest ai-observability/ai-server/tests/` 로 실행합니다.
- 문서와 demo 흐름은 현재 구현된 `/docs`, `/ui`, `/admin` 동작과 맞춰 유지합니다.

## 개발 기간

2026.04 ~ 2026.06 (12주)
