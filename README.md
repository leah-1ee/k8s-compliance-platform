# KubeOwl

KubeOwl은 Policy-as-Code 기반 Kubernetes 컴플라이언스 자동화 플랫폼입니다.
Gatekeeper 정책 생성, Falco 런타임 탐지, AI 분석, 대시보드, 관리자 검토 흐름을 한 번에 다룹니다.

## 서비스 URL

- 사용자 콘솔: [https://compliance-ai-console.shares.zrok.io/ui](https://compliance-ai-console.shares.zrok.io/ui)
- 관리자 콘솔: [https://compliance-ai-console.shares.zrok.io/admin](https://compliance-ai-console.shares.zrok.io/admin)

관리자 콘솔은 관리자 토큰이 있어야 기능을 사용할 수 있습니다. zrok public share가
실행 중일 때만 외부에서 접속할 수 있습니다.

## 저장소 구조

- `k8s-policy-engine/` - Gatekeeper 정책, Helm values, 정책 테스트
- `runtime-detection/` - Falco 규칙, Response Server, 런타임 배포 매니페스트
- `ai-observability/` - FastAPI 기반 중앙 콘솔, Grafana 대시보드, AI/모니터링 배포 파일
- `compliance-agent/` - 사용자 클러스터의 Falco 이벤트 수집 에이전트

각 배포 파일은 소유 모듈 안에만 두며 중복 배포 사본은 유지하지 않습니다.

## 빠른 검증

```bash
.venv/bin/python -m pytest ai-observability/ai-server/tests/
python3 runtime-detection/response-server/tests/test_all.py
python3 runtime-detection/response-server/tests/test_integration.py
make -C k8s-policy-engine test
```

OPA CLI나 Kubernetes 클러스터가 필요한 검증은 각 모듈 README를 따릅니다.

## 배포 진입점

- AI 서버와 모니터링: `ai-observability/deploy/`
- Response Server와 Falco: `runtime-detection/manifests/`, `runtime-detection/scripts/`
- Gatekeeper: `k8s-policy-engine/helm/`, `k8s-policy-engine/scripts/`

현재 AI 서버 배포 이미지 기준은 `docker.io/leeon3345/compliance-ai-server:0.2.48`입니다.

프로젝트 개발 과정의 AI 활용 방식과 검증 원칙은 [`AI_USAGE.md`](AI_USAGE.md)에 정리했습니다.
