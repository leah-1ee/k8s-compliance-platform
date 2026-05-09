# Compliance AI Console

## Purpose

Compliance AI Console은 LLM 정책 생성, Gatekeeper 정책 YAML 확인, Falco/Gatekeeper 위반 이벤트 분석을 한 화면에서 수행하기 위한 웹 UI이다.

## Run

```bash
cd ai-observability/ai-server
uvicorn app.main:app --reload --port 8000
```

브라우저에서 접속한다.

```text
http://127.0.0.1:8000/ui
```

## APIs

| API | Purpose |
|---|---|
| `POST /generate-policy` | 자연어 정책 요청을 Gatekeeper ConstraintTemplate, Constraint, Rego 또는 Assign Mutation YAML로 변환 |
| `POST /analyze-violation` | 위반 이벤트 JSON을 심각도, 신뢰도, 대응 권고로 분석 |
| `POST /classify` | Response Server 연동용 Falco 이벤트 분류 |
| `GET /config` | 웹 UI의 Grafana 링크 설정 제공 |

## Policy Coverage

| Type | Supported Policy |
|---|---|
| Validate | latest 태그 금지 |
| Validate | non-root 강제 |
| Validate | 허용 레지스트리 제한 |
| Validate | host namespace 금지 |
| Mutation | securityContext 자동 주입 |
| Mutation | resource limits 자동 주입 |

## Grafana Link

웹 UI의 Grafana 버튼은 `GRAFANA_URL` 환경 변수를 사용한다.

```bash
GRAFANA_URL="https://example.trycloudflare.com" uvicorn app.main:app --reload --port 8000
```

## Notes

- 현재 정책 생성은 재현 가능한 템플릿 기반으로 동작한다.
- LLM API 연동 시 `LLM_API_URL`, `LLM_API_KEY`, `LLM_MODEL` 환경 변수를 사용한다.
- LLM 응답 장애 시 템플릿 기반 정책 생성 결과를 유지한다.
- 기본 제외 네임스페이스는 `kube-system`, `gatekeeper-system`, `kube-flannel`, `monitoring` 이다.
- 생성된 정책은 적용 전 테스트 네임스페이스에서 검증한다.
