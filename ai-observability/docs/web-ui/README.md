# KubeOwl Web UI

## Purpose

KubeOwl 웹 UI는 LLM 정책 생성, Gatekeeper 정책 YAML 확인, Falco/Gatekeeper 위반 이벤트 분석을 한 화면에서 수행하기 위한 웹 UI이다.

## Run

```bash
cd ai-observability/ai-server
uvicorn app.main:app --reload --port 8000
```

브라우저에서 접속한다.

```text
http://127.0.0.1:8000/ui
```

공개 문서는 로그인 없이 `/docs` 에서 확인한다.

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
GRAFANA_URL="https://compliance-grafana.shares.zrok.io" uvicorn app.main:app --reload --port 8000
```

## zrok Public Access

학교 클라우드 VM에 Public IP가 없는 경우 zrok public share를 사용해 AI Console과 Grafana를 외부에 공개한다.

최종 접속 주소는 다음 형태를 사용한다.

```text
AI Console: https://compliance-ai-console.shares.zrok.io/ui
Grafana:    https://compliance-grafana.shares.zrok.io
```

`shares.zrok.io`의 `s`를 포함해야 한다.

### Required Processes

아래 프로세스가 VM에서 계속 실행 중이어야 외부 사용자가 URL로 접속할 수 있다.

| Process | Purpose |
|---|---|
| Grafana port-forward | Kubernetes 내부 Grafana 서비스를 VM 로컬 포트로 연결 |
| Grafana zrok share | Grafana 로컬 포트를 고정 public URL로 공개 |
| AI Console server | FastAPI 기반 AI Console 실행 |
| AI Console zrok share | AI Console 로컬 포트를 고정 public URL로 공개 |

### Run Commands

터미널 1에서 Grafana port-forward를 실행한다.

```bash
kubectl port-forward -n monitoring svc/monitoring-grafana 3001:80
```

터미널 2에서 Grafana zrok share를 실행한다.

```bash
cd ~/vscode
./zrok2 share public 3001 -n public:compliance-grafana
```

터미널 3에서 AI Console 서버를 실행한다.

```bash
cd ~/vscode/k8s-compliance-platform/ai-observability/ai-server

GRAFANA_URL="https://compliance-grafana.shares.zrok.io" \
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

터미널 4에서 AI Console zrok share를 실행한다.

```bash
cd ~/vscode
./zrok2 share public 8000 -n public:compliance-ai-console
```

### Health Check

AI Console 서버 상태와 Grafana URL 설정을 확인한다.

```bash
curl http://127.0.0.1:8000/healthz
curl http://127.0.0.1:8000/config
curl -I http://127.0.0.1:8000/ui
```

정상 응답 예시는 다음과 같다.

```json
{"status":"ok"}
```

```json
{"grafana_url":"https://compliance-grafana.shares.zrok.io"}
```

## Notes

- 현재 정책 생성은 재현 가능한 템플릿 기반으로 동작한다.
- `/docs` 는 공개 진입점이며 로그인 없이 접근 가능해야 한다.
- LLM API 연동 시 `LLM_API_URL`, `LLM_API_KEY`, `LLM_MODEL` 환경 변수를 사용한다.
- LLM 응답 장애 시 템플릿 기반 정책 생성 결과를 유지한다.
- 기본 제외 네임스페이스는 `kube-system`, `gatekeeper-system`, `kube-flannel`, `monitoring` 이다.
- 생성된 정책은 적용 전 테스트 네임스페이스에서 검증한다.
- zrok URL은 `zrok2 share public` 프로세스가 실행 중일 때만 접근 가능하다.
