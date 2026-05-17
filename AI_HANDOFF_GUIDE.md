# AI Handoff Guide

이 문서는 새 대화창에서 이어 작업하는 AI가 현재 상태와 운영 규칙을 바로 이해하기 위한 인수인계 문서다.
코드 수정이 발생하면 이 문서의 진행상황, 이미지 버전, 적용 명령도 함께 갱신한다.

## 현재 진행상황

- Gatekeeper 정책 생성/검토 UI는 로그인 없이 사용 가능하다.
- Google OAuth 코드와 개발 로그인(`/auth/dev-login`)이 추가되어 있고, Google Secret 없이도 테스트할 수 있다.
- SQLite 저장소, PVC 영속화, WAL 모드가 적용되어 있다.
- 백엔드 Pod는 SQLite 동시 쓰기 문제를 피하기 위해 `replicas: 1`, `strategy.type: Recreate` 방향을 유지한다.
- `/admin` 관리자 콘솔에서 클러스터 등록, token 발급/재발급, 비활성화가 가능하다.
- Falco Sidekick은 `/ingest/falco-events`로 이벤트를 전송하고 ingest token으로 검증된다.
- `cluster_id`, `cluster_kind`가 저장되고 demo/customer/source/legacy 필터가 존재한다.
- 최근 작업으로 사용자별 클러스터 귀속이 시작됐다.
- `clusters.user_id`가 추가됐고, 로그인 사용자는 `/ui`의 `Cluster Setup` 탭에서 자기 클러스터를 등록할 수 있다.
- `Cluster Setup` 탭은 클러스터 이름 입력, 등록, Falco Sidekick 설치 명령 표시, last seen 확인, token 재발급을 제공한다.
- 로그인한 사용자의 `/runtime-events`, 이벤트 상세, AI report는 해당 사용자의 클러스터 이벤트만 보도록 스코프가 적용됐다.

## 아직 남은 중요한 작업

- 런타임 탭 자체를 로그인 필수 UI로 명확히 막아야 한다.
- Violation Detail, AI Report, Cluster Setup, Slack 설정 영역은 로그인하지 않으면 안내 메시지를 보여줘야 한다.
- 관리자 대시보드는 전체 사용자 목록, 사용자별 클러스터 목록, active/disabled 상태, last seen, 이벤트 수를 볼 수 있게 정리해야 한다.
- 중앙 AI 서버가 K8s API를 직접 조회하는 매니페스트 조회 구조는 사용자 클러스터 서비스 구조에 맞지 않는다.
- 1차 fallback은 사용자 클러스터에서 실행할 `kubectl` 명령 제공, 2차는 collector/agent가 manifest snapshot을 함께 보내는 구조로 검토한다.
- Violation Detail 품질 개선이 필요하다: 이벤트 원인, 위험도, 수정 방법, 수정 YAML, 복사 가능한 코드블록, 매니페스트 없을 때 fallback 분석.
- Slack 알림 설정이 아직 없다: 사용자별 Slack webhook URL, 테스트 알림, High/Critical만 전송 옵션, 클러스터별 on/off가 필요하다.
- Google OAuth 실연동은 카드/Google Cloud 문제 해결 후 dev-login 비활성화와 함께 마무리한다.
- zrok 수동 실행 안정화 스크립트, 이미지 태그/배포 절차 문서화, SQLite 백업/초기화 방법, 데모 데이터 정리 명령이 필요하다.

## 현재 인증 상태

- Google OAuth 코드는 구현되어 있지만 실제 Google Client ID/Secret은 아직 설정하지 않는다.
- Google Cloud Console 설정 중 카드 정보 입력이 요구되어 실연동은 보류한다.
- 현재 개발/시연은 `DEV_AUTH_ENABLED=true` 기반 개발 로그인을 사용한다.
- 운영 배포 시에는 `DEV_AUTH_ENABLED=false`로 끄고 Google OAuth 또는 학교 SSO로 전환한다.

VM에서 개발 로그인을 활성화할 때는 아래 명령을 사용한다.

```bash
kubectl set env deploy/ai-classifier -n compliance-system \
  DEV_AUTH_ENABLED=true \
  DEV_AUTH_EMAIL=demo@school.test \
  DEV_AUTH_NAME="Demo User"

kubectl rollout status deploy/ai-classifier -n compliance-system --timeout=180s
```

확인 명령:

```bash
curl -s http://127.0.0.1:18000/me | python3 -m json.tool

kubectl exec -n compliance-system deploy/ai-classifier -- \
  python -c "from app.main import app; print([r.path for r in app.routes if 'auth' in r.path or r.path == '/me'])"
```

정상 라우트 예시:

```text
['/me', '/auth/google/login', '/auth/google/callback', '/auth/dev-login']
```

`/me`가 404이면 코드 문제가 아니라 대개 새 이미지가 아직 VM에 배포되지 않은 상태다.

## Git 작업 규칙

코드 수정 후에는 사용자에게 아래 정보를 반드시 보여준다.

1. 수정 요약 2~3줄
2. 검증 결과
3. `git add`, `git commit`, `git push` 명령
4. VM/클러스터 적용 명령

기존 작업 트리에 사용자가 만든 변경이 있을 수 있으므로, 내가 수정한 파일만 `git add`에 명시한다.
불필요한 `git reset --hard`, `git checkout --`, 대량 revert는 하지 않는다.

커밋 메시지는 예를 들어 아래처럼 2~3줄 본문을 붙인다.

```bash
git commit -m "feat(ai-server): add user-owned cluster setup" \
  -m "Scope clusters and runtime events to logged-in users." \
  -m "Add Cluster Setup UI with Sidekick install command and token rotation."
```

현재 작업 브랜치는 다음을 기준으로 한다.

```bash
ai-observability-leeon
```

## Docker 이미지 버전 규칙

- 사용자가 알려준 마지막 수정 이미지 버전은 `0.1.5`다.
- 다음 코드 수정 배포 버전은 `0.1.6`부터 사용한다.
- 이후 수정할 때마다 patch 버전을 하나씩 올린다. 예: `0.1.6`, `0.1.7`, `0.1.8`.
- 이미지 이름은 `docker.io/leeon3345/compliance-ai-server:<version>` 형식을 사용한다.
- 로컬 Docker Desktop/Apple Silicon 환경에서 클러스터용 이미지는 `linux/amd64`로 buildx 빌드 후 바로 push한다.

이미지 빌드/푸시 명령 예시는 다음 형식을 사용한다.

```bash
cd /Users/leeon/Documents/k8s-compliance-platform

docker buildx build --platform linux/amd64 \
  -t docker.io/leeon3345/compliance-ai-server:0.1.6 \
  ai-observability/ai-server \
  --push
```

## VM/클러스터 적용 명령 규칙

사용자는 앞으로 아래 형식을 선호한다.

```bash
kubectl set image deploy/ai-classifier -n compliance-system \
  ai-classifier=docker.io/leeon3345/compliance-ai-server:0.1.6

kubectl rollout status deploy/ai-classifier -n compliance-system --timeout=180s
```

필요하면 상태 확인을 이어서 제공한다.

```bash
kubectl get pods -n compliance-system -l app=ai-classifier
kubectl logs -n compliance-system deploy/ai-classifier --tail=100
```

배포 후에는 현재 Pod 이미지와 라우트를 반드시 확인한다.

```bash
kubectl get deploy -n compliance-system ai-classifier \
  -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}'

kubectl exec -n compliance-system deploy/ai-classifier -- \
  python -c "from app.main import app; print([r.path for r in app.routes])"

curl -s http://127.0.0.1:18000/healthz
curl -s http://127.0.0.1:18000/me | python3 -m json.tool
```

## 터널/포트포워딩 운영 메모

데모 환경은 아래 로컬 포트가 살아 있어야 한다.

- AI Console: `127.0.0.1:18000 -> ai-classifier:8000`
- Response Server: `127.0.0.1:5000 -> response-server:5000`
- Grafana: `127.0.0.1:3001 -> monitoring-grafana:80`

zrok 공개 주소:

- AI Console: `https://compliance-ai-console.shares.zrok.io/ui`
- Admin: `https://compliance-ai-console.shares.zrok.io/admin`
- Grafana: `https://compliance-grafana.shares.zrok.io`

`zrok`에서 `connect: connection refused`가 뜨면 zrok 문제가 아니라 해당 로컬 포트포워딩이 죽은 것이다.
`502`가 뜨면 stale zrok share일 가능성이 높으므로 share 삭제 후 재실행한다.

상태 확인:

```bash
sudo lsof -iTCP:18000 -sTCP:LISTEN -n -P
sudo lsof -iTCP:3001 -sTCP:LISTEN -n -P
sudo lsof -iTCP:5000 -sTCP:LISTEN -n -P
ps aux | grep -E "port-forward|zrok2 share public"

curl -o /dev/null -s -w "%{http_code}\n" http://127.0.0.1:18000/ui
curl -o /dev/null -s -w "%{http_code}\n" https://compliance-ai-console.shares.zrok.io/ui
curl -o /dev/null -s -w "%{http_code}\n" https://compliance-ai-console.shares.zrok.io/admin
```

정상 기대값은 `200`, `200`, `200`이다.

## Gatekeeper 관련 주의점

- `allow-registries` 정책 때문에 `docker.io/leeon3345/`가 허용되어 있어야 ai-classifier 이미지 롤아웃이 된다.
- local-path provisioner 설치 시 `local-path-storage` namespace가 Gatekeeper 예외에 포함되어 있어야 한다.
- rollout이 멈추면 먼저 admission webhook 또는 PVC 이벤트를 확인한다.

확인 명령:

```bash
kubectl get events -A --sort-by=.lastTimestamp | tail -40
kubectl describe pod -n compliance-system -l app=ai-classifier
kubectl get constraints
kubectl get k8sallowedrepos.constraints.gatekeeper.sh allow-registries -o yaml | grep -A20 repos
```

## 최근 수정 파일

사용자별 클러스터 귀속과 Cluster Setup 작업에서 수정한 파일은 다음과 같다.

```text
ai-observability/ai-server/app/storage.py
ai-observability/ai-server/app/runtime_client.py
ai-observability/ai-server/app/main.py
ai-observability/ai-server/app/static/index.html
ai-observability/ai-server/app/static/app.js
ai-observability/ai-server/app/static/styles.css
ai-observability/ai-server/tests/conftest.py
ai-observability/ai-server/tests/test_api.py
ai-observability/k8s/ai-server.yaml
cloud-deploy/ai-server.yaml
AI_HANDOFF_GUIDE.md
```

검증 명령:

```bash
cd /Users/leeon/Documents/k8s-compliance-platform/ai-observability/ai-server
/Users/leeon/Documents/k8s-compliance-platform/.venv/bin/python -m pytest
```

최근 검증 결과:

```text
41 passed, 14 warnings
```
