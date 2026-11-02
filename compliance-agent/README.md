# Compliance Agent

사용자 Kubernetes 클러스터에 설치하는 런타임 이벤트 수집 에이전트입니다.

## 역할

- Falco HTTP webhook 이벤트를 수신합니다.
- 이벤트의 namespace/pod 정보를 기준으로 Kubernetes API에서 Pod manifest snapshot을 조회합니다.
- 중앙 AI Console의 `/ingest/falco-events` endpoint로 이벤트와 manifest를 전송합니다.

## 설치

중앙 AI Console URL을 지정해 설치합니다.

```bash
cd compliance-agent

CENTRAL_INGEST_URL="https://compliance-ai-console.example.com/ingest/falco-events" \
CLUSTER_NAME="customer-cluster-a" \
./install-agent.sh
```

API key를 쓰는 환경이면 `CENTRAL_API_KEY`를 같이 넘깁니다.

```bash
CENTRAL_INGEST_URL="https://compliance-ai-console.example.com/ingest/falco-events" \
CENTRAL_API_KEY="..." \
CLUSTER_NAME="customer-cluster-a" \
./install-agent.sh
```

## 설치되는 구성

- `Namespace/compliance-system`
- `ServiceAccount/compliance-agent`
- read-only `ClusterRole` / `ClusterRoleBinding`
- `Deployment/compliance-agent`
- `Service/compliance-agent`
- Helm이 있으면 Falco chart 설치 또는 업데이트

Falco는 다음 endpoint로 이벤트를 보냅니다.

```text
http://compliance-agent.compliance-system.svc.cluster.local:8080/webhook
```

## 확인

```bash
kubectl get pods -n compliance-system -l app=compliance-agent
kubectl logs -n compliance-system deploy/compliance-agent --tail=100
kubectl get pods -n falco
```

중앙 AI Console에서 `Violation Detail`의 `최근 위반 새로고침`을 누르면 해당 클러스터 이벤트가 표시됩니다.
