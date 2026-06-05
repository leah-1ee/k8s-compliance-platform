# AI Observability Deployment

중앙 AI 콘솔과 Prometheus/Grafana를 Kubernetes에 배포하는 파일입니다.

## AI 서버

관리자 토큰 Secret을 먼저 생성합니다.

```bash
kubectl create namespace compliance-system --dry-run=client -o yaml | kubectl apply -f -
kubectl create secret generic ai-classifier-admin \
  -n compliance-system \
  --from-literal=ADMIN_TOKEN="$(openssl rand -hex 32)" \
  --dry-run=client -o yaml | kubectl apply -f -
```

`local-path` StorageClass가 없다면 provisioner를 설치한 뒤 AI 서버를 배포합니다.

```bash
bash ai-observability/deploy/install-local-path-provisioner.sh
kubectl apply -f ai-observability/deploy/ai-server.yaml
kubectl apply -f ai-observability/deploy/ai-server-ingress.yaml
kubectl apply -f ai-observability/deploy/ai-server-cleanup-cronjob.yaml
```

## 모니터링

```bash
helm upgrade --install monitoring prometheus-community/kube-prometheus-stack \
  -n monitoring \
  --create-namespace \
  -f ai-observability/deploy/monitoring/monitoring-values.yaml

kubectl apply -f ai-observability/deploy/monitoring/monitoring-servicemonitors.yaml
```

관리자 전용 Grafana release는
`ai-observability/deploy/monitoring/admin-grafana-values.yaml`을 사용합니다.

Gatekeeper와 Runtime Detection 배포는 각각 `k8s-policy-engine/`과
`runtime-detection/`을 참고합니다.
