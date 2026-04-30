# AI 서버 Kubernetes 배포

## 파일 역할

이 폴더의 `ai-server.yaml`은 AI 분류 서버를 배포한다.

`response-server.yaml`은 기존 런타임 탐지 response-server를 AI 서버와 연결된 상태로 배포한다.

`ai-server.yaml`로 생성되는 리소스:

- `Namespace/compliance-system`
- `Deployment/ai-classifier`
- `Service/ai-classifier`

`response-server.yaml`로 생성되는 리소스:

- `Deployment/response-server`
- `ConfigMap/response-server-config`
- `Service/response-server`

`response-server-config`의 `AI_ENDPOINT`는 아래 주소로 미리 설정되어 있다.

```text
http://ai-classifier.compliance-system.svc.cluster.local:8000/classify
```

## 이미지 빌드 및 푸시

Apple Silicon 노트북에서 amd64 클라우드 클러스터로 배포할 때는 `buildx`로 linux/amd64 이미지를 푸시한다.

### AI 서버 이미지

```bash
docker buildx build --platform linux/amd64 \
  -t leeon3345/compliance-ai-server:0.1.0 \
  ai-observability/ai-server \
  --push
```

### response-server 이미지

```bash
docker buildx build --platform linux/amd64 \
  -t leeon3345/compliance-response-server:0.1.0 \
  runtime-detection/response-server \
  --push
```

## 배포 순서

### 1. AI 서버 배포

```bash
kubectl apply -f ai-observability/k8s/ai-server.yaml
kubectl rollout status deployment/ai-classifier -n compliance-system
```

### 2. response-server 배포

`response-server.yaml`은 `AI_ENDPOINT`가 이미 설정된 파일이다.

```bash
kubectl apply -f ai-observability/k8s/response-server.yaml
kubectl rollout status deployment/response-server -n compliance-system
```

### 3. 배포 확인

```bash
kubectl get deploy,svc,cm -n compliance-system
```

## 오류 처리

### `configmaps "response-server-config" not found`

원인: `response-server`가 아직 배포되지 않았거나 다른 namespace에 배포된 상태.

확인:

```bash
kubectl get deploy,svc,cm -A | grep response
```

해결:

```bash
kubectl apply -f ai-observability/k8s/response-server.yaml
kubectl get configmap response-server-config -n compliance-system
```
