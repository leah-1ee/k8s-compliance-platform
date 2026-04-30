# AI 서버 테스트

## 로컬 단위 테스트

```bash
.venv/bin/python -m pytest ai-observability/ai-server/tests -q
```

## 로컬 API 실행

```bash
cd ai-observability/ai-server
../../.venv/bin/uvicorn app.main:app --reload --port 8000
```

```bash
curl http://127.0.0.1:8000/healthz
```

## Kubernetes 배포 테스트

아래 단계는 미리 만든 Kubernetes 클러스터에서 실행한다.

주의: 학교 클라우드가 amd64이고 로컬 노트북이 Apple Silicon이면 `docker buildx`로 `linux/amd64` 이미지를 푸시한다.

```bash
docker buildx build --platform linux/amd64 \
  -t [DOCKER_ID]/compliance-ai-server:0.1.0 \
  ai-observability/ai-server \
  --push
```

```bash
docker buildx build --platform linux/amd64 \
  -t [DOCKER_ID]/compliance-response-server:0.1.0 \
  runtime-detection/response-server \
  --push
```

```bash
kubectl apply -f ai-observability/k8s/ai-server.yaml
```

```bash
kubectl rollout status deployment/ai-classifier -n compliance-system
```

## response-server 연동

`ai-observability/k8s/response-server.yaml`은 `AI_ENDPOINT`가 이미 설정된 파일이다.

```bash
kubectl apply -f ai-observability/k8s/response-server.yaml
kubectl rollout status deployment/response-server -n compliance-system
```

## 연동 확인

response-server 로그에서 `AI classification` 또는 `classification severity` 흐름을 확인한다.

```bash
kubectl logs -n compliance-system -l app=response-server --tail=100
kubectl logs -n compliance-system -l app=ai-classifier --tail=100
```
