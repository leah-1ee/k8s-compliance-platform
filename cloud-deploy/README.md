# 클라우드 배포 파일

이 폴더는 학교 클라우드 서버에서 Git 브랜치를 clone/pull해서 쓰는 배포 파일 모음이다.

## 파일

- `ai-server.yaml`: AI 분류 서버 배포
- `response-server.yaml`: response-server 배포 및 AI endpoint 연결
- `gatekeeper-values.yaml`: Gatekeeper Helm 설치 값
- `monitoring-values.yaml`: Prometheus/Grafana Helm 설치 값
- `apply-policies.sh`: Gatekeeper 정책 적용 스크립트
- `monitoring-servicemonitors.yaml`: Prometheus 메트릭 수집 연결
- `policies/`: ConstraintTemplate, Constraint, Mutation YAML 모음

## VM에서 가져오기

학교 클라우드 서버에서 실행한다.

```bash
cd ~/vscode
git clone -b <브랜치명> <프라이빗레포URL>
cd <레포폴더>/cloud-deploy
```

이미 clone한 repo가 있다면 아래처럼 최신 작업을 받는다.

```bash
cd ~/vscode/<레포폴더>
git fetch
git checkout <브랜치명>
git pull
cd cloud-deploy
```

## Gatekeeper 설치

학교 클라우드 서버에서 실행한다.

```bash
cd ~/vscode/<레포폴더>/cloud-deploy

helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
helm repo update

helm install gatekeeper gatekeeper/gatekeeper \
  -n gatekeeper-system \
  --create-namespace \
  -f gatekeeper-values.yaml
```

```bash
kubectl get pods -n gatekeeper-system
```

## Gatekeeper 정책 적용

학교 클라우드 서버에서 실행한다.

정책 개발/검증 기준 트리는 `k8s-policy-engine/`이고, 이 디렉터리의
`policies/`는 VM에서 바로 적용하기 위한 배포 사본이다. 정책을 수정했다면
배포 전에 두 트리의 `templates/`, `constraints/`, `mutations/`를 동기화한다.

```bash
cd ~/vscode/<레포폴더>/cloud-deploy
chmod +x apply-policies.sh
./apply-policies.sh
```

```bash
kubectl get constrainttemplates
kubectl get constraints
```

`monitoring` namespace는 Prometheus/Grafana 설치를 위해 Validate 및 Mutation 정책 적용 대상에서 제외한다.
`local-path-storage` namespace는 SQLite PVC용 local-path provisioner 설치를 위해 제외한다.
`falco` namespace는 Falco/Falco Sidekick의 privileged, host namespace, hostPath 요구사항 때문에 제외한다.
`docker.io/leeon3345/` 이미지는 demo/ops 이미지 롤아웃을 위해 allow-registries에 포함한다.

배포 전 dry-run:

```bash
kubectl apply --dry-run=server -f policies/templates/
kubectl apply --dry-run=server -f policies/constraints/
kubectl apply --dry-run=server -f policies/mutations/
```

정책 smoke:

```bash
kubectl run allowed-leeon-image \
  --image=docker.io/leeon3345/compliance-ai-server:0.2.14 \
  --restart=Never \
  --dry-run=server
```

```bash
kubectl run denied-latest-image \
  --image=nginx:latest \
  --restart=Never \
  --dry-run=server
```

첫 명령은 통과해야 하고, 두 번째 명령은 `block-latest-tag` 또는
`allow-registries`에 의해 거부되어야 한다.

## AI 서버와 response-server 배포

관리자 토큰 Secret을 먼저 생성한다.

```bash
kubectl create namespace compliance-system --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic ai-classifier-admin \
  -n compliance-system \
  --from-literal=ADMIN_TOKEN="$(openssl rand -hex 32)" \
  --dry-run=client -o yaml | kubectl apply -f -
```

AI 서버는 SQLite를 `/data/compliance-ai-server.sqlite3`에 저장한다. PVC는 `local-path`
StorageClass를 사용하므로, StorageClass가 없다면 먼저 local-path provisioner를 설치한다.

```bash
bash install-local-path-provisioner.sh
kubectl get storageclass
```

SQLite 동시 쓰기를 피하기 위해 AI 서버는 `replicas: 1`과 `strategy.type: Recreate`를
유지해야 한다. `/data`는 파일이 아니라 디렉토리 단위로 mount한다.

```bash
kubectl apply -f ai-server.yaml
kubectl apply -f response-server.yaml
```

```bash
kubectl get deploy,svc,cm,pods -n compliance-system
```

## Prometheus/Grafana 설치

학교 클라우드 서버에서 실행한다.

```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

helm upgrade --install monitoring prometheus-community/kube-prometheus-stack \
  -n monitoring \
  --create-namespace \
  -f monitoring-values.yaml
```

```bash
kubectl get pods -n monitoring
```

## 메트릭 수집 연결

Prometheus Operator CRD가 설치된 뒤 실행한다.

```bash
kubectl apply -f monitoring-servicemonitors.yaml
```

```bash
kubectl get servicemonitor -n monitoring
kubectl get svc -n gatekeeper-system | grep metrics
```

## Grafana 접속

```bash
kubectl port-forward -n monitoring svc/monitoring-grafana 3000:80
```

비밀번호 확인:

```bash
kubectl get secret -n monitoring monitoring-grafana \
  -o jsonpath="{.data.admin-password}" | base64 -d
```
