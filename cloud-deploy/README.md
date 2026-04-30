# 클라우드 배포 파일

이 폴더는 학교 클라우드 서버에서 Git 브랜치를 clone/pull해서 쓰는 배포 파일 모음이다.

## 파일

- `ai-server.yaml`: AI 분류 서버 배포
- `response-server.yaml`: response-server 배포 및 AI endpoint 연결
- `gatekeeper-values.yaml`: Gatekeeper Helm 설치 값
- `apply-policies.sh`: Gatekeeper 정책 적용 스크립트
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

```bash
cd ~/vscode/<레포폴더>/cloud-deploy
chmod +x apply-policies.sh
./apply-policies.sh
```

```bash
kubectl get constrainttemplates
kubectl get constraints
```

## AI 서버와 response-server 배포

```bash
kubectl apply -f ai-server.yaml
kubectl apply -f response-server.yaml
```

```bash
kubectl get deploy,svc,cm,pods -n compliance-system
```
