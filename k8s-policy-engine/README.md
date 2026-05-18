# k8s-policy-engine

Kubernetes 클러스터 보안 정책을 OPA Gatekeeper로 자동화하는 정책 엔진입니다.
ConstraintTemplate(Rego 정책 정의), Constraint(정책 적용), Assign(자동 Mutation)으로 구성됩니다.

- **OPA Gatekeeper**: Helm chart 기준 `v3.14+` 지원, 본 저장소의 정책/예시는 `v3.22` 기준으로 검증
- `assign-*` Mutation 정책은 Gatekeeper mutation CRD가 활성화된 환경을 전제로 합니다.
- **Rego** (OPA v1.x 문법)
- **Helm** (Gatekeeper 설치)

---

## 정책 목록

| 정책명 | 종류 | 적용 대상 | enforcement | ISMS-P 매핑 |
|--------|------|-----------|:-----------:|-------------|
| require-non-root | Validate | Pod containers / initContainers | deny | 2.9.1 시스템 및 서비스 운영관리 |
| allow-registries | Validate | Pod containers | deny | 2.9.1 시스템 및 서비스 운영관리 |
| block-host-namespaces | Validate | Pod | deny | 2.9.1 시스템 및 서비스 운영관리 |
| block-latest-tag | Validate | Pod containers / initContainers / ephemeralContainers | deny | 2.9.1 시스템 및 서비스 운영관리 |
| assign-security-context | Mutation | Pod containers / initContainers | - | 2.9.1 시스템 및 서비스 운영관리 |
| assign-resource-limits | Mutation | Pod containers / initContainers | - | 2.9.1 시스템 및 서비스 운영관리 |

> 모든 정책은 `kube-system`, `gatekeeper-system`, `kube-flannel`, `monitoring`, `local-path-storage` 네임스페이스에 적용되지 않습니다.

## 운영 소스 오브 트루스

`k8s-policy-engine/`은 Gatekeeper 정책의 개발/검증 기준 트리입니다. Rego 테스트,
Mutation E2E, 적용 스크립트가 이 디렉터리를 기준으로 동작합니다.

학교 클라우드 VM에서 바로 적용하는 배포 사본은 `cloud-deploy/policies/`입니다.
배포 전에는 두 트리의 `templates/`, `constraints/`, `mutations/`가 동기화되어야 합니다.

```bash
diff -rq -x README.md -x Makefile -x scripts -x tests -x helm -x .gitkeep \
  cloud-deploy/policies k8s-policy-engine
```

현재 demo/ops 요구사항으로 유지하는 예외는 다음과 같습니다.

- `local-path-storage`: SQLite PVC용 local-path provisioner가 정책에 막히지 않도록 제외
- `docker.io/leeon3345/`: 직접 빌드/푸시한 demo 이미지를 allow-registries에 허용

---

## 파라미터 설명

### allow-registries — `spec.parameters.repos`

컨테이너 이미지가 반드시 아래 prefix 중 하나로 시작해야 합니다.
prefix 끝에 `/`를 포함해야 prefix 우회를 방지할 수 있습니다.

```yaml
parameters:
  repos:
    - "docker.io/library/"   # Docker Hub 공식 이미지
    - "docker.io/leeon3345/" # demo/ops 이미지
    - "gcr.io/"              # Google Container Registry
    - "ghcr.io/"             # GitHub Container Registry
    - "registry.k8s.io/"    # Kubernetes 공식 이미지
```

다른 레지스트리를 허용하려면 `constraints/allow-registries.yaml`의 `repos` 배열에 항목을 추가하세요.

---

## Mutation 동작 예시

### securityContext 자동 주입 (assign-security-context)

**적용 전**
```yaml
spec:
  containers:
  - name: app
    image: docker.io/library/nginx:1.25.0
```

**적용 후** (Gatekeeper Assign Mutation)
```yaml
spec:
  containers:
  - name: app
    image: docker.io/library/nginx:1.25.0
    securityContext:
      runAsNonRoot: true
      readOnlyRootFilesystem: true
```

> 이미 값이 명시된 경우(`MustNotExist` 조건) Mutation이 적용되지 않아 기존 값이 유지됩니다.

---

### resources.limits 자동 주입 (assign-resource-limits)

**적용 전**
```yaml
spec:
  containers:
  - name: app
    image: docker.io/library/nginx:1.25.0
```

**적용 후** (Gatekeeper Assign Mutation)
```yaml
spec:
  containers:
  - name: app
    image: docker.io/library/nginx:1.25.0
    resources:
      limits:
        cpu: "500m"
        memory: "256Mi"
```

> `initContainers`에도 동일하게 적용됩니다 (`assign-*-init` Assign 리소스).

---

## 메트릭

Gatekeeper Audit Pod의 8888 포트에서 Prometheus 메트릭을 제공합니다.

**포트포워드**
```bash
kubectl port-forward -n gatekeeper-system \
  deployment/gatekeeper-audit 8888:8888
```

**메트릭 확인**
```bash
curl -s http://localhost:8888/metrics | grep -E "gatekeeper_violations|gatekeeper_audit_last_run_time"
```

**주요 메트릭**

| 메트릭 | 설명 |
|--------|------|
| `gatekeeper_violations` | 정책 위반 건수. `enforcement_action` 라벨로 `deny` / `warn` 구분 |
| `gatekeeper_audit_last_run_time` | 마지막 Audit 실행 시각 (Unix timestamp) |

**라벨 구조 예시**
```
gatekeeper_violations{
  enforcement_action="deny",
  kind="Pod",
  name="require-non-root",
  namespace="default"
} 3
```

---

## 로컬 테스트

의존성: [OPA CLI](https://www.openpolicyagent.org/docs/latest/#running-opa) (`opa`)

```bash
# Rego 단위 테스트 실행
make test

# Rego 포맷 검사
make lint

# 클러스터에 전체 정책 적용 (templates → constraints → mutations 순)
make apply

# Mutation E2E 테스트 (클러스터 + Gatekeeper 설치 필요)
bash tests/mutation-e2e-test.sh
```

## 배포 전 검증

클러스터와 Gatekeeper CRD가 있는 환경에서 실행합니다.

```bash
kubectl apply --dry-run=server -f templates/
kubectl apply --dry-run=server -f constraints/
kubectl apply --dry-run=server -f mutations/
```

허용 이미지 smoke:

```bash
kubectl run allowed-leeon-image \
  --image=docker.io/leeon3345/compliance-ai-server:0.1.13 \
  --restart=Never \
  --dry-run=server
```

거부 이미지 smoke:

```bash
kubectl run denied-latest-image \
  --image=nginx:latest \
  --restart=Never \
  --dry-run=server
```

`allowed-leeon-image`는 admission을 통과해야 하고, `denied-latest-image`는
`block-latest-tag` 또는 `allow-registries` 정책에 의해 거부되어야 합니다.

**디렉토리 구조**
```
k8s-policy-engine/
├── templates/       # ConstraintTemplate (Rego 정책 정의)
├── constraints/     # Constraint (정책 인스턴스, 적용 대상/파라미터)
├── mutations/       # Assign (자동 기본값 주입)
├── tests/
│   ├── policy/      # 테스트용 독립 Rego 파일 (templates에서 추출)
│   ├── *_test.rego  # OPA 단위 테스트
│   └── mutation-e2e-test.sh
├── scripts/
│   ├── apply-all.sh
│   └── k8s-setup.sh
└── Makefile
```
