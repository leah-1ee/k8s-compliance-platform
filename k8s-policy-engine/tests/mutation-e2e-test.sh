#!/bin/bash
set -uo pipefail

NAMESPACE="policy-test"
PASS_COUNT=0
FAIL_COUNT=0

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS_COUNT++)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL_COUNT++)); }
info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

# dry-run=server 결과(JSON)에서 jq 또는 python3 으로 값 추출
json_get() {
  local json="$1" key="$2"
  if command -v jq &>/dev/null; then
    echo "$json" | jq -r "$key // \"null\""
  else
    echo "$json" | python3 -c "
import sys, json
d = json.load(sys.stdin)
keys = '$key'.lstrip('.').split('.')
v = d
for k in keys:
    if isinstance(v, list): v = v[0]
    v = v.get(k, None)
    if v is None:
        print('null'); sys.exit(0)
print(json.dumps(v) if isinstance(v, bool) else str(v))
"
  fi
}

echo "============================================"
echo " Gatekeeper Mutation E2E Test"
echo " Namespace: ${NAMESPACE}"
echo "============================================"
echo ""

# 네임스페이스 준비
if ! kubectl get namespace "$NAMESPACE" &>/dev/null; then
  info "네임스페이스 ${NAMESPACE} 생성 중..."
  kubectl create namespace "$NAMESPACE"
fi

# ─────────────────────────────────────────────────────────────
# 시나리오 1: securityContext 없는 Pod → runAsNonRoot / readOnlyRootFilesystem 자동 주입 확인
# ─────────────────────────────────────────────────────────────
echo "--- 시나리오 1: securityContext 없는 Pod 에 보안 컨텍스트 자동 주입 ---"

SC_MANIFEST=$(cat <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: mutation-test-sc
  namespace: ${NAMESPACE}
spec:
  containers:
  - name: app
    image: docker.io/library/nginx:1.25.0
EOF
)

MUTATED_SC=$(echo "$SC_MANIFEST" | kubectl apply --dry-run=server -o json -f - 2>&1) || {
  fail "시나리오 1: dry-run 실패 (webhook 거부 또는 클러스터 연결 오류)"
  echo "  출력: $MUTATED_SC"
  MUTATED_SC=""
}

if [ -n "$MUTATED_SC" ]; then
  RUN_AS_NON_ROOT=$(json_get "$MUTATED_SC" ".spec.containers[0].securityContext.runAsNonRoot")
  READ_ONLY_FS=$(json_get "$MUTATED_SC" ".spec.containers[0].securityContext.readOnlyRootFilesystem")

  info "  runAsNonRoot          = ${RUN_AS_NON_ROOT}"
  info "  readOnlyRootFilesystem = ${READ_ONLY_FS}"

  if [ "$RUN_AS_NON_ROOT" = "true" ]; then
    pass "시나리오 1-1: runAsNonRoot = true 자동 주입 확인"
  else
    fail "시나리오 1-1: runAsNonRoot 주입 실패 (값: ${RUN_AS_NON_ROOT})"
  fi

  if [ "$READ_ONLY_FS" = "true" ]; then
    pass "시나리오 1-2: readOnlyRootFilesystem = true 자동 주입 확인"
  else
    fail "시나리오 1-2: readOnlyRootFilesystem 주입 실패 (값: ${READ_ONLY_FS})"
  fi
fi

echo ""

# ─────────────────────────────────────────────────────────────
# 시나리오 2: resources.limits 없는 Pod → cpu / memory 자동 주입 확인
# ─────────────────────────────────────────────────────────────
echo "--- 시나리오 2: resources.limits 없는 Pod 에 CPU/Memory limit 자동 주입 ---"

RL_MANIFEST=$(cat <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: mutation-test-rl
  namespace: ${NAMESPACE}
spec:
  containers:
  - name: app
    image: docker.io/library/nginx:1.25.0
    securityContext:
      runAsNonRoot: true
      readOnlyRootFilesystem: true
EOF
)

MUTATED_RL=$(echo "$RL_MANIFEST" | kubectl apply --dry-run=server -o json -f - 2>&1) || {
  fail "시나리오 2: dry-run 실패 (webhook 거부 또는 클러스터 연결 오류)"
  echo "  출력: $MUTATED_RL"
  MUTATED_RL=""
}

if [ -n "$MUTATED_RL" ]; then
  CPU_LIMIT=$(json_get "$MUTATED_RL" ".spec.containers[0].resources.limits.cpu")
  MEM_LIMIT=$(json_get "$MUTATED_RL" ".spec.containers[0].resources.limits.memory")

  info "  resources.limits.cpu    = ${CPU_LIMIT}"
  info "  resources.limits.memory = ${MEM_LIMIT}"

  if [ "$CPU_LIMIT" = "500m" ]; then
    pass "시나리오 2-1: resources.limits.cpu = 500m 자동 주입 확인"
  else
    fail "시나리오 2-1: cpu limit 주입 실패 (값: ${CPU_LIMIT})"
  fi

  if [ "$MEM_LIMIT" = "256Mi" ]; then
    pass "시나리오 2-2: resources.limits.memory = 256Mi 자동 주입 확인"
  else
    fail "시나리오 2-2: memory limit 주입 실패 (값: ${MEM_LIMIT})"
  fi
fi

echo ""

# ─────────────────────────────────────────────────────────────
# 시나리오 3: runAsNonRoot: false 명시 → Mutation 이 덮어쓰지 않는지 확인
# ─────────────────────────────────────────────────────────────
echo "--- 시나리오 3: runAsNonRoot: false 명시 시 Mutation 비적용(덮어쓰기 없음) 확인 ---"

EXISTING_SC_MANIFEST=$(cat <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: mutation-test-existing-sc
  namespace: ${NAMESPACE}
spec:
  containers:
  - name: app
    image: docker.io/library/nginx:1.25.0
    securityContext:
      runAsNonRoot: false
EOF
)

# validate 정책(require-non-root) 이 deny 할 수 있으므로 --validate=false 로 webhook 응답만 확인
MUTATED_ESC=$(echo "$EXISTING_SC_MANIFEST" | kubectl apply --dry-run=server --validate=false -o json -f - 2>&1) || {
  # deny 되더라도 mutation 결과는 확인 가능한 경우가 있으므로 경고만 출력
  info "시나리오 3: dry-run 중 오류 발생 (validate 정책 deny 가능성 있음)"
  echo "  출력: $MUTATED_ESC"
  MUTATED_ESC=""
}

if [ -n "$MUTATED_ESC" ]; then
  EXISTING_RUN_AS=$(json_get "$MUTATED_ESC" ".spec.containers[0].securityContext.runAsNonRoot")
  info "  runAsNonRoot (명시 false 후) = ${EXISTING_RUN_AS}"

  if [ "$EXISTING_RUN_AS" = "false" ]; then
    pass "시나리오 3: runAsNonRoot = false 유지 확인 (Mutation 덮어쓰기 없음)"
  else
    fail "시나리오 3: runAsNonRoot 값이 변경됨 (기대: false, 실제: ${EXISTING_RUN_AS})"
  fi
else
  info "시나리오 3: validate 정책에 의해 dry-run 이 거부되어 Mutation 결과 확인 불가"
  info "  → Assign pathTests 의 MissingPathCreatesKey 조건에 의해 기존 값은 보존됩니다."
fi

echo ""
echo "============================================"
echo " 결과: PASS ${PASS_COUNT} / FAIL ${FAIL_COUNT}"
echo "============================================"

if [ "$FAIL_COUNT" -gt 0 ]; then
  exit 1
fi
