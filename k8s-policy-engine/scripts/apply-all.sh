#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICY_DIR="$(dirname "$SCRIPT_DIR")"

# 클러스터 연결 확인
echo "==> 클러스터 연결 확인 중..."
if ! kubectl cluster-info > /dev/null 2>&1; then
  echo "[오류] kubectl이 클러스터에 연결되어 있지 않습니다. kubeconfig를 확인하세요."
  exit 1
fi
kubectl cluster-info
echo ""

apply_dir() {
  local dir="$1"
  local label="$2"

  echo "==> [${label}] 적용 시작: ${dir}"

  if [ ! -d "$dir" ]; then
    echo "[오류] 정책 디렉터리가 없습니다: ${dir}"
    exit 1
  fi

  local files
  files=$(find "$dir" -maxdepth 1 -type f \( -name "*.yaml" -o -name "*.yml" \) | sort)

  if [ -z "$files" ]; then
    echo "[오류] 적용할 YAML 파일이 없습니다: ${dir}"
    exit 1
  fi

  echo "$files" | while read -r f; do
    echo "    kubectl apply -f ${f}"
    kubectl apply -f "$f"
  done

  echo "==> [${label}] 완료"
  echo ""
}

# 적용 순서: templates → constraints → mutations
# - templates  : ConstraintTemplate (Rego 정책 정의)
# - constraints: Constraint (정책 인스턴스, 적용 대상/파라미터 설정)
# - mutations  : MutationPolicy (리소스 자동 변환 규칙)
apply_dir "${POLICY_DIR}/templates"   "1/3 ConstraintTemplates"
apply_dir "${POLICY_DIR}/constraints" "2/3 Constraints"
apply_dir "${POLICY_DIR}/mutations"   "3/3 Mutations"

echo "==> 모든 정책 적용 완료"
