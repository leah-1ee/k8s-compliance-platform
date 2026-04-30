#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICY_DIR="${SCRIPT_DIR}/policies"

echo "==> 클러스터 연결 확인"
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

  echo "$files" | while read -r file; do
    echo "    kubectl apply -f ${file}"
    kubectl apply -f "$file"
  done

  echo "==> [${label}] 완료"
  echo ""
}

# 적용 순서
apply_dir "${POLICY_DIR}/templates" "1/3 ConstraintTemplates"
apply_dir "${POLICY_DIR}/constraints" "2/3 Constraints"
apply_dir "${POLICY_DIR}/mutations" "3/3 Mutations"

echo "==> 모든 Gatekeeper 정책 적용 완료"
