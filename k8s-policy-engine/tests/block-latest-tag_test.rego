package k8sblocklatesttag

import rego.v1

# ─── 공통 헬퍼 ──────────────────────────────────────────────

make_input(image) = {"review": {"object": {
  "metadata": {"name": "test-pod"},
  "spec": {
    "containers": [{"name": "app", "image": image}],
    "initContainers": [],
  },
}}}

make_input_init(image) = {"review": {"object": {
  "metadata": {"name": "test-pod"},
  "spec": {
    "containers": [{"name": "app", "image": "nginx:1.25.0"}],
    "initContainers": [{"name": "init", "image": image}],
  },
}}}

# ─── Deny cases ─────────────────────────────────────────────

# ":latest" 태그 명시
test_deny_latest_tag if {
  result := data.k8sblocklatesttag.violation with input as make_input("nginx:latest")
  count(result) > 0
}

# 태그 없음 (latest 로 동작)
test_deny_no_tag if {
  result := data.k8sblocklatesttag.violation with input as make_input("nginx")
  count(result) > 0
}

# initContainer에 latest 태그
test_deny_init_container_latest if {
  result := data.k8sblocklatesttag.violation with input as make_input_init("busybox:latest")
  count(result) > 0
}

# initContainer에 태그 없음
test_deny_init_container_no_tag if {
  result := data.k8sblocklatesttag.violation with input as make_input_init("alpine")
  count(result) > 0
}

# ─── Allow cases ────────────────────────────────────────────

# 명시적 버전 태그
test_allow_explicit_version if {
  result := data.k8sblocklatesttag.violation with input as make_input("nginx:1.25.0")
  count(result) == 0
}

# 레지스트리 포함 + 명시적 태그
test_allow_registry_with_tag if {
  result := data.k8sblocklatesttag.violation with input as make_input("gcr.io/google/nginx:stable")
  count(result) == 0
}
