package k8sallowedrepos

import rego.v1

# ─── 공통 헬퍼 ──────────────────────────────────────────────

make_review(image) = {"review": {"object": {
  "metadata": {"name": "test-pod"},
  "spec": {"containers": [{"name": "app", "image": image}]},
}}}

allowed_repos = ["docker.io/library/", "gcr.io/", "ghcr.io/", "registry.k8s.io/"]

make_input(image) = {"parameters": {"repos": allowed_repos}, "review": {"object": {
  "metadata": {"name": "test-pod"},
  "spec": {
    "containers": [{"name": "app", "image": image}],
    "initContainers": [],
  },
}}}

# ─── Deny cases ─────────────────────────────────────────────

# docker.io/nginx 는 "docker.io/library/" prefix 와 일치하지 않음
test_deny_dockerhub_non_library if {
  result := data.k8sallowedrepos.violation with input as make_input("docker.io/nginx:latest")
  count(result) > 0
}

# 레지스트리 없이 이미지 이름만 지정한 경우 허용 목록 불일치
test_deny_no_registry if {
  result := data.k8sallowedrepos.violation with input as make_input("ubuntu:22.04")
  count(result) > 0
}

# ─── Allow cases ────────────────────────────────────────────

# docker.io/library/ prefix 정확히 일치
test_allow_docker_library if {
  result := data.k8sallowedrepos.violation with input as make_input("docker.io/library/nginx:1.25.0")
  count(result) == 0
}

# gcr.io/ prefix 일치
test_allow_gcr if {
  result := data.k8sallowedrepos.violation with input as make_input("gcr.io/google-containers/pause:3.9")
  count(result) == 0
}
