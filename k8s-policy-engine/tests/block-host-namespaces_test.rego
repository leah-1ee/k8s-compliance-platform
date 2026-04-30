package k8spsphostnamespace

import rego.v1

# ─── 공통 헬퍼 ──────────────────────────────────────────────

make_input(host_pid, host_ipc) = {"review": {
  "operation": "CREATE",
  "object": {
    "metadata": {"name": "test-pod"},
    "spec": {
      "hostPID": host_pid,
      "hostIPC": host_ipc,
      "containers": [{"name": "app", "image": "nginx:1.25.0"}],
    },
  },
}}

make_input_no_fields = {"review": {
  "operation": "CREATE",
  "object": {
    "metadata": {"name": "test-pod"},
    "spec": {
      "containers": [{"name": "app", "image": "nginx:1.25.0"}],
    },
  },
}}

# ─── Deny cases ─────────────────────────────────────────────

# hostNetwork: true (hostPID 사용)
test_deny_host_pid if {
  result := data.k8spsphostnamespace.violation with input as make_input(true, false)
  count(result) > 0
}

# hostIPC: true
test_deny_host_ipc if {
  result := data.k8spsphostnamespace.violation with input as make_input(false, true)
  count(result) > 0
}

# ─── Allow cases ────────────────────────────────────────────

# hostPID: false, hostIPC: false
test_allow_host_namespace_disabled if {
  result := data.k8spsphostnamespace.violation with input as make_input(false, false)
  count(result) == 0
}

# hostPID / hostIPC 필드 자체가 없는 경우
test_allow_no_host_namespace_fields if {
  result := data.k8spsphostnamespace.violation with input as make_input_no_fields
  count(result) == 0
}
