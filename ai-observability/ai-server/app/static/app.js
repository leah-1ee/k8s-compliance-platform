const $ = (selector) => document.querySelector(selector);

let latestPolicyText = "";
let latestAnalysisText = "";
let latestYamlSnippet = "";
let latestReportText = "";
let selectedRuntimeEvent = null;
let grafanaUrl = "";
let authState = { authenticated: false, user: null, auth: { google_configured: false } };
let userClusters = [];
const SESSION_KEY = "complianceAiLlmApiKey";
const POLICY_PROMPTS = {
  "latest-tag": "latest 태그를 사용하는 컨테이너 이미지를 금지하는 Gatekeeper 정책을 만들어줘",
  "non-root": "non-root 실행을 강제하는 Gatekeeper 정책을 만들어줘",
  "allowed-registries": "허용된 이미지 레지스트리만 사용하게 하는 Gatekeeper 정책을 만들어줘",
  "host-namespace": "host namespace 사용을 금지하는 Gatekeeper 정책을 만들어줘",
  "security-context-mutation": "securityContext를 자동 주입하는 mutation 정책을 만들어줘",
  "resource-limits-mutation": "resource limits를 자동 주입하는 mutation 정책을 만들어줘",
  "network-policy": "ingress 네트워크 정책 만들어줘",
};

function splitList(value) {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function showToast(message) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.add("show");
  window.setTimeout(() => toast.classList.remove("show"), 1800);
}

function showInlineAlert(message) {
  const alert = $("#inlineAlert");
  alert.textContent = message;
  alert.hidden = false;
}

function clearInlineAlert() {
  const alert = $("#inlineAlert");
  alert.textContent = "";
  alert.hidden = true;
}

function isSecureContextForKey() {
  const host = window.location.hostname;
  return (
    window.location.protocol === "https:" ||
    host === "localhost" ||
    host === "127.0.0.1"
  );
}

function sanitizeApiKey(value) {
  return value
    .trim()
    .split("")
    .filter((ch) => ch >= " " && ch !== "\u007f")
    .join("")
    .slice(0, 4096);
}

function llmHeaders() {
  const headers = {
    "Content-Type": "application/json",
  };
  if (!$("#useOwnApiKey").checked) {
    return headers;
  }
  if (!isSecureContextForKey()) {
    showInlineAlert("HTTPS 연결에서만 사용자 API key를 전송할 수 있습니다.");
    return headers;
  }
  const apiKey = sessionStorage.getItem(SESSION_KEY) || "";
  if (apiKey.length >= 8) {
    headers["X-LLM-Provider"] = $("#llmProvider").value;
    headers["X-LLM-API-Key"] = apiKey;
  }
  return headers;
}

async function postJson(path, payload) {
  const response = await fetch(path, {
    method: "POST",
    headers: llmHeaders(),
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    const text = await response.text();
    let message = text || `HTTP ${response.status}`;
    try {
      const body = JSON.parse(text);
      message = formatErrorMessage(body.error || body.detail || message);
      if (Array.isArray(body.examples) && body.examples.length > 0) {
        message = `${message}\n예시: ${body.examples.slice(0, 3).join(" / ")}`;
      }
    } catch (error) {
      // 오류 본문 원문 사용
    }
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }
  return response.json();
}

async function apiJson(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(formatErrorMessage(body.error || body.detail || `HTTP ${response.status}`));
  }
  return body;
}

function formatErrorMessage(value) {
  if (typeof value === "string") {
    return value;
  }
  if (Array.isArray(value)) {
    return value
      .map((item) => {
        if (typeof item === "string") {
          return item;
        }
        const path = Array.isArray(item.loc) ? item.loc.join(".") : "";
        const detail = item.msg || JSON.stringify(item);
        return path ? `${path}: ${detail}` : detail;
      })
      .join("\n");
  }
  if (value && typeof value === "object") {
    return value.message || value.msg || JSON.stringify(value);
  }
  return String(value);
}

function activateTab(tabName) {
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.classList.toggle("is-active", tab.dataset.tab === tabName);
  });
  document.querySelectorAll(".panel").forEach((panel) => {
    panel.classList.remove("is-active");
  });
  $(`#${tabName}Panel`).classList.add("is-active");
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function setAnalysisState(status, title, detail = "") {
  const badgeByStatus = {
    ready: "● 준비됨",
    loading: "⟳ 처리 중",
    error: "✕ 오류",
  };
  $("#analysisResult").innerHTML = `
    <span class="badge ${status}">${badgeByStatus[status]}</span>
    <h2>${escapeHtml(title)}</h2>
    <p>${escapeHtml(detail)}</p>
  `;
}

function setOutput(selector, value) {
  const element = $(selector);
  element.textContent = value;
  element.removeAttribute("data-empty");
}

function eventToAnalysisPayload(event) {
  return {
    cluster: event.cluster || "current-cluster",
    rule: event.rule || "",
    priority: event.priority || "",
    output: event.output || event.classification_reason || "",
    time: event.timestamp || event.time || "",
    output_fields: {
      "k8s.ns.name": event.namespace || "",
      "k8s.pod.name": event.pod_name || "",
      "container.name": event.container_name || "",
      "container.image.repository": event.image || "",
      "user.name": event.user || "",
      "proc.name": event.command || "",
      "proc.cmdline": event.command || "",
    },
    tags: [event.source || "runtime"],
  };
}

function fieldValue(payload, key) {
  return payload.output_fields?.[key] || "unknown";
}

function analysisContextRows(payload) {
  const rows = [
    ["Rule", payload.rule || "unknown rule"],
    ["Cluster", payload.cluster || "current-cluster"],
    ["Namespace", fieldValue(payload, "k8s.ns.name")],
    ["Pod", fieldValue(payload, "k8s.pod.name")],
    ["Container", fieldValue(payload, "container.name")],
  ];
  return rows
    .map(
      ([label, value]) => `
        <div>
          <span>${escapeHtml(label)}</span>
          <strong>${escapeHtml(value)}</strong>
        </div>
      `,
    )
    .join("");
}

function renderYamlSnippet(yamlSnippet) {
  if (!yamlSnippet) {
    return `
      <div class="analysis-code-block">
        <h3>수정 YAML 스니펫</h3>
        <p>이 이벤트에는 바로 적용할 수 있는 YAML 스니펫이 없습니다.</p>
      </div>
    `;
  }
  return `
    <div class="analysis-code-block">
      <div class="card-heading">
        <button class="copy-section copy-yaml-snippet" aria-label="수정 YAML 스니펫 복사" title="복사">
          <svg class="copy-icon" viewBox="0 0 24 24" aria-hidden="true">
            <rect x="9" y="9" width="11" height="11" rx="2"></rect>
            <path d="M5 15V6a2 2 0 0 1 2-2h9"></path>
          </svg>
          <svg class="check-icon" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M20 6 9 17l-5-5"></path>
          </svg>
        </button>
        <h3>수정 YAML 스니펫</h3>
      </div>
      <pre><code id="analysisYamlOutput">${escapeHtml(yamlSnippet)}</code></pre>
    </div>
  `;
}

function renderViolationAnalysis(result, payload) {
  const actions = (result.recommended_actions || [])
    .map((item) => `<li>${escapeHtml(item)}</li>`)
    .join("");
  latestYamlSnippet = result.yaml_snippet || "";
  $("#analysisResult").innerHTML = `
    <div class="analysis-meta">
      <span class="badge ${escapeHtml(result.severity)}">${escapeHtml(result.severity)}</span>
      <span class="badge ${result.llm_used ? "ready" : "loading"}">${result.llm_used ? "LLM 분석" : "기본 분석"}</span>
    </div>
    <h2>${escapeHtml(payload.rule || result.summary)}</h2>
    <div class="analysis-meta">${analysisContextRows(payload)}</div>
    <h3>심각도 설명</h3>
    <p>${escapeHtml(result.severity_explanation || result.reason)}</p>
    <h3>원인 요약</h3>
    <p>${escapeHtml(result.root_cause)}</p>
    <h3>권장 수정</h3>
    <p>${escapeHtml(result.recommended_fix || result.remediation)}</p>
    <h3>구체적 조치</h3>
    <p>${escapeHtml(result.remediation)}</p>
    ${renderYamlSnippet(latestYamlSnippet)}
    ${actions ? `<h3>체크리스트</h3><ul>${actions}</ul>` : ""}
    ${result.llm_error ? `<p>${escapeHtml(result.llm_error)}</p>` : ""}
  `;
}

function setPolicyLoading(isLoading) {
  $("#policyLoading").hidden = !isLoading;
  $("#policyLoadingText").textContent = "정책 생성 중...";
  $("#generatePolicy").disabled = isLoading;
  $("#generatePolicy").textContent = isLoading ? "생성 중..." : "정책 생성";
}

function setAnalysisLoading(isLoading) {
  $("#analysisLoading").hidden = !isLoading;
  $("#analysisLoadingText").textContent = $("#useViolationLlm").checked
    ? "LLM으로 원인과 수정 YAML을 생성 중..."
    : "규칙 기반 위반 상세 분석 중...";
  $("#analyzeViolation").disabled = isLoading;
  $("#analyzeViolation").textContent = isLoading ? "분석 중..." : "상세 분석";
}

async function generatePolicy() {
  clearInlineAlert();
  const useLlm = $("#useLlm").checked;
  const selectedPolicyKind = $("#policyKind").value;
  if (!useLlm && !selectedPolicyKind) {
    showInlineAlert("LLM 검토를 사용하지 않을 때는 정책 유형을 선택해 주세요.");
    showToast("정책 유형 선택 필요");
    return;
  }
  setPolicyLoading(true);
  const payload = {
    prompt: selectedPolicyKind ? POLICY_PROMPTS[selectedPolicyKind] : $("#policyPrompt").value,
    policy_kind: selectedPolicyKind || null,
    constraint_name: $("#constraintName").value,
    enforcement_action: $("#enforcementAction").value,
    allowed_registries: splitList($("#allowedRegistries").value),
    excluded_namespaces: splitList($("#excludedNamespaces").value),
    use_llm: useLlm,
  };
  try {
    const result = await postJson("/generate-policy", payload);
    const llmText = result.llm_review || result.llm_error || "LLM 검토를 선택하지 않았습니다.";
    setOutput(
      "#templateOutput",
      result.constraint_template || "Mutation 정책은 ConstraintTemplate을 사용하지 않습니다.",
    );
    setOutput("#constraintOutput", result.constraint);
    setOutput("#regoOutput", result.rego || "Mutation 정책은 Rego를 사용하지 않습니다.");
    setOutput("#llmOutput", llmText);
    if (result.llm_error) {
      showInlineAlert(result.llm_error);
    }
    latestPolicyText = [
      "# ConstraintTemplate",
      result.constraint_template,
      "",
      "# Constraint",
      result.constraint,
      "",
      "# Rego",
      result.rego,
      "",
      "# Review notes",
      ...result.review_notes.map((item) => `- ${item}`),
      "",
      "# LLM review",
      llmText,
    ].join("\n");
    showToast("정책 생성 완료");
  } finally {
    setPolicyLoading(false);
  }
}

function syncPolicyPromptMode() {
  const useLlm = $("#useLlm").checked;
  const selectedPolicyKind = $("#policyKind").value;
  $("#policyPromptField").hidden = !useLlm;
  $("#policyPrompt").disabled = !useLlm;
  $("#policyKind").querySelector('option[value=""]').disabled = !useLlm;
  if (!useLlm && !selectedPolicyKind) {
    $("#policyKind").value = "latest-tag";
  }
  const effectivePolicyKind = $("#policyKind").value;
  if (!useLlm && effectivePolicyKind) {
    $("#policyPrompt").value = POLICY_PROMPTS[effectivePolicyKind];
  }
}

async function analyzeViolation() {
  if (!authState.authenticated) {
    showToast("로그인 후 사용할 수 있습니다");
    return;
  }
  clearInlineAlert();
  setAnalysisLoading(true);
  setAnalysisState(
    "loading",
    "위반 상세 분석 중",
    $("#useViolationLlm").checked
      ? "이벤트 JSON과 리소스 매니페스트를 LLM에 함께 전달하고 있습니다."
      : "이벤트 JSON과 리소스 매니페스트를 규칙 기반으로 분석하고 있습니다.",
  );
  let payload;
  try {
    payload = JSON.parse($("#eventPayload").value);
  } catch (error) {
    setAnalysisState("error", "JSON 형식 오류", error.message);
    throw error;
  }
  try {
    payload.resource_manifest = $("#resourceManifest").value;
    payload.use_llm = $("#useViolationLlm").checked;
    const result = await postJson("/analyze-violation", payload);
    renderViolationAnalysis(result, payload);
    latestAnalysisText = JSON.stringify(result, null, 2);
    showToast("분석 완료");
  } finally {
    setAnalysisLoading(false);
  }
}

async function refreshRuntimeEvents() {
  const container = $("#runtimeEvents");
  if (!authState.authenticated) {
    container.innerHTML = "";
    return;
  }
  const query = new URLSearchParams({
    limit: "20",
    cluster: $("#runtimeCluster").value,
    cluster_kind: $("#runtimeClusterKind").value,
    source: $("#runtimeSource").value,
    include_legacy: $("#includeLegacyEvents").checked ? "true" : "false",
  });
  container.innerHTML = `
    <article class="event-row">
      <span class="badge loading">loading</span>
      <h2>최근 위반 이벤트 로딩 중</h2>
      <p>저장된 Sidekick/Gatekeeper 이벤트를 확인하고 있습니다.</p>
    </article>
  `;
  const response = await fetch(`/runtime-events?${query.toString()}`);
  const body = await response.json();
  if (!response.ok) {
    throw new Error(formatErrorMessage(body.error || body.detail || `HTTP ${response.status}`));
  }
  if (!body.events || body.events.length === 0) {
    container.innerHTML = `
      <article class="event-row">
        <span class="badge ready">empty</span>
        <h2>최근 위반 이벤트 없음</h2>
        <p>${escapeHtml(body.source_status?.response_server_error || "현재 필터에 맞는 저장 이벤트가 없습니다.")}</p>
      </article>
    `;
    return;
  }
  container.innerHTML = body.events
    .map(
      (event) => `
        <button class="event-row runtime-event-button" data-event-id="${escapeHtml(event.id || "")}">
          <span class="badge ${escapeHtml(event.severity || "medium")}">${escapeHtml(event.severity || "medium")}</span>
          <h2>${escapeHtml(event.rule || "unknown rule")}</h2>
          <p>
            ${escapeHtml(event.cluster || "unknown-cluster")}
            <span class="badge compact ${escapeHtml(event.cluster_kind || "customer")}">${escapeHtml(event.cluster_kind || "customer")}</span>
            · ${escapeHtml(event.namespace || "unknown")}/${escapeHtml(event.pod_name || "unknown")}
            · ${escapeHtml(event.action_taken || event.source || "event")}
          </p>
        </button>
      `,
    )
    .join("");
}

function renderClusterSetupGate() {
  const isAuthenticated = Boolean(authState.authenticated);
  $("#clusterSetupAuthMessage").hidden = isAuthenticated;
  $("#clusterSetupContent").hidden = !isAuthenticated;
}

function renderAuthGates() {
  const isAuthenticated = Boolean(authState.authenticated);
  $("#clusterSetupAuthMessage").hidden = isAuthenticated;
  $("#clusterSetupContent").hidden = !isAuthenticated;
  $("#analysisAuthMessage").hidden = isAuthenticated;
  $("#analysisContent").hidden = !isAuthenticated;
  $("#reportAuthMessage").hidden = isAuthenticated;
  $("#reportContent").hidden = !isAuthenticated;
}

function renderRuntimeClusterFilter() {
  const select = $("#runtimeCluster");
  const selected = select.value;
  select.innerHTML = [
    '<option value="">전체 클러스터</option>',
    ...userClusters.map(
      (cluster) =>
        `<option value="${escapeHtml(cluster.name || "")}">${escapeHtml(cluster.name || "unknown-cluster")}</option>`,
    ),
  ].join("");
  if (userClusters.some((cluster) => cluster.name === selected)) {
    select.value = selected;
  }
}

function renderUserClusters() {
  const container = $("#userClusters");
  if (!authState.authenticated) {
    container.innerHTML = "";
    return;
  }
  if (!userClusters.length) {
    container.innerHTML = '<p class="muted">등록된 클러스터가 없습니다.</p>';
    return;
  }
  container.innerHTML = userClusters
    .map(
      (cluster) => `
        <div class="cluster-row">
          <div>
            <strong>${escapeHtml(cluster.name || "unknown-cluster")}</strong>
            <p>
              status=${escapeHtml(cluster.status || "active")} ·
              last_seen=${escapeHtml(cluster.last_seen_at || "-")}
            </p>
          </div>
          <button data-user-rotate="${escapeHtml(cluster.id || "")}">토큰 재발급</button>
        </div>
      `,
    )
    .join("");
}

async function loadUserClusters() {
  renderClusterSetupGate();
  if (!authState.authenticated) {
    userClusters = [];
    renderRuntimeClusterFilter();
    renderUserClusters();
    return;
  }
  const body = await apiJson("/api/clusters");
  userClusters = body.clusters || [];
  renderRuntimeClusterFilter();
  renderUserClusters();
}

async function registerUserCluster() {
  const name = $("#setupClusterName").value.trim();
  if (!name) {
    showToast("클러스터 이름을 입력하세요");
    return;
  }
  const body = await apiJson("/api/clusters", {
    method: "POST",
    body: JSON.stringify({ name }),
  });
  $("#setupClusterName").value = "";
  setOutput("#setupInstallCommand", body.cluster.install_command || "");
  await loadUserClusters();
  showToast("클러스터 등록 완료");
}

async function rotateUserClusterToken(clusterId) {
  const body = await apiJson(`/api/clusters/${encodeURIComponent(clusterId)}/rotate-token`, {
    method: "POST",
  });
  setOutput("#setupInstallCommand", body.cluster.install_command || "");
  await loadUserClusters();
  showToast("토큰 재발급 완료");
}

async function loadRuntimeEvent(eventId) {
  if (!authState.authenticated) {
    showToast("로그인 후 사용할 수 있습니다");
    return;
  }
  const response = await fetch(`/runtime-events/${encodeURIComponent(eventId)}`);
  if (!response.ok) {
    throw new Error(await response.text());
  }
  selectedRuntimeEvent = await response.json();
  $("#eventPayload").value = JSON.stringify(eventToAnalysisPayload(selectedRuntimeEvent), null, 2);
  $("#resourceManifest").value = "";
  showToast("이벤트 상세를 불러왔습니다");
}

async function loadSelectedManifest() {
  if (!authState.authenticated) {
    showToast("로그인 후 사용할 수 있습니다");
    return;
  }
  if (!selectedRuntimeEvent) {
    showToast("먼저 이벤트를 선택하세요");
    return;
  }
  const namespace = selectedRuntimeEvent.namespace || "";
  const pod = selectedRuntimeEvent.pod_name || "";
  const response = await fetch(
    `/resource-manifest?namespace=${encodeURIComponent(namespace)}&pod=${encodeURIComponent(pod)}`,
  );
  const body = await response.json();
  if (body.manifest) {
    $("#resourceManifest").value = body.manifest;
    showToast("매니페스트 조회 완료");
  } else {
    showInlineAlert(body.error || "매니페스트를 조회하지 못했습니다.");
  }
}

async function generateReport() {
  if (!authState.authenticated) {
    showToast("로그인 후 사용할 수 있습니다");
    return;
  }
  $("#reportResult").innerHTML = `
    <span class="badge loading">loading</span>
    <h2>리포트 생성 중</h2>
    <p>최근 Falco/Gatekeeper 이벤트를 집계하고 있습니다.</p>
  `;
  const response = await fetch("/compliance-report");
  const report = await response.json();
  if (!response.ok) {
    throw new Error(formatErrorMessage(report.error || report.detail || `HTTP ${response.status}`));
  }
  latestReportText = JSON.stringify(report, null, 2);
  const recommendations = (report.recommendations || [])
    .map((item) => `<li>${escapeHtml(item)}</li>`)
    .join("");
  const topRules = (report.top_rules || [])
    .map((item) => `<li>${escapeHtml(item.rule)}: ${escapeHtml(item.count)}</li>`)
    .join("");
  $("#reportResult").innerHTML = `
    <span class="badge ready">generated</span>
    <h2>AI 컴플라이언스 리포트</h2>
    <p>generated_at: ${escapeHtml(report.generated_at || "")}</p>
    <h3>상위 위반 Rule</h3>
    <ul>${topRules || "<li>수집된 rule 없음</li>"}</ul>
    <h3>권장 조치</h3>
    <ul>${recommendations}</ul>
    <div class="analysis-code-block">
      <pre><code>${escapeHtml(latestReportText)}</code></pre>
    </div>
  `;
}

async function copyText(value) {
  if (!value) {
    showToast("복사할 결과 없음");
    return;
  }
  await navigator.clipboard.writeText(value);
  showToast("복사 완료");
}

function markCopied(button) {
  button.classList.add("is-copied");
  window.setTimeout(() => button.classList.remove("is-copied"), 1500);
}

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => activateTab(tab.dataset.tab));
});

$("#generatePolicy").addEventListener("click", () => {
  generatePolicy().catch((error) => {
    showInlineAlert(error.message);
    showToast(error.message);
  });
});

$("#analyzeViolation").addEventListener("click", () => {
  analyzeViolation().catch((error) => {
    if (!$("#analysisResult .badge.error")) {
      setAnalysisState("error", "분석 실패", error.message);
    }
    showInlineAlert(error.message);
    showToast(error.message);
  });
});

$("#copyPolicy").addEventListener("click", () => {
  copyText(latestPolicyText).catch((error) => showToast(error.message));
});

$("#copyAnalysis").addEventListener("click", () => {
  copyText(latestAnalysisText).catch((error) => showToast(error.message));
});

$("#refreshRuntimeEvents").addEventListener("click", () => {
  refreshRuntimeEvents().catch((error) => {
    showInlineAlert(error.message);
    showToast("위반 목록 로드 실패");
  });
});

$("#registerUserCluster").addEventListener("click", () => {
  registerUserCluster().catch((error) => {
    showInlineAlert(error.message);
    showToast("클러스터 등록 실패");
  });
});

$("#refreshUserClusters").addEventListener("click", () => {
  loadUserClusters()
    .then(() => showToast("클러스터 목록 갱신"))
    .catch((error) => {
      showInlineAlert(error.message);
      showToast("클러스터 목록 로드 실패");
    });
});

$("#userClusters").addEventListener("click", (event) => {
  const button = event.target.closest("[data-user-rotate]");
  if (!button) {
    return;
  }
  rotateUserClusterToken(button.dataset.userRotate).catch((error) => {
    showInlineAlert(error.message);
    showToast("토큰 재발급 실패");
  });
});

["#runtimeCluster", "#runtimeClusterKind", "#runtimeSource", "#includeLegacyEvents"].forEach((selector) => {
  $(selector).addEventListener("change", () => {
    refreshRuntimeEvents().catch((error) => {
      showInlineAlert(error.message);
      showToast("위반 목록 로드 실패");
    });
  });
});

$("#runtimeEvents").addEventListener("click", (event) => {
  const button = event.target.closest(".runtime-event-button");
  if (!button) {
    return;
  }
  loadRuntimeEvent(button.dataset.eventId).catch((error) => {
    showInlineAlert(error.message);
    showToast("이벤트 상세 로드 실패");
  });
});

$("#loadSelectedManifest").addEventListener("click", () => {
  loadSelectedManifest().catch((error) => {
    showInlineAlert(error.message);
    showToast("매니페스트 조회 실패");
  });
});

$("#generateReport").addEventListener("click", () => {
  generateReport().catch((error) => {
    showInlineAlert(error.message);
    showToast("리포트 생성 실패");
  });
});

$("#copyReport").addEventListener("click", () => {
  copyText(latestReportText).catch((error) => showToast(error.message));
});

$("#analysisResult").addEventListener("click", (event) => {
  const button = event.target.closest(".copy-yaml-snippet");
  if (!button) {
    return;
  }
  copyText(latestYamlSnippet)
    .then(() => markCopied(button))
    .catch((error) => showToast(error.message));
});

document.querySelectorAll(".copy-section").forEach((button) => {
  button.addEventListener("click", async () => {
    const targetId = button.dataset.copyTarget;
    const target = document.getElementById(targetId);
    if (!target || target.dataset.empty === "true") {
      showToast("복사할 결과 없음");
      return;
    }
    try {
      await copyText(target.textContent);
      markCopied(button);
    } catch (error) {
      showToast(error.message);
    }
  });
});

$("#useOwnApiKey").addEventListener("change", () => {
  $("#byokFields").hidden = !$("#useOwnApiKey").checked;
  sessionStorage.removeItem(SESSION_KEY);
  $("#llmApiKey").value = "";
  clearInlineAlert();
  if ($("#useOwnApiKey").checked && !isSecureContextForKey()) {
    showInlineAlert("HTTPS 연결에서만 사용자 API key를 전송할 수 있습니다.");
  }
});

$("#llmApiKey").addEventListener("input", () => {
  const value = sanitizeApiKey($("#llmApiKey").value);
  if ($("#llmApiKey").value !== value) {
    $("#llmApiKey").value = value;
  }
  if (value) {
    sessionStorage.setItem(SESSION_KEY, value);
  } else {
    sessionStorage.removeItem(SESSION_KEY);
  }
});

$("#useLlm").addEventListener("change", () => {
  syncPolicyPromptMode();
});

$("#policyKind").addEventListener("change", () => {
  syncPolicyPromptMode();
});

$("#logoutButton").addEventListener("click", () => {
  logout()
    .then(() => showToast("로그아웃되었습니다"))
    .catch((error) => showToast(error.message));
});

$("#grafanaLink").addEventListener("click", (event) => {
  if (!grafanaUrl) {
    event.preventDefault();
    showToast("Grafana URL 설정 필요");
  }
});

async function loadConfig() {
  const response = await fetch("/config");
  const config = await response.json();
  grafanaUrl = config.grafana_url || "";
  if (grafanaUrl) {
    $("#grafanaLink").href = grafanaUrl;
    $("#grafanaLink").target = "_blank";
    $("#grafanaLink").rel = "noreferrer";
  }
}

async function loadAuthStatus() {
  const response = await fetch("/me");
  authState = await response.json();
  renderAuthStatus();
}

function renderAuthStatus() {
  const status = $("#authStatus");
  const loginLink = $("#loginLink");
  const devLoginLink = $("#devLoginLink");
  const logoutButton = $("#logoutButton");
  if (authState.authenticated) {
    status.textContent = authState.user?.email || "로그인됨";
    loginLink.hidden = true;
    devLoginLink.hidden = true;
    logoutButton.hidden = false;
    renderAuthGates();
    return;
  }
  const googleConfigured = Boolean(authState.auth?.google_configured);
  const devEnabled = Boolean(authState.auth?.dev_enabled);
  status.textContent = googleConfigured || devEnabled ? "로그인 필요" : "로그인 미설정";
  loginLink.hidden = !authState.auth?.google_configured;
  devLoginLink.hidden = !authState.auth?.dev_enabled;
  logoutButton.hidden = true;
  renderAuthGates();
}

async function logout() {
  const response = await fetch("/logout", { method: "POST" });
  if (!response.ok) {
    throw new Error(await response.text());
  }
  authState = { authenticated: false, user: null, auth: authState.auth };
  userClusters = [];
  renderAuthStatus();
  renderUserClusters();
  selectedRuntimeEvent = null;
  $("#runtimeEvents").innerHTML = "";
}

function initLlmKeyPanel() {
  // 세션 키 초기화
  sessionStorage.removeItem(SESSION_KEY);
  $("#useOwnApiKey").checked = false;
  $("#byokFields").hidden = true;
  $("#llmProvider").value = "google";
  $("#llmApiKey").value = "";
  $("#useLlm").checked = false;
  $("#useViolationLlm").checked = false;
}

initLlmKeyPanel();
syncPolicyPromptMode();
window.setInterval(() => {
  if (authState.authenticated) {
    refreshRuntimeEvents().catch(() => {});
  }
}, 30000);
loadConfig().catch(() => showToast("설정 로드 실패"));
loadAuthStatus()
  .then(() => Promise.all([loadUserClusters(), authState.authenticated ? refreshRuntimeEvents() : Promise.resolve()]))
  .catch(() => {
    $("#authStatus").textContent = "로그인 상태 확인 실패";
    renderAuthGates();
  });
