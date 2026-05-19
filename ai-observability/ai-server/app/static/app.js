const $ = (selector) => document.querySelector(selector);

let latestPolicyText = "";
let latestPolicyManifestText = "";
let latestAnalysisText = "";
let latestYamlSnippet = "";
let latestReportText = "";
let latestReportHtml = "";
let latestManifestCommand = "";
let selectedRuntimeEvent = null;
let grafanaUrl = "";
let authState = { authenticated: false, user: null, auth: { google_configured: false, dev_enabled: false } };
let userClusters = [];
let slackSettings = { webhook_url: "", configured: false };
let landingTypewriterStarted = false;
const SESSION_KEY = "complianceAiLlmApiKey";
const THEME_KEY = "complianceOpsTheme";
const DEFAULT_RUNTIME_LIMIT = "50";
const INFRA_NAMESPACES = new Set([
  "kube-system",
  "monitoring",
  "gatekeeper-system",
  "falco",
  "local-path-storage",
  "calico-system",
  "cilium",
  "cilium-system",
  "kube-flannel",
  "tigera-operator",
]);
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

function applyTheme(theme) {
  const normalizedTheme = theme === "dark" ? "dark" : "light";
  document.documentElement.dataset.theme = normalizedTheme;
  localStorage.setItem(THEME_KEY, normalizedTheme);
  const button = $("#themeToggle");
  if (button) {
    const isDark = normalizedTheme === "dark";
    const label = button.querySelector(".theme-label");
    if (label) {
      label.textContent = isDark ? "Light" : "Dark";
    } else {
      button.textContent = isDark ? "Light mode" : "Dark mode";
    }
    button.setAttribute("aria-label", isDark ? "Light mode" : "Dark mode");
    button.setAttribute("aria-pressed", String(isDark));
  }
}

function toggleTheme() {
  const nextTheme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  applyTheme(nextTheme);
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
  const activeTab = document.querySelector(`.tab[data-tab="${tabName}"]`);
  const pageTitle = $("#pageTitle");
  if (activeTab && pageTitle) {
    pageTitle.textContent = activeTab.textContent.trim();
  }
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function shortEventId(event) {
  const id = String(event?.id || "");
  return id ? id.slice(0, 8) : "no-id";
}

function eventTimestamp(event) {
  return event?.timestamp || event?.time || event?.created_at || "";
}

function formatEventTime(event) {
  const value = eventTimestamp(event);
  if (!value) {
    return "time unknown";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString(undefined, {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function formatRelativeTime(value) {
  if (!value) {
    return "-";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "-";
  }
  const diffMs = Date.now() - date.getTime();
  if (diffMs < 0) {
    return "방금";
  }
  const minutes = Math.floor(diffMs / 60000);
  if (minutes < 1) {
    return "방금";
  }
  if (minutes < 60) {
    return `${minutes}m`;
  }
  const hours = Math.floor(minutes / 60);
  if (hours < 24) {
    return `${hours}h`;
  }
  return `${Math.floor(hours / 24)}d`;
}

function eventImage(event) {
  const image = event?.image || event?.image_repository || event?.container_image || "";
  const tag = event?.image_tag || "";
  if (image && tag && !image.includes(":")) {
    return `${image}:${tag}`;
  }
  return image || "image unknown";
}

function eventContextLine(event) {
  return [
    event?.namespace || "namespace unknown",
    event?.pod_name || "pod unknown",
    event?.container_name || "container unknown",
  ].join(" / ");
}

function eventClusterLine(event) {
  const clusterKind = event?.cluster_kind || "customer";
  return `
    ${escapeHtml(event?.cluster || "unknown-cluster")}
    <span class="badge compact ${escapeHtml(clusterKind)}">${escapeHtml(clusterKind)}</span>
    · ${escapeHtml(event?.source || "runtime")}
    · ${escapeHtml(event?.action_taken || "event")}
  `;
}

function renderDashboardSummary(summary = {}) {
  $("#activePoliciesMetric").textContent =
    summary.active_policies === null || summary.active_policies === undefined
      ? "-"
      : String(summary.active_policies);
  $("#activePoliciesMetricDetail").textContent =
    summary.active_policies_error
      ? `Gatekeeper API error: ${summary.active_policies_error}`
      : summary.active_policies_source === "kubernetes"
      ? "Live Gatekeeper constraints"
      : "Gatekeeper API unavailable";
  $("#recentViolationsMetric").textContent = String(summary.recent_violations ?? 0);
  $("#runtimeEventsMetric").textContent = String(summary.runtime_events ?? 0);
  $("#lastSyncMetric").textContent = formatRelativeTime(summary.last_sync || "");
  $("#lastSyncMetricDetail").textContent = summary.last_sync ? "Cluster telemetry" : "No cluster sync yet";
}

async function refreshDashboardSummary() {
  if (!authState.authenticated) {
    renderDashboardSummary({});
    return;
  }
  const summary = await apiJson("/dashboard-summary");
  renderDashboardSummary(summary);
}

function runtimeEventLabel(event) {
  return `#${shortEventId(event)} · ${formatEventTime(event)} · ${event?.rule || "unknown rule"}`;
}

function isInfraRuntimeEvent(event) {
  const namespace = String(event?.namespace || "").trim();
  return INFRA_NAMESPACES.has(namespace);
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

function renderManifestGuidance(result = null) {
  const button = $("#loadSelectedManifest");
  if (!button) {
    return;
  }
  let panel = $("#manifestGuidancePanel");
  if (!panel) {
    button.insertAdjacentHTML("afterend", '<div id="manifestGuidancePanel" class="analysis-code-block" hidden></div>');
    panel = $("#manifestGuidancePanel");
  }
  latestManifestCommand = result?.kubectl_command || "";
  if (!result || (!latestManifestCommand && !result.error)) {
    panel.hidden = true;
    panel.innerHTML = "";
    return;
  }
  const context = result.resource_context || {};
  const contextText = [
    context.cluster ? `cluster=${context.cluster}` : "",
    context.namespace ? `namespace=${context.namespace}` : "",
    context.pod ? `pod=${context.pod}` : "",
    context.container ? `container=${context.container}` : "",
  ]
    .filter(Boolean)
    .join(" · ");
  panel.hidden = false;
  panel.innerHTML = `
    <div class="card-heading">
      <button class="copy-section copy-manifest-command" aria-label="kubectl 명령 복사" title="복사">
        <svg class="copy-icon" viewBox="0 0 24 24" aria-hidden="true">
          <rect x="9" y="9" width="11" height="11" rx="2"></rect>
          <path d="M5 15V6a2 2 0 0 1 2-2h9"></path>
        </svg>
        <svg class="check-icon" viewBox="0 0 24 24" aria-hidden="true">
          <path d="M20 6 9 17l-5-5"></path>
        </svg>
      </button>
      <h3>사용자 클러스터에서 매니페스트 조회</h3>
    </div>
    <p>${escapeHtml(result.manifest_guidance || "아래 명령을 이벤트가 발생한 클러스터에서 실행하세요.")}</p>
    ${contextText ? `<p>${escapeHtml(contextText)}</p>` : ""}
    ${latestManifestCommand ? `<pre><code>${escapeHtml(latestManifestCommand)}</code></pre>` : ""}
    ${result.error ? `<p>${escapeHtml(result.error)}</p>` : ""}
  `;
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

function ensureSelectedRuntimeEventPanel() {
  let panel = $("#selectedRuntimeEventSummary");
  if (panel) {
    return panel;
  }
  const anchor = $("#eventPayload");
  if (!anchor) {
    return null;
  }
  anchor.insertAdjacentHTML("beforebegin", '<div id="selectedRuntimeEventSummary" class="analysis-code-block" hidden></div>');
  return $("#selectedRuntimeEventSummary");
}

function renderSelectedRuntimeEventState(status, event = null, detail = "") {
  const panel = ensureSelectedRuntimeEventPanel();
  if (!panel) {
    return;
  }
  if (!event && !detail) {
    panel.hidden = true;
    panel.innerHTML = "";
    return;
  }
  const badgeByStatus = {
    ready: "selected",
    loading: "loading",
    error: "error",
  };
  const title = event ? runtimeEventLabel(event) : "선택된 이벤트 없음";
  const context = event
    ? [
        eventClusterLine(event).replace(/\s+/g, " ").trim(),
        escapeHtml(eventContextLine(event)),
        escapeHtml(eventImage(event)),
      ].join(" · ")
    : "";
  panel.hidden = false;
  panel.innerHTML = `
    <span class="badge ${escapeHtml(status)}">${escapeHtml(badgeByStatus[status] || status)}</span>
    <h3>${escapeHtml(title)}</h3>
    ${context ? `<p>${context}</p>` : ""}
    ${detail ? `<p>${escapeHtml(detail)}</p>` : ""}
  `;
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
        <div class="analysis-context-item">
          <span class="analysis-context-label">${escapeHtml(label)}</span>
          <strong class="analysis-context-value">${escapeHtml(value)}</strong>
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
    <div class="analysis-context-grid" aria-label="analysis target context">${analysisContextRows(payload)}</div>
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

function buildGeneratedPolicyManifest(result) {
  return [result.constraint_template, result.constraint]
    .map((value) => String(value || "").trim())
    .filter(Boolean)
    .join("\n---\n");
}

function ensurePolicyApplyPanel() {
  if ($("#policyApplyPanel")) {
    return;
  }
  const anchor = $("#constraintOutput")?.closest(".result-grid") || $("#policyPanel");
  if (!anchor || !anchor.parentElement) {
    return;
  }
  const panel = document.createElement("section");
  panel.id = "policyApplyPanel";
  panel.className = "policy-apply-panel";
  panel.hidden = true;
  panel.innerHTML = `
    <div class="policy-apply-heading">
      <div>
        <h2>클러스터 적용 가이드</h2>
        <p>생성된 정책을 사용자 클러스터 context에서 안전하게 적용할 kubectl 단계를 준비합니다.</p>
      </div>
      <span id="policyApplyStatusBadge" class="badge compact">대기</span>
    </div>
    <div class="policy-apply-notice">
      <strong>사용자 클러스터 적용 안내</strong>
      <p>현재 AI 서버는 사용자 클러스터에 직접 Kubernetes API apply 권한을 갖지 않습니다. 아래에서 생성되는 단계별 명령을 대상 클러스터 context에서 실행하세요.</p>
      <p>터미널에서 <code>kubectl config current-context</code>로 대상 클러스터를 확인한 뒤 권한 확인, 필요 시 RBAC, dry-run, apply 순서로 진행합니다.</p>
    </div>
    <div class="policy-apply-controls">
      <label>
        대상 클러스터
        <select id="policyApplyCluster"></select>
      </label>
      <button id="applyGeneratedPolicy" class="primary" type="button">적용 가이드 생성</button>
    </div>
    <div id="policyApplyHint" class="policy-apply-hint"></div>
    <div id="policyApplyResult" class="policy-apply-result" hidden></div>
  `;
  anchor.insertAdjacentElement("afterend", panel);
  renderPolicyApplyPanel();
}

function renderPolicyApplyPanel() {
  const panel = $("#policyApplyPanel");
  if (!panel) {
    return;
  }
  const isAuthenticated = Boolean(authState.authenticated);
  panel.hidden = !isAuthenticated;
  if (!isAuthenticated) {
    return;
  }
  const activeClusters = userClusters.filter((cluster) => cluster.status === "active");
  const select = $("#policyApplyCluster");
  const selected = select.value;
  select.innerHTML = [
    '<option value="">클러스터 선택</option>',
    ...activeClusters.map(
      (cluster) =>
        `<option value="${escapeHtml(cluster.id || "")}">${escapeHtml(cluster.name || "unknown-cluster")}</option>`,
    ),
  ].join("");
  if (activeClusters.some((cluster) => cluster.id === selected)) {
    select.value = selected;
  }
  const hasPolicy = Boolean(latestPolicyManifestText.trim());
  const hasCluster = activeClusters.length > 0;
  $("#applyGeneratedPolicy").disabled = !hasPolicy;
  $("#policyApplyHint").textContent = hasPolicy
    ? hasCluster
      ? "Gatekeeper validation constraint만 Live Gatekeeper constraints 지표에 반영됩니다. 적용 권한은 사용자 kubeconfig context에서 확인합니다."
      : "선택 가능한 활성 클러스터가 없습니다. Cluster Setup에서 클러스터를 등록하거나 복원 후 토큰을 재발급하세요."
    : "정책을 생성하면 적용 대상을 선택할 수 있습니다.";
}

function fallbackCommandSteps(fallback = {}) {
  const steps = [
    {
      key: "permission",
      label: "1. 권한 확인",
      description: "현재 kubeconfig 계정이 Gatekeeper 리소스를 읽고 생성/수정할 수 있는지 확인합니다.",
      command: fallback.permission_check_command,
      open: true,
    },
    {
      key: "rbac",
      label: "2. 필요 시 RBAC",
      description: "권한 확인이 실패하면 클러스터 관리자가 먼저 실행하는 예시 권한 부여 명령입니다.",
      command: fallback.admin_rbac_command,
      open: false,
    },
    {
      key: "dry-run",
      label: "3. dry-run 검증",
      description: "실제 리소스를 만들기 전에 API 서버 검증만 수행합니다.",
      command: fallback.dry_run_command,
      open: false,
    },
    {
      key: "apply",
      label: "4. 실제 apply",
      description: "dry-run이 성공한 뒤 같은 클러스터 context에서 실행합니다.",
      command: fallback.apply_command,
      open: false,
    },
  ];
  return steps.filter((step) => String(step.command || "").trim());
}

function renderPolicyFallbackSteps(fallback = {}) {
  const steps = fallbackCommandSteps(fallback);
  if (steps.length === 0 && !fallback.combined_command) {
    return "";
  }
  const fallbackSteps = steps.length
    ? steps
    : [
        {
          key: "combined",
          label: "kubectl 명령",
          description: "대상 클러스터 context에서 순서대로 실행합니다.",
          command: fallback.combined_command,
          open: true,
        },
      ];
  return `
    <div class="policy-apply-fallback">
      <div class="policy-apply-fallback-heading">
        <div>
          <strong>단계별 kubectl 적용</strong>
          <p>각 단계의 명령을 따로 복사해 순서대로 실행하세요.</p>
        </div>
      </div>
      <div class="policy-apply-steps">
        ${fallbackSteps
          .map((step, index) => {
            const targetId = `policyApplyFallbackStep${index}`;
            return `
              <details class="policy-apply-step" ${step.open ? "open" : ""}>
                <summary>
                  <span>
                    <strong>${escapeHtml(step.label)}</strong>
                    <small>${escapeHtml(step.description)}</small>
                  </span>
                  <button class="secondary" data-copy-policy-step="${targetId}" type="button">복사</button>
                </summary>
                <pre id="${targetId}">${escapeHtml(step.command)}</pre>
              </details>
            `;
          })
          .join("")}
      </div>
    </div>
  `;
}

function renderPolicyApplyResult(result) {
  const container = $("#policyApplyResult");
  const badge = $("#policyApplyStatusBadge");
  if (!container || !badge) {
    return;
  }
  const status = result?.status || "unknown";
  badge.textContent = status;
  badge.className = `badge compact ${status === "applied" ? "ready" : status === "not_configured" ? "medium" : "error"}`;
  const rows = (result.resources || [])
    .map(
      (item) => `
        <div class="policy-apply-resource">
          <strong>${escapeHtml(item.order || "-")}. ${escapeHtml(item.kind || "Unknown")} / ${escapeHtml(item.name || "-")}</strong>
          <p>
            dry-run=${escapeHtml(item.dry_run_status || "skipped")} ·
            apply=${escapeHtml(item.apply_status || "skipped")}
            ${item.namespace ? ` · ns=${escapeHtml(item.namespace)}` : ""}
          </p>
          ${item.error ? `<pre>${escapeHtml(item.error)}</pre>` : ""}
        </div>
      `,
    )
    .join("");
  const fallback = renderPolicyFallbackSteps(result.fallback || {});
  const error = result.error && status !== "not_configured"
    ? `<p class="policy-apply-error">${escapeHtml(result.error)}</p>`
    : "";
  const notConfiguredNote = result.error && status === "not_configured"
    ? `<p class="policy-apply-note">${escapeHtml(result.error)}</p>`
    : "";
  container.hidden = false;
  container.innerHTML = `
    ${error}
    ${notConfiguredNote}
    ${rows || '<p class="muted">리소스 결과가 없습니다.</p>'}
    ${fallback}
  `;
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
    latestPolicyManifestText = buildGeneratedPolicyManifest(result);
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
    renderPolicyApplyPanel();
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
  syncEnforcementBadges();
}

function syncEnforcementBadges() {
  const selected = $("#enforcementAction")?.value || "deny";
  document.querySelectorAll("[data-enforcement-badge]").forEach((badge) => {
    badge.classList.toggle("is-selected", badge.dataset.enforcementBadge === selected);
  });
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
  ensureRuntimeUsabilityControls();
  const hideInfra = $("#hideInfraRuntimeNamespaces")?.checked ?? false;
  const limit = $("#runtimeEventLimit")?.value || DEFAULT_RUNTIME_LIMIT;
  const query = new URLSearchParams({
    limit,
    cluster: $("#runtimeCluster").value,
    cluster_kind: $("#runtimeClusterKind").value,
    source: $("#runtimeSource").value,
    include_legacy: $("#includeLegacyEvents").checked ? "true" : "false",
    exclude_infra: hideInfra ? "true" : "false",
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
  const visibleEvents = body.events || [];
  if (visibleEvents.length === 0) {
    const emptyMessage = body.source_status?.response_server_error || "현재 필터에 맞는 저장 이벤트가 없습니다.";
    container.innerHTML = `
      <article class="event-row">
        <span class="badge ready">empty</span>
        <h2>최근 위반 이벤트 없음</h2>
        <p>${escapeHtml(emptyMessage)}</p>
      </article>
    `;
    return;
  }
  const hiddenSummary = hideInfra
    ? `<article class="event-row event-row-note"><span class="badge ready">filtered</span><p>infra namespace 숨김 활성화</p></article>`
    : "";
  container.innerHTML =
    hiddenSummary +
    visibleEvents
    .map(
      (event) => `
        <button class="event-row runtime-event-button" data-event-id="${escapeHtml(event.id || "")}">
          <span class="badge ${escapeHtml(event.severity || "medium")}">${escapeHtml(event.severity || "medium")}</span>
          <div class="event-row-content">
            <h2>${escapeHtml(event.rule || "unknown rule")}</h2>
            <p class="event-row-meta">${escapeHtml(formatEventTime(event))} · #${escapeHtml(shortEventId(event))}</p>
            <p class="event-row-meta">${eventClusterLine(event)}</p>
            <p class="event-row-meta">${escapeHtml(eventContextLine(event))}</p>
            <p class="event-row-meta">${escapeHtml(eventImage(event))}</p>
          </div>
        </button>
      `,
    )
    .join("");
}

function ensureRuntimeUsabilityControls() {
  if ($("#runtimeEventLimit") && $("#hideInfraRuntimeNamespaces")) {
    return;
  }
  const anchor = $("#includeLegacyEvents");
  if (!anchor) {
    return;
  }
  const wrapper = anchor.closest("label") || anchor;
  wrapper.insertAdjacentHTML(
    "afterend",
    `
      <label>
        표시 개수
        <select id="runtimeEventLimit">
          <option value="20">20</option>
          <option value="50" selected>50</option>
          <option value="100">100</option>
        </select>
      </label>
      <label class="toggle-row">
        <input id="hideInfraRuntimeNamespaces" type="checkbox" checked />
        <span class="toggle-control" aria-hidden="true"></span>
        <span>infra namespace 숨김</span>
      </label>
    `,
  );
  ["#runtimeEventLimit", "#hideInfraRuntimeNamespaces"].forEach((selector) => {
    $(selector).addEventListener("change", () => {
      refreshRuntimeEvents().catch((error) => {
        showInlineAlert(error.message);
        showToast("위반 목록 로드 실패");
      });
    });
  });
}

function renderClusterSetupGate() {
  const isAuthenticated = Boolean(authState.authenticated);
  $("#clusterSetupAuthMessage").hidden = isAuthenticated;
  $("#clusterSetupContent").hidden = !isAuthenticated;
  renderSlackSettings();
}

function renderAuthGates() {
  const isAuthenticated = Boolean(authState.authenticated);
  $("#clusterSetupAuthMessage").hidden = isAuthenticated;
  $("#clusterSetupContent").hidden = !isAuthenticated;
  $("#analysisAuthMessage").hidden = isAuthenticated;
  $("#analysisContent").hidden = !isAuthenticated;
  $("#reportAuthMessage").hidden = isAuthenticated;
  $("#reportContent").hidden = !isAuthenticated;
  renderLandingIntro();
  renderSlackSettings();
  renderPolicyApplyPanel();
}

function renderLandingIntro() {
  const landingIntro = $("#landingIntro");
  if (!landingIntro) {
    return;
  }
  const isAuthenticated = Boolean(authState.authenticated);
  const googleConfigured = Boolean(authState.auth?.google_configured);
  const devEnabled = Boolean(authState.auth?.dev_enabled);
  landingIntro.hidden = isAuthenticated;
  $("#landingLoginLink").hidden = isAuthenticated || !googleConfigured;
  $("#landingDevLoginLink").hidden = isAuthenticated || !devEnabled;
  $("#landingLoginNote").hidden = isAuthenticated || (!googleConfigured && !devEnabled);
  $("#landingNoLoginMessage").hidden = isAuthenticated || googleConfigured || devEnabled;
  if (!isAuthenticated) {
    startLandingTypewriter();
  }
}

function startLandingTypewriter() {
  const subtitle = $("#landingSubtitle");
  if (!subtitle || landingTypewriterStarted) {
    return;
  }
  const fullText = subtitle.dataset.typewriterText || subtitle.textContent.trim();
  landingTypewriterStarted = true;
  subtitle.setAttribute("aria-label", fullText);
  subtitle.textContent = "";
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    subtitle.textContent = fullText;
    return;
  }
  let index = 0;
  const typeNext = () => {
    subtitle.textContent = fullText.slice(0, index);
    if (index >= fullText.length) {
      return;
    }
    const char = fullText[index];
    index += 1;
    const delay = [".", ",", "·", "까지"].includes(char) ? 120 : char === " " ? 32 : 24;
    window.setTimeout(typeNext, delay);
  };
  window.setTimeout(typeNext, 220);
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
      (cluster) => {
        const isDeleted = cluster.status === "deleted";
        return `
        <div class="cluster-row">
          <div>
            <strong>${escapeHtml(cluster.name || "unknown-cluster")}</strong>
            <p>
              status=${escapeHtml(cluster.status || "active")} ·
              last_seen=${escapeHtml(cluster.last_seen_at || "-")}
              ${isDeleted ? ` · deleted_at=${escapeHtml(cluster.deleted_at || "-")}` : ""}
            </p>
          </div>
          <div class="cluster-row-actions">
            ${
              isDeleted
                ? `<button class="secondary" data-user-restore="${escapeHtml(cluster.id || "")}">복원</button>`
                : `
                  <button data-user-rotate="${escapeHtml(cluster.id || "")}">토큰 재발급</button>
                  <button class="secondary" data-user-delete="${escapeHtml(cluster.id || "")}">휴지통</button>
                `
            }
          </div>
        </div>
      `;
      },
    )
    .join("");
  renderSlackClusterToggles();
}

async function loadUserClusters() {
  renderClusterSetupGate();
  if (!authState.authenticated) {
    userClusters = [];
    renderRuntimeClusterFilter();
    renderUserClusters();
    renderSlackClusterToggles();
    renderPolicyApplyPanel();
    return;
  }
  const includeDeleted = $("#showDeletedClusters")?.checked ? "true" : "false";
  const body = await apiJson(`/api/clusters?include_deleted=${includeDeleted}`);
  userClusters = body.clusters || [];
  renderRuntimeClusterFilter();
  renderUserClusters();
  renderPolicyApplyPanel();
}

async function applyGeneratedPolicy() {
  if (!latestPolicyManifestText.trim()) {
    showToast("먼저 정책을 생성해 주세요");
    return;
  }
  const activeClusters = userClusters.filter((cluster) => cluster.status === "active");
  if (activeClusters.length === 0) {
    renderPolicyApplyResult({
      status: "not_ready",
      error: "선택 가능한 활성 클러스터가 없습니다. Cluster Setup에서 클러스터를 등록하거나 복원 후 토큰을 재발급하세요.",
      resources: [],
    });
    showToast("활성 클러스터 없음");
    return;
  }
  const clusterId = $("#policyApplyCluster")?.value || "";
  if (!clusterId) {
    renderPolicyApplyResult({
      status: "not_ready",
      error: "적용할 대상 클러스터를 먼저 선택해 주세요.",
      resources: [],
    });
    showToast("대상 클러스터 선택 필요");
    return;
  }
  const cluster = userClusters.find((item) => item.id === clusterId);
  const clusterName = cluster?.name || "selected cluster";
  if (!window.confirm(`${clusterName} 클러스터에서 실행할 단계별 kubectl 적용 가이드를 생성할까요?`)) {
    return;
  }
  const button = $("#applyGeneratedPolicy");
  const previousText = button.textContent;
  button.disabled = true;
  button.textContent = "가이드 생성 중...";
  try {
    const result = await apiJson(`/api/clusters/${encodeURIComponent(clusterId)}/policy-applies`, {
      method: "POST",
      body: JSON.stringify({ manifest: latestPolicyManifestText }),
    });
    renderPolicyApplyResult(result);
    if (result.status === "applied") {
      await refreshDashboardSummary();
      showToast("정책 적용 완료");
    } else if (result.status === "not_configured") {
      showToast("kubectl 적용 가이드 준비 완료");
    } else {
      showToast("정책 적용 결과 확인 필요");
    }
  } finally {
    button.textContent = previousText;
    renderPolicyApplyPanel();
  }
}

function ensureSlackSettingsPanel() {
  if ($("#slackSettingsPanel")) {
    return;
  }
  const anchor = $("#clusterSetupAuthMessage");
  const parent = anchor?.parentElement || $("#clusterSetupContent");
  if (!parent) {
    return;
  }
  const panel = document.createElement("section");
  panel.id = "slackSettingsPanel";
  panel.className = "card slack-settings-card";
  panel.innerHTML = `
    <div class="card-heading slack-card-heading">
      <span class="devicon--slack slack-icon" aria-hidden="true"></span>
      <h2>Slack Notifications</h2>
    </div>
    <p id="slackSettingsAuthMessage" class="muted">로그인 후 Slack 알림을 설정할 수 있습니다.</p>
    <div id="slackSettingsContent" class="slack-settings-content" hidden>
      <div class="slack-webhook-form">
        <label>
          Slack webhook URL
          <input id="slackWebhookUrl" class="slack-webhook-input" type="url" autocomplete="off" placeholder="https://hooks.slack.com/services/..." />
        </label>
        <div class="button-row slack-actions">
          <button id="saveSlackSettings" class="primary slack-primary-action">저장</button>
          <button id="testSlackSettings" class="slack-secondary-action" type="button">테스트</button>
        </div>
      </div>
      <div class="slack-cluster-section">
        <div>
          <h3>클러스터별 알림</h3>
          <p class="muted slack-cluster-helper">High/Critical 런타임 이벤트만 Slack으로 전송합니다.</p>
        </div>
        <div id="slackClusterToggles" class="slack-cluster-list"></div>
      </div>
    </div>
  `;
  parent.appendChild(panel);
}

function renderSlackSettings() {
  ensureSlackSettingsPanel();
  if (!$("#slackSettingsPanel")) {
    return;
  }
  const isAuthenticated = Boolean(authState.authenticated);
  $("#slackSettingsAuthMessage").hidden = isAuthenticated;
  $("#slackSettingsContent").hidden = !isAuthenticated;
  if (isAuthenticated) {
    $("#slackWebhookUrl").value = slackSettings.webhook_url || "";
    renderSlackClusterToggles();
  }
}

function renderSlackClusterToggles() {
  ensureSlackSettingsPanel();
  const container = $("#slackClusterToggles");
  if (!container || !authState.authenticated) {
    return;
  }
  if (!userClusters.length) {
    container.innerHTML = '<p class="muted slack-cluster-empty">Slack 알림을 켤 클러스터가 없습니다.</p>';
    return;
  }
  container.innerHTML = userClusters
    .map(
      (cluster) => {
        const isSlackEnabled = cluster.slack_enabled !== false;
        return `
        <label class="cluster-row slack-cluster-row">
          <span class="slack-cluster-copy">
            <span class="slack-cluster-title-row">
              <strong>${escapeHtml(cluster.name || "unknown-cluster")}</strong>
              <span class="slack-status-badge ${isSlackEnabled ? "is-active" : "is-muted"}">
                <span class="slack-status-dot"></span>
                ${isSlackEnabled ? "Active" : "Muted"}
              </span>
            </span>
            <p>High/Critical 런타임 이벤트만 Slack으로 전송</p>
          </span>
          <span class="slack-toggle-wrap">
            <input
              class="slack-toggle-input"
              type="checkbox"
              data-slack-cluster="${escapeHtml(cluster.id || "")}"
              ${isSlackEnabled ? "checked" : ""}
            />
            <span class="slack-toggle" aria-hidden="true">
              <span class="slack-toggle-thumb"></span>
            </span>
          </span>
        </label>
      `;
      },
    )
    .join("");
}

async function loadSlackSettings() {
  if (!authState.authenticated) {
    slackSettings = { webhook_url: "", configured: false };
    renderSlackSettings();
    return;
  }
  const body = await apiJson("/api/slack-settings");
  slackSettings = body.settings || { webhook_url: "", configured: false };
  renderSlackSettings();
}

async function saveSlackSettings() {
  const body = await apiJson("/api/slack-settings", {
    method: "POST",
    body: JSON.stringify({ webhook_url: $("#slackWebhookUrl").value.trim() }),
  });
  slackSettings = body.settings || slackSettings;
  renderSlackSettings();
  showToast("Slack 설정 저장 완료");
}

async function testSlackSettings() {
  await apiJson("/api/slack-settings/test", { method: "POST" });
  showToast("Slack 테스트 전송 완료");
}

async function setClusterSlack(clusterId, enabled) {
  const body = await apiJson(`/api/clusters/${encodeURIComponent(clusterId)}/slack`, {
    method: "POST",
    body: JSON.stringify({ enabled }),
  });
  const updated = body.cluster;
  userClusters = userClusters.map((cluster) => (cluster.id === updated.id ? { ...cluster, ...updated } : cluster));
  renderSlackClusterToggles();
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

async function trashUserCluster(clusterId) {
  await apiJson(`/api/clusters/${encodeURIComponent(clusterId)}`, {
    method: "DELETE",
  });
  await loadUserClusters();
  await refreshDashboardSummary();
  showToast("클러스터를 휴지통으로 이동했습니다");
}

async function restoreUserCluster(clusterId) {
  await apiJson(`/api/clusters/${encodeURIComponent(clusterId)}/restore`, {
    method: "POST",
  });
  await loadUserClusters();
  await refreshDashboardSummary();
  showToast("클러스터를 복원했습니다. 사용 전 토큰을 재발급하세요");
}

async function loadRuntimeEvent(eventId) {
  if (!authState.authenticated) {
    showToast("로그인 후 사용할 수 있습니다");
    return;
  }
  renderSelectedRuntimeEventState("loading", { id: eventId }, "이 이벤트 상세를 불러오는 중입니다.");
  try {
    const response = await fetch(`/runtime-events/${encodeURIComponent(eventId)}`);
    if (!response.ok) {
      throw new Error(await response.text());
    }
    selectedRuntimeEvent = await response.json();
    $("#eventPayload").value = JSON.stringify(eventToAnalysisPayload(selectedRuntimeEvent), null, 2);
    $("#resourceManifest").value = selectedRuntimeEvent.resource_manifest || "";
    renderManifestGuidance(null);
    renderSelectedRuntimeEventState("ready", selectedRuntimeEvent);
    showToast(`이벤트 #${shortEventId(selectedRuntimeEvent)} 상세를 불러왔습니다`);
  } catch (error) {
    renderSelectedRuntimeEventState("error", { id: eventId }, "이 이벤트 상세를 불러오지 못했습니다.");
    throw error;
  }
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
    `/resource-manifest?event_id=${encodeURIComponent(selectedRuntimeEvent.id || "")}&namespace=${encodeURIComponent(namespace)}&pod=${encodeURIComponent(pod)}`,
  );
  const body = await response.json();
  renderManifestGuidance(body);
  if (body.manifest) {
    $("#resourceManifest").value = body.manifest;
    showToast("저장된 매니페스트를 불러왔습니다");
  } else if (body.kubectl_command) {
    showToast("kubectl 명령을 준비했습니다");
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
    <p>최근 Falco/Gatekeeper 이벤트를 집계하고 LLM 요약을 생성하고 있습니다.</p>
  `;
  const response = await fetch("/compliance-report", {
    headers: llmHeaders(),
  });
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
  const llmSummary = report.llm_summary
    ? `<div class="analysis-code-block"><p>${escapeHtml(report.llm_summary)}</p></div>`
    : `<p>${escapeHtml(report.llm_error || "LLM 요약을 생성하지 못해 규칙 기반 리포트만 표시합니다.")}</p>`;
  $("#reportResult").innerHTML = `
    <span class="badge ${report.llm_used ? "ready" : "loading"}">${report.llm_used ? "LLM report" : "rule report"}</span>
    <h2>AI 컴플라이언스 리포트</h2>
    <p>generated_at: ${escapeHtml(report.generated_at || "")}</p>
    <h3>LLM 요약</h3>
    ${llmSummary}
    <h3>상위 위반 Rule</h3>
    <ul>${topRules || "<li>수집된 rule 없음</li>"}</ul>
    <h3>권장 조치</h3>
    <ul>${recommendations}</ul>
    <div class="analysis-code-block">
      <pre><code>${escapeHtml(latestReportText)}</code></pre>
    </div>
  `;
  latestReportHtml = $("#reportResult").innerHTML;
}

function downloadReportPdf() {
  if (!latestReportText || !latestReportHtml) {
    showToast("먼저 리포트를 생성해 주세요");
    return;
  }
  const generatedAt = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
  const printWindow = window.open("", "kubeowl-report-pdf", "width=960,height=720");
  if (!printWindow) {
    showInlineAlert("팝업이 차단되어 PDF 창을 열 수 없습니다. 브라우저 팝업 허용 후 다시 시도해 주세요.");
    return;
  }
  printWindow.document.write(`
    <!doctype html>
    <html lang="ko">
      <head>
        <meta charset="utf-8" />
        <title>KubeOwl AI Report ${generatedAt}</title>
        <style>
          * { box-sizing: border-box; }
          body {
            margin: 0;
            padding: 32px;
            color: #111827;
            font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            line-height: 1.55;
          }
          .report-print {
            max-width: 860px;
            margin: 0 auto;
          }
          .badge {
            display: inline-block;
            margin-bottom: 12px;
            padding: 4px 10px;
            border: 1px solid #bbf7d0;
            border-radius: 999px;
            background: #f0fdf4;
            color: #15803d;
            font-size: 12px;
            font-weight: 800;
          }
          h1, h2, h3 { margin: 0 0 10px; line-height: 1.2; }
          h1 { margin-bottom: 24px; font-size: 28px; }
          h2 { font-size: 22px; }
          h3 { margin-top: 22px; font-size: 15px; color: #374151; }
          p, li { font-size: 13px; }
          ul { padding-left: 18px; }
          .analysis-code-block {
            margin-top: 10px;
            padding: 14px;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            background: #f9fafb;
          }
          pre {
            white-space: pre-wrap;
            word-break: break-word;
            margin: 0;
            font-size: 10px;
          }
          @page { margin: 16mm; }
          @media print {
            body { padding: 0; }
          }
        </style>
      </head>
      <body>
        <main class="report-print">
          <h1>KubeOwl AI Report</h1>
          ${latestReportHtml}
        </main>
      </body>
    </html>
  `);
  printWindow.document.close();
  printWindow.focus();
  window.setTimeout(() => {
    printWindow.print();
  }, 250);
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
  tab.addEventListener("click", () => {
    activateTab(tab.dataset.tab);
    $(".sidebar")?.classList.remove("is-open");
    $("#navMenuToggle")?.setAttribute("aria-expanded", "false");
  });
});

ensureSlackSettingsPanel();
ensurePolicyApplyPanel();

$("#generatePolicy").addEventListener("click", () => {
  generatePolicy().catch((error) => {
    showInlineAlert(error.message);
    showToast(error.message);
  });
});

document.addEventListener("click", (event) => {
  const applyButton = event.target.closest("#applyGeneratedPolicy");
  if (!applyButton) {
    return;
  }
  applyGeneratedPolicy().catch((error) => {
    renderPolicyApplyResult({ status: "error", error: error.message, resources: [] });
    showInlineAlert(error.message);
    showToast("정책 적용 실패");
  });
});

document.addEventListener("click", (event) => {
  const copyButton = event.target.closest("[data-copy-policy-step]");
  if (!copyButton) {
    return;
  }
  event.preventDefault();
  event.stopPropagation();
  const target = document.getElementById(copyButton.dataset.copyPolicyStep || "");
  copyText(target?.textContent || "")
    .then(() => showToast("kubectl 단계 복사 완료"))
    .catch((error) => showToast(error.message));
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

$("#showDeletedClusters").addEventListener("change", () => {
  loadUserClusters().catch((error) => {
    showInlineAlert(error.message);
    showToast("클러스터 목록 로드 실패");
  });
});

$("#userClusters").addEventListener("click", (event) => {
  const rotateButton = event.target.closest("[data-user-rotate]");
  const deleteButton = event.target.closest("[data-user-delete]");
  const restoreButton = event.target.closest("[data-user-restore]");
  if (rotateButton) {
    rotateUserClusterToken(rotateButton.dataset.userRotate).catch((error) => {
      showInlineAlert(error.message);
      showToast("토큰 재발급 실패");
    });
    return;
  }
  if (deleteButton) {
    trashUserCluster(deleteButton.dataset.userDelete).catch((error) => {
      showInlineAlert(error.message);
      showToast("클러스터 삭제 실패");
    });
    return;
  }
  if (!restoreButton) {
    return;
  }
  restoreUserCluster(restoreButton.dataset.userRestore).catch((error) => {
    showInlineAlert(error.message);
    showToast("클러스터 복원 실패");
  });
});

$("#saveSlackSettings").addEventListener("click", () => {
  saveSlackSettings().catch((error) => {
    showInlineAlert(error.message);
    showToast("Slack 설정 저장 실패");
  });
});

$("#testSlackSettings").addEventListener("click", () => {
  testSlackSettings().catch((error) => {
    showInlineAlert(error.message);
    showToast("Slack 테스트 실패");
  });
});

$("#slackClusterToggles").addEventListener("change", (event) => {
  const input = event.target.closest("[data-slack-cluster]");
  if (!input) {
    return;
  }
  setClusterSlack(input.dataset.slackCluster, input.checked)
    .then(() => showToast("클러스터 Slack 설정 변경 완료"))
    .catch((error) => {
      showInlineAlert(error.message);
      showToast("클러스터 Slack 설정 실패");
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

$("#downloadReportPdf").addEventListener("click", () => {
  downloadReportPdf();
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

document.addEventListener("click", (event) => {
  const button = event.target.closest(".copy-manifest-command");
  if (!button) {
    return;
  }
  copyText(latestManifestCommand)
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

$("#enforcementAction").addEventListener("change", () => {
  syncEnforcementBadges();
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

$("#themeToggle").addEventListener("click", () => {
  toggleTheme();
});

$("#navMenuToggle").addEventListener("click", () => {
  const sidebar = $(".sidebar");
  const isOpen = sidebar.classList.toggle("is-open");
  $("#navMenuToggle").setAttribute("aria-expanded", String(isOpen));
  $("#navMenuToggle").setAttribute("aria-label", isOpen ? "메뉴 닫기" : "메뉴 열기");
});

function openPublicPolicyGenerator() {
  const landingIntro = $("#landingIntro");
  if (landingIntro) {
    landingIntro.hidden = true;
  }
  activateTab("policy");
  $("#policyPanel")?.scrollIntoView({ behavior: "smooth", block: "start" });
}

$("#landingPolicyButton").addEventListener("click", () => {
  openPublicPolicyGenerator();
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
  document.body.classList.toggle("logged-out", !authState.authenticated);
  document.body.classList.toggle("logged-in", Boolean(authState.authenticated));
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
  slackSettings = { webhook_url: "", configured: false };
  renderAuthStatus();
  renderUserClusters();
  renderSlackSettings();
  renderPolicyApplyPanel();
  renderDashboardSummary({});
  selectedRuntimeEvent = null;
  renderSelectedRuntimeEventState("ready");
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

applyTheme(localStorage.getItem(THEME_KEY) || "light");
initLlmKeyPanel();
syncPolicyPromptMode();
window.setInterval(() => {
  if (authState.authenticated) {
    refreshRuntimeEvents().catch(() => {});
    refreshDashboardSummary().catch(() => {});
  }
}, 30000);
loadConfig().catch(() => showToast("설정 로드 실패"));
loadAuthStatus()
  .then(() =>
    Promise.all([
      loadUserClusters(),
      loadSlackSettings(),
      authState.authenticated ? refreshDashboardSummary() : Promise.resolve(renderDashboardSummary({})),
      authState.authenticated ? refreshRuntimeEvents() : Promise.resolve(),
    ]),
  )
  .catch(() => {
    $("#authStatus").textContent = "로그인 상태 확인 실패";
    renderAuthGates();
  });
