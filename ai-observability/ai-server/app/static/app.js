const $ = (selector) => document.querySelector(selector);

let latestPolicyText = "";
let latestPolicyManifestText = "";
let latestAnalysisText = "";
let latestYamlSnippet = "";
let latestReportText = "";
let latestReportReadableText = "";
let latestReportHtml = "";
let latestReportRawVisible = false;
let latestManifestCommand = "";
let selectedRuntimeEvent = null;
let authState = { authenticated: false, user: null, auth: { google_configured: false, dev_enabled: false } };
let userClusters = [];
let slackSettings = { webhook_url: "", configured: false };
let landingTypewriterStarted = false;
let apiBackoffUntil = 0;
let runtimeEventsCollapsed = false;
const AUTH_REQUIRED_TABS = new Set(["setup", "analysis", "report"]);
const SESSION_KEY = "complianceAiLlmApiKey";
const THEME_KEY = "complianceOpsTheme";
const LAST_AUTH_EMAIL_KEY = "kubeowlLastAuthEmail";
const DEFAULT_RUNTIME_LIMIT = "10";
const SEOUL_TIME_ZONE = "Asia/Seoul";
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
  } else {
    showInlineAlert("API key를 먼저 적용해 주세요.");
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
  if (Date.now() < apiBackoffUntil) {
    throw new Error("zrok 연결 복구 대기 중입니다. 잠시 후 자동으로 다시 시도합니다.");
  }
  const response = await fetch(path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    if ([502, 503, 504].includes(response.status)) {
      apiBackoffUntil = Date.now() + 30_000;
    }
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
  const landingIntro = $("#landingIntro");
  if (landingIntro) {
    landingIntro.hidden = true;
  }
  document.querySelector(".landing-top-cue")?.classList.remove("is-visible");
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
    pageTitle.textContent = activeTab.querySelector(".nav-label")?.textContent.trim() || activeTab.textContent.trim();
  }
}

function isAuthRequiredTab(tabName) {
  return AUTH_REQUIRED_TABS.has(tabName);
}

function updateNavigationAuthState() {
  const shouldLock = !authState.authenticated;
  document.querySelectorAll(".tab[data-auth-required='true']").forEach((tab) => {
    tab.classList.toggle("is-locked", shouldLock);
    tab.setAttribute("aria-disabled", String(shouldLock));
    tab.title = shouldLock ? "로그인 후 이용할 수 있습니다." : "";
  });
}

function updateLandingActions() {
  const isAuthenticated = Boolean(authState.authenticated);
  const landingPolicyButton = $("#landingPolicyButton");
  $("#landingLoginLink").hidden = isAuthenticated;
  if (landingPolicyButton) {
    landingPolicyButton.textContent = isAuthenticated ? "Go to Dashboard" : "Policy Generator";
  }
}

function showLandingHome() {
  const landingIntro = $("#landingIntro");
  if (!landingIntro) {
    return;
  }
  updateLandingActions();
  landingIntro.hidden = false;
  document.querySelectorAll(".panel").forEach((panel) => {
    panel.classList.remove("is-active");
  });
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.classList.remove("is-active");
  });
  $("#pageTitle").textContent = "Home";
  window.scrollTo({ top: 0, behavior: "smooth" });
  startLandingTypewriter();
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function highlightEditableCommand(value) {
  return escapeHtml(value).replaceAll(
    "alice@example.com",
    '<span class="command-editable-value" contenteditable="true" spellcheck="false">alice@example.com</span>',
  );
}

function shortEventId(event) {
  const id = String(event?.id || "");
  return id ? id.slice(0, 8) : "no-id";
}

function eventTimestamp(event) {
  return event?.timestamp || event?.time || event?.created_at || "";
}

function formatSeoulDateTime(value, options = {}) {
  if (!value) {
    return "time unknown";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  const dateOptions = {
    timeZone: SEOUL_TIME_ZONE,
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  };
  if (options.includeYear !== false) {
    dateOptions.year = "numeric";
  }
  return `${date.toLocaleString("ko-KR", dateOptions)} KST`;
}

function formatEventTime(event) {
  return formatSeoulDateTime(eventTimestamp(event), { includeYear: false });
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
  const appliedCount = Number(summary.active_policies_applied || 0);
  const guideCount = Number(summary.active_policies_generated_guides || 0);
  $("#activePoliciesMetricDetail").textContent =
    summary.active_policies_error
      ? `Policy history error: ${summary.active_policies_error}`
    : summary.active_policies_source === "user_policy_apply_history"
      ? guideCount > 0
        ? `${appliedCount} server-applied / ${guideCount} kubectl guides`
        : "Applied in your clusters"
      : "Your applied policies";
  $("#recentViolationsMetric").textContent = String(summary.recent_violations ?? 0);
  $("#runtimeEventsMetric").textContent = String(summary.runtime_events ?? 0);
  $("#lastSyncMetric").textContent = formatRelativeTime(summary.last_sync || "");
  $("#lastSyncMetricDetail").textContent = summary.last_sync ? "Cluster telemetry" : "No cluster sync yet";
}

function renderObservabilityList(selector, items, emptyText) {
  const list = $(selector);
  if (!list) {
    return;
  }
  if (!items.length) {
    list.innerHTML = `<li>${escapeHtml(emptyText)}</li>`;
    return;
  }
  list.innerHTML = items
    .map((item) => `<li><span>${escapeHtml(item.label)}</span><strong>${escapeHtml(item.count)}</strong></li>`)
    .join("");
}

function renderUserObservability(summary = {}) {
  if (!$("#ownedClusterMetric")) {
    return;
  }
  const clusters = summary.clusters || [];
  const clusterCounts = summary.cluster_counts || {};
  const eventCounts = summary.event_counts || {};
  const breakdowns = summary.breakdowns || {};
  $("#ownedClusterMetric").textContent = authState.authenticated
    ? `${clusterCounts.active || 0} active / ${clusterCounts.total || 0} total`
    : "로그인 후 클러스터 상태를 확인할 수 있습니다.";
  renderObservabilityList(
    "#ownedClusterList",
    clusters.slice(0, 6).map((cluster) => ({
      label: `${cluster.name || "unknown-cluster"} · ${cluster.status || "active"}`,
      count: cluster.event_count || 0,
    })),
    authState.authenticated ? "등록된 클러스터 없음" : "로그인 필요",
  );
  $("#runtimeMetricDetail").textContent = authState.authenticated
    ? `${eventCounts.recent_24h || 0} events in the last 24h / ${eventCounts.total || 0} total`
    : "사용자 소유 클러스터에서 수집된 이벤트만 집계합니다.";
  renderObservabilityList(
    "#severityBreakdownList",
    breakdowns.severity || [],
    authState.authenticated ? "수집된 이벤트 없음" : "로그인 필요",
  );
  const topSignals = [
    ...(breakdowns.rule || []).slice(0, 3).map((item) => ({ label: `Rule: ${item.label}`, count: item.count })),
    ...(breakdowns.namespace || []).slice(0, 3).map((item) => ({ label: `Namespace: ${item.label}`, count: item.count })),
  ];
  $("#topSignalsDetail").textContent = authState.authenticated
    ? "Rules and namespaces scoped to your clusters"
    : "규칙과 네임스페이스를 사용자 범위 안에서 요약합니다.";
  renderObservabilityList(
    "#topSignalsList",
    topSignals,
    authState.authenticated ? "수집된 신호 없음" : "로그인 필요",
  );
}

async function refreshDashboardSummary() {
  if (!authState.authenticated) {
    renderDashboardSummary({});
    renderUserObservability({});
    return;
  }
  if (Date.now() < apiBackoffUntil) {
    return;
  }
  const [summary, observability] = await Promise.all([
    apiJson("/dashboard-summary"),
    apiJson("/api/observability/summary"),
  ]);
  renderDashboardSummary(summary);
  renderUserObservability(observability);
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

function resourceManifestCommand(event = selectedRuntimeEvent) {
  const namespace = event?.namespace || event?.output_fields?.["k8s.ns.name"] || "default";
  const pod = event?.pod_name || event?.output_fields?.["k8s.pod.name"] || "<pod-name>";
  return `kubectl get pod ${pod} -n ${namespace} -o yaml`;
}

function renderResourceManifestHelp(event = selectedRuntimeEvent, missingManifest = false) {
  const helper = $("#resourceManifestHelp");
  if (!helper) {
    return;
  }
  const command = resourceManifestCommand(event);
  helper.innerHTML = missingManifest
    ? `저장된 매니페스트가 없으면 사용자가 직접 붙여넣어야 합니다. 예: <code>${escapeHtml(command)}</code>`
    : `선택한 이벤트에 저장된 매니페스트가 없으면 사용자가 직접 붙여넣는 입력칸입니다. 예: <code>${escapeHtml(command)}</code>`;
}

function setReportLoading(isLoading) {
  $("#reportLoading").hidden = !isLoading;
  $("#reportLoadingText").textContent = "최근 Falco/Gatekeeper 이벤트를 집계하고 LLM 요약을 생성하고 있습니다.";
  $("#generateReport").disabled = isLoading;
  $("#generateReport").textContent = isLoading ? "생성 중..." : "리포트 생성";
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

function analysisScopeTrail(payload) {
  const nodes = [
    { label: "Cluster", value: payload.cluster || "current-cluster", icon: "C" },
    { label: "Namespace", value: fieldValue(payload, "k8s.ns.name"), icon: "NS" },
    { label: "Pod", value: fieldValue(payload, "k8s.pod.name"), icon: "P" },
    { label: "Container", value: fieldValue(payload, "container.name"), icon: "CT", alert: true },
  ];
  return `
    <div class="analysis-scope-trail" aria-label="runtime violation resource path">
      ${nodes
        .map(
          (node, index) => `
            <div class="scope-node ${node.alert ? "is-alert" : ""}">
              <span class="scope-icon" aria-hidden="true">${escapeHtml(node.alert ? "🚨" : node.icon)}</span>
              <span class="scope-label">${escapeHtml(node.label)}</span>
              <strong class="scope-value">${escapeHtml(node.value || "unknown")}</strong>
            </div>
            ${index < nodes.length - 1 ? '<span class="scope-arrow" aria-hidden="true">→</span>' : ""}
          `,
        )
        .join("")}
    </div>
  `;
}

function renderYamlSnippet(yamlSnippet) {
  const originalManifest = $("#resourceManifest")?.value.trim() || "";
  if (!yamlSnippet) {
    return `
      <div class="analysis-code-block">
        <h3>매니페스트 변경 제안</h3>
        <p>이 이벤트에는 바로 적용할 수 있는 YAML 패치 제안이 없습니다.</p>
      </div>
    `;
  }
  const originalLines = originalManifest
    ? renderManifestLines(originalManifest, "original", yamlSnippet)
    : `<span class="diff-line muted">저장된 리소스 매니페스트가 없습니다. 상단의 매니페스트 조회 버튼으로 kubectl 조회 명령을 확인하세요.</span>`;
  return `
    <div class="analysis-code-block manifest-diff-block">
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
        <h3>매니페스트 변경 제안</h3>
      </div>
      <div class="manifest-diff-grid">
        <section class="manifest-diff-pane">
          <h4>기존 리소스 매니페스트</h4>
          <pre><code>${originalLines}</code></pre>
        </section>
        <section class="manifest-diff-pane">
          <h4>AI 제안 패치</h4>
          <pre><code id="analysisYamlOutput">${renderManifestLines(yamlSnippet, "added")}</code></pre>
        </section>
      </div>
    </div>
  `;
}

function renderManifestLines(value, mode = "context", suggestedPatch = "") {
  const patchText = String(suggestedPatch || "").toLowerCase();
  return String(value || "")
    .split("\n")
    .map((line) => `<span class="${manifestLineClass(line, mode, patchText)}">${escapeHtml(line || " ")}</span>`)
    .join("\n");
}

function manifestLineClass(line, mode, patchText = "") {
  if (mode === "added") {
    return "diff-line diff-added";
  }
  if (mode !== "original") {
    return "diff-line";
  }
  const normalized = String(line || "").trim().toLowerCase();
  const riskyPatterns = [
    /^privileged:\s*true$/,
    /^allowprivilegeescalation:\s*true$/,
    /^runasuser:\s*0$/,
    /^runasnonroot:\s*false$/,
    /^hostpid:\s*true$/,
    /^hostipc:\s*true$/,
    /^hostnetwork:\s*true$/,
    /^automountserviceaccounttoken:\s*true$/,
    /^image:\s*[^ ]+:latest$/,
  ];
  if (riskyPatterns.some((pattern) => pattern.test(normalized))) {
    return "diff-line diff-removed";
  }
  if (patchText.includes("kind: networkpolicy") && /^(name|namespace|app):\s+/.test(normalized)) {
    return "diff-line diff-removed";
  }
  if (patchText.includes("securitycontext") && /^(securitycontext|allowprivilegeescalation|capabilities|drop|runasnonroot|readonlyrootfilesystem):/.test(normalized)) {
    return "diff-line diff-removed";
  }
  return "diff-line";
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
    ${analysisScopeTrail(payload)}
    <div class="analysis-context-grid" aria-label="analysis target context">${analysisContextRows(payload)}</div>
    <div class="analysis-insight-grid">
      <section class="analysis-insight-card">
        <h3>심각도 설명</h3>
        <p>${escapeHtml(result.severity_explanation || result.reason)}</p>
      </section>
      <section class="analysis-insight-card">
        <h3>원인 요약</h3>
        <p>${escapeHtml(result.root_cause)}</p>
      </section>
      <section class="analysis-insight-card">
        <h3>권장 수정</h3>
        <p>${escapeHtml(result.recommended_fix || result.remediation)}</p>
      </section>
      <section class="analysis-insight-card">
        <h3>구체적 조치</h3>
        <p>${escapeHtml(result.remediation)}</p>
      </section>
    </div>
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
    </div>
    <div class="policy-apply-notice">
      <strong>사용자 클러스터 적용 안내</strong>
      <p>현재 AI 서버는 사용자 클러스터에 직접 Kubernetes API apply 권한을 갖지 않습니다. 아래에서 생성되는 단계별 명령을 대상 클러스터 context에서 실행하세요.</p>
      <p>터미널에서 <code>kubectl config current-context</code>로 대상 클러스터를 확인한 뒤 Gatekeeper 설치 확인, 권한 확인, 필요 시 RBAC, dry-run, apply 순서로 진행합니다.</p>
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
      key: "gatekeeper",
      label: "1. Gatekeeper 설치 확인",
      description: "대상 클러스터에 Gatekeeper API와 controller pod가 준비되어 있는지 확인합니다.",
      command: fallback.gatekeeper_check_command,
      open: true,
    },
    {
      key: "permission",
      label: "2. 권한 확인",
      description: "현재 kubeconfig 계정이 Gatekeeper 리소스를 읽고 생성/수정할 수 있는지 확인합니다.",
      command: fallback.permission_check_command,
      open: true,
    },
    {
      key: "rbac",
      label: "3. 필요 시 RBAC",
      description: "권한 확인이 실패하면 클러스터 관리자가 먼저 실행하는 예시 권한 부여 명령입니다.",
      command: fallback.admin_rbac_command,
      open: true,
    },
    {
      key: "dry-run",
      label: "4. dry-run 검증",
      description: "ConstraintTemplate을 검증/등록한 뒤 Constraint를 API 서버 dry-run으로 확인합니다.",
      command: fallback.dry_run_command,
      open: true,
    },
    {
      key: "apply",
      label: "5. 실제 apply",
      description: "dry-run이 성공한 뒤 같은 클러스터 context에서 실행합니다.",
      command: fallback.apply_command,
      open: true,
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
                    <strong>
                      ${escapeHtml(step.label)}
                      <span class="policy-apply-step-toggle" aria-hidden="true"></span>
                    </strong>
                    <small>${escapeHtml(step.description)}</small>
                  </span>
                  <button class="secondary" data-copy-policy-step="${targetId}" type="button">복사</button>
                </summary>
                <pre id="${targetId}" class="policy-apply-command" contenteditable="true" spellcheck="false">${highlightEditableCommand(step.command)}</pre>
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
  if (!container) {
    return;
  }
  const status = result?.status || "unknown";
  const isKubectlGuide = status === "not_configured";
  const rows = (result.resources || [])
    .map(
      (item) => `
        <div class="policy-apply-resource">
          <strong>${escapeHtml(item.order || "-")}. ${escapeHtml(item.kind || "Unknown")} / ${escapeHtml(item.name || "-")}</strong>
          <p>
            ${
              isKubectlGuide
                ? "kubectl 단계에서 실행 예정"
                : `dry-run=${escapeHtml(item.dry_run_status || "skipped")} · apply=${escapeHtml(item.apply_status || "skipped")}`
            }
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

function setRuntimeEventsCollapsed(collapsed) {
  runtimeEventsCollapsed = collapsed;
  const container = $("#runtimeEvents");
  const hint = $(".analysis-selection-hint");
  const button = $("#toggleRuntimeEvents");
  if (container) {
    container.hidden = collapsed;
  }
  if (hint) {
    hint.hidden = collapsed;
  }
  if (button) {
    button.textContent = collapsed ? "위반 이벤트 펼치기" : "위반 이벤트 접기";
    button.setAttribute("aria-expanded", String(!collapsed));
  }
}

async function generatePolicy() {
  clearInlineAlert();
  const useLlm = $("#useLlm").checked;
  const selectedPolicyKind = $("#policyKind").value;
  if (!selectedPolicyKind) {
    showInlineAlert("정책 유형을 선택해 주세요.");
    showToast("정책 유형 선택 필요");
    return;
  }
  setPolicyLoading(true);
  const payload = {
    prompt: POLICY_PROMPTS[selectedPolicyKind],
    policy_kind: selectedPolicyKind,
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
  const selectedPolicyKind = $("#policyKind").value;
  if (!selectedPolicyKind) {
    $("#policyKind").value = "latest-tag";
  }
  syncEnforcementBadges();
}

function syncEnforcementBadges() {
  const selected = $("#enforcementAction")?.value || "dryrun";
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
  try {
    const useLlm = $("#useViolationLlm").checked;
    const hasSelectedEvent = Boolean(selectedRuntimeEvent?.id);
    let payload;
    setAnalysisState(
      "loading",
      "위반 상세 분석 중",
      hasSelectedEvent
        ? (useLlm
          ? "선택한 런타임 이벤트와 저장된 매니페스트를 LLM에 함께 전달하고 있습니다."
          : "선택한 런타임 이벤트를 규칙 기반으로 분석하고 있습니다.")
        : (useLlm
          ? "이벤트 JSON과 리소스 매니페스트를 LLM에 함께 전달하고 있습니다."
          : "이벤트 JSON과 리소스 매니페스트를 규칙 기반으로 분석하고 있습니다."),
    );
    let result;
    const manualManifest = $("#resourceManifest").value.trim();
    if (hasSelectedEvent) {
      payload = eventToAnalysisPayload(selectedRuntimeEvent);
      const response = await fetch(`/analyze-runtime-event/${encodeURIComponent(selectedRuntimeEvent.id)}`, {
        method: "POST",
        headers: llmHeaders(),
      });
      const body = await response.json();
      if (!response.ok) {
        throw new Error(formatErrorMessage(body.error || body.detail || `HTTP ${response.status}`));
      }
      result = body;
    } else {
      if (!$("#eventPayload").value.trim()) {
        setAnalysisState("error", "이벤트를 선택하세요", "최근 위반 이벤트 목록에서 분석할 이벤트를 먼저 선택하세요.");
        throw new Error("최근 위반 이벤트 목록에서 분석할 이벤트를 먼저 선택하세요.");
      }
      if (hasSelectedEvent) {
        payload = eventToAnalysisPayload(selectedRuntimeEvent);
      } else {
        try {
          payload = JSON.parse($("#eventPayload").value);
        } catch (error) {
          setAnalysisState("error", "JSON 형식 오류", error.message);
          throw error;
        }
      }
      payload.resource_manifest = manualManifest;
      payload.use_llm = useLlm;
      result = await postJson("/analyze-violation", payload);
    }
    renderViolationAnalysis(result, payload);
    latestAnalysisText = JSON.stringify(result, null, 2);
    showToast("분석 완료");
  } finally {
    setAnalysisLoading(false);
  }
}

async function refreshRuntimeEvents() {
  const container = $("#runtimeEvents");
  ensureRuntimeUsabilityControls();
  setRuntimeEventsCollapsed(runtimeEventsCollapsed);
  if (!authState.authenticated) {
    container.innerHTML = "";
    return;
  }
  if (Date.now() < apiBackoffUntil) {
    return;
  }
  if (runtimeEventsCollapsed) {
    return;
  }
  const limit = $("#runtimeEventLimit")?.value || DEFAULT_RUNTIME_LIMIT;
  const query = new URLSearchParams({
    limit,
    cluster: $("#runtimeCluster").value,
    cluster_kind: "",
    source: $("#runtimeSource").value,
    include_legacy: "false",
    exclude_infra: "false",
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
  container.innerHTML =
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
  if ($("#runtimeEventLimit")) {
    return;
  }
  const anchor = $("#runtimeSource");
  if (!anchor) {
    return;
  }
  const wrapper = anchor.closest("label") || anchor;
  wrapper.insertAdjacentHTML(
    "afterend",
    `
      <label class="runtime-limit-field">
        표시 개수
        <select id="runtimeEventLimit">
          <option value="3">3</option>
          <option value="5">5</option>
          <option value="10" selected>10</option>
          <option value="20">20</option>
          <option value="50">50</option>
          <option value="100">100</option>
        </select>
      </label>
    `,
  );
  const actions = $(".runtime-actions");
  const limitField = $("#runtimeEventLimit")?.closest("label");
  if (actions && limitField) {
    limitField.insertAdjacentElement("afterend", actions);
  }
  ["#runtimeEventLimit"].forEach((selector) => {
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
  updateNavigationAuthState();
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
  updateLandingActions();
  landingIntro.hidden = isAuthenticated;
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

function setupLandingScrollAnimation() {
  const items = document.querySelectorAll(
    ".landing-showcase .showcase-demo-copy, .landing-showcase .showcase-demo-media, .landing-showcase .showcase-code span",
  );
  const topCue = document.querySelector(".landing-top-cue");
  const downCue = document.querySelector(".landing-scroll-cue");
  const showcase = document.querySelector("#landingShowcase");
  const updateLandingCues = () => {
    if (!topCue && !downCue) {
      return;
    }
    const landingVisible = !$("#landingIntro")?.hidden;
    const showcasePoint = showcase ? Math.max(180, showcase.offsetTop - window.innerHeight * 0.35) : Math.max(240, window.innerHeight * 0.55);
    const reachedShowcase = window.scrollY > showcasePoint;
    topCue?.classList.toggle("is-visible", landingVisible && reachedShowcase);
    downCue?.classList.toggle("is-hidden", !landingVisible || reachedShowcase);
  };
  window.addEventListener("scroll", updateLandingCues, { passive: true });
  window.addEventListener("resize", updateLandingCues);
  updateLandingCues();
  if (!items.length) {
    return;
  }
  if (!("IntersectionObserver" in window)) {
    items.forEach((item) => item.classList.add("is-visible"));
    return;
  }
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-visible");
          observer.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.18, rootMargin: "0px 0px -8% 0px" },
  );
  items.forEach((item, index) => {
    item.style.setProperty("--reveal-delay", `${Math.min(index * 70, 560)}ms`);
    observer.observe(item);
  });
}

function setupShowcaseDemo() {
  const showcaseImageExtensions = ["png", "webp", "jpg", "jpeg"];
  const showcaseImageSlots = ["-1", "-2", ""];
  const showcaseSlideIntervalMs = 4200;
  let showcaseSlideTimer = null;
  let showcaseActivationId = 0;
  const demos = {
    policy: {
      kicker: "Policy",
      title: "정책 생성",
      description: "선택한 정책 유형을 검토 가능한 Kubernetes 정책 YAML로 정리합니다.",
      bullets: ["정책 유형 선택", "Gatekeeper YAML 생성", "클러스터 적용 가이드"],
      alt: "Policy generator showcase preview",
    },
    runtime: {
      kicker: "Runtime",
      title: "런타임 위반 분석",
      description: "Falco와 Gatekeeper 이벤트를 영향 범위와 조치 흐름으로 연결합니다.",
      bullets: ["이벤트 수집", "위반 상세 확인", "조치 맥락 연결"],
      alt: "Runtime violation showcase preview",
    },
    report: {
      kicker: "AI Report",
      title: "AI 리포트",
      description: "수집된 위반을 요약해 위험도와 다음 행동을 빠르게 정리합니다.",
      bullets: ["컴플라이언스 요약", "위험도 우선순위", "Next Action 제안"],
      alt: "AI report showcase preview",
    },
  };
  const tabs = Array.from(document.querySelectorAll("[data-showcase-demo]"));
  const images = Array.from(document.querySelectorAll("[data-showcase-image]"));
  const placeholder = $("#showcaseDemoPlaceholder");
  const kicker = $("#showcaseDemoKicker");
  const title = $("#showcaseDemoTitle");
  const description = $("#showcaseDemoDescription");
  const bullets = $("#showcaseDemoBullets");
  const copy = document.querySelector(".showcase-demo-copy");
  const media = document.querySelector(".showcase-demo-media");
  if (!tabs.length || images.length < 2 || !kicker || !title || !description || !bullets) {
    return;
  }

  const restartTransition = () => {
    [copy, media].forEach((element) => {
      element?.classList.remove("is-visible");
      void element?.offsetWidth;
      element?.classList.add("is-visible");
    });
  };

  const imageCandidatesFor = (tab) => {
    const explicitPath = tab.dataset.demoImage || "";
    if (explicitPath) {
      return [explicitPath];
    }
    const basePath = tab.dataset.demoImageBase || "";
    if (!basePath) {
      return [];
    }
    return showcaseImageSlots.flatMap((slot) => showcaseImageExtensions.map((extension) => `${basePath}${slot}.${extension}`));
  };

  const loadImagePath = (path) =>
    new Promise((resolve) => {
      const probe = new Image();
      probe.onload = () => resolve(path);
      probe.onerror = () => resolve("");
      probe.src = path;
    });

  const resolveImagePaths = async (paths) => {
    const loadedPaths = await Promise.all(paths.map((path) => loadImagePath(path)));
    return loadedPaths.filter(Boolean).slice(0, 2);
  };

  const clearShowcaseImages = () => {
    stopShowcaseSlides();
    images.forEach((image) => {
      image.classList.remove("is-ready", "is-current");
      image.removeAttribute("src");
    });
    if (placeholder) {
      placeholder.hidden = true;
    }
  };

  const stopShowcaseSlides = () => {
    if (showcaseSlideTimer) {
      window.clearInterval(showcaseSlideTimer);
      showcaseSlideTimer = null;
    }
  };

  const showSlide = (index) => {
    images.forEach((image, imageIndex) => {
      image.classList.toggle("is-current", imageIndex === index);
    });
  };

  const renderImages = (paths, demo) => {
    stopShowcaseSlides();
    images.forEach((image, index) => {
      const path = paths[index] || paths[0] || "";
      image.src = path;
      image.alt = index === 0 ? demo.alt : "";
      image.setAttribute("aria-hidden", String(index !== 0));
      image.classList.add("is-ready");
      image.classList.toggle("is-current", index === 0);
    });
    if (placeholder) {
      placeholder.hidden = true;
    }
    if (paths.length > 1) {
      let currentIndex = 0;
      showcaseSlideTimer = window.setInterval(() => {
        currentIndex = (currentIndex + 1) % paths.length;
        showSlide(currentIndex);
      }, showcaseSlideIntervalMs);
    }
  };

  const activateDemo = async (tab) => {
    const activationId = ++showcaseActivationId;
    const key = tab.dataset.showcaseDemo;
    const demo = demos[key] || demos.policy;
    const imagePaths = imageCandidatesFor(tab);
    tabs.forEach((candidate) => {
      const active = candidate === tab;
      candidate.classList.toggle("is-active", active);
      candidate.setAttribute("aria-selected", String(active));
    });
    kicker.textContent = demo.kicker;
    title.textContent = demo.title;
    description.textContent = demo.description;
    bullets.innerHTML = demo.bullets.map((item) => `<span>${escapeHtml(item)}</span>`).join("");
    restartTransition();
    const loadedImagePaths = await resolveImagePaths(imagePaths);
    if (activationId !== showcaseActivationId) {
      return;
    }
    if (loadedImagePaths.length) {
      renderImages(loadedImagePaths, demo);
    } else {
      clearShowcaseImages();
    }
  };

  tabs.forEach((tab) => {
    tab.addEventListener("click", () => activateDemo(tab));
  });
  activateDemo(tabs.find((tab) => tab.classList.contains("is-active")) || tabs[0]);
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

function renderReportClusterFilter() {
  const select = $("#reportCluster");
  if (!select) {
    return;
  }
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
  const trashMode = Boolean($("#showDeletedClusters")?.checked);
  if (!userClusters.length) {
    container.innerHTML = trashMode
      ? '<p class="muted">휴지통에 클러스터가 없습니다.</p>'
      : '<p class="muted">등록된 클러스터가 없습니다.</p>';
    return;
  }
  container.innerHTML = userClusters
    .map(
      (cluster) => {
        const isDeleted = cluster.status === "deleted";
        return `
        <div class="cluster-row">
          <div class="cluster-row-copy">
            <strong>${escapeHtml(cluster.name || "unknown-cluster")}</strong>
            <p>
              status=${escapeHtml(cluster.status || "active")} ·
              last_seen=${escapeHtml(cluster.last_seen_at || "-")}
              ${isDeleted ? ` · deleted_at=${escapeHtml(cluster.deleted_at || "-")} · 3일 후 자동 영구 삭제` : ""}
            </p>
          </div>
          <div class="cluster-row-actions">
            ${
              isDeleted
                ? `
                  <button class="secondary" data-user-restore="${escapeHtml(cluster.id || "")}">복원</button>
                  <button class="danger" data-user-purge="${escapeHtml(cluster.id || "")}">영구 삭제</button>
                `
                : `
                  <button class="secondary grafana-action-button" data-user-grafana="${escapeHtml(cluster.id || "")}">
                    <span class="devicon--grafana" aria-hidden="true"></span>
                    Grafana
                  </button>
                  <button data-user-rotate="${escapeHtml(cluster.id || "")}">토큰 재발급</button>
                  <button class="danger-icon-button" data-user-delete="${escapeHtml(cluster.id || "")}" aria-label="휴지통으로 이동" title="휴지통으로 이동">
                    <svg viewBox="0 0 24 24" aria-hidden="true">
                      <path d="M3 6h18"></path>
                      <path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                      <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"></path>
                      <path d="M10 11v6"></path>
                      <path d="M14 11v6"></path>
                    </svg>
                  </button>
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

function syncDeletedClusterToggleState() {
  const toggle = $(".cluster-trash-toggle");
  const checkbox = $("#showDeletedClusters");
  if (!toggle || !checkbox) {
    return;
  }
  const trashMode = Boolean(checkbox.checked);
  toggle.classList.toggle("is-trash-mode", trashMode);
  toggle.setAttribute("title", trashMode ? "활성 클러스터 보기" : "휴지통 보기");
  toggle.setAttribute("aria-label", trashMode ? "활성 클러스터 보기" : "휴지통 보기");
}

async function loadUserClusters() {
  renderClusterSetupGate();
  syncDeletedClusterToggleState();
  if (!authState.authenticated) {
    userClusters = [];
    renderRuntimeClusterFilter();
    renderReportClusterFilter();
    renderUserClusters();
    renderSlackClusterToggles();
    renderPolicyApplyPanel();
    return;
  }
  const deletedOnly = $("#showDeletedClusters")?.checked ? "true" : "false";
  const body = await apiJson(`/api/clusters?include_deleted=${deletedOnly}&deleted_only=${deletedOnly}`);
  const clusters = body.clusters || [];
  userClusters = deletedOnly === "true"
    ? clusters.filter((cluster) => cluster.status === "deleted")
    : clusters.filter((cluster) => cluster.status !== "deleted");
  renderRuntimeClusterFilter();
  renderReportClusterFilter();
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
      await refreshDashboardSummary();
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

function ensureAccountDeletionModal() {
  if ($("#accountDeletionModal")) {
    return;
  }
  document.body.insertAdjacentHTML(
    "beforeend",
    `
      <div class="account-deletion-modal" id="accountDeletionModal" hidden>
        <div class="account-deletion-backdrop" data-account-delete-close></div>
      <div class="account-deletion-dialog" role="dialog" aria-modal="true" aria-labelledby="accountDeletionTitle" aria-describedby="accountDeletionDescription">
        <div class="account-deletion-heading">
            <span class="badge error">Danger</span>
            <h2 id="accountDeletionTitle">회원 탈퇴</h2>
          </div>
          <p id="accountDeletionDescription" class="account-deletion-copy">
            탈퇴하면 현재 로그인 세션과 모든 사용자 클러스터 ingest token이 즉시 무효화됩니다.
            Slack 설정과 Grafana 프로비저닝 연결도 삭제되며, 런타임 이벤트·AI 리포트·정책 적용 기록은 감사 목적으로 유지됩니다.
          </p>
          <ul class="account-deletion-list">
            <li>삭제된 계정은 <code>/ui</code>에서 더 이상 표시되지 않습니다.</li>
            <li>관리자는 삭제 상태와 소유 클러스터를 계속 확인할 수 있습니다.</li>
            <li>복구가 필요한 경우 관리자에게 문의해야 합니다.</li>
          </ul>
          <label class="account-deletion-field">
            확인을 위해 이메일을 입력하세요
            <input id="accountDeletionConfirmEmail" type="email" autocomplete="off" placeholder="user@example.com" />
          </label>
          <p class="account-deletion-target" id="accountDeletionTarget">현재 계정: -</p>
          <p class="account-deletion-error" id="accountDeletionError" hidden></p>
          <div class="actions account-deletion-actions">
            <button class="danger" id="confirmAccountDeletion" disabled>회원 탈퇴</button>
            <button class="secondary" id="cancelAccountDeletion" type="button">취소</button>
          </div>
        </div>
      </div>
    `,
  );
}

function updateAccountDeletionModalState() {
  const modal = $("#accountDeletionModal");
  if (!modal || modal.hidden) {
    return;
  }
  const confirmInput = $("#accountDeletionConfirmEmail");
  const confirmButton = $("#confirmAccountDeletion");
  const target = (authState.user?.email || "").trim().toLowerCase();
  const value = (confirmInput?.value || "").trim().toLowerCase();
  if (confirmButton) {
    confirmButton.disabled = !target || value !== target;
  }
  const targetLabel = $("#accountDeletionTarget");
  if (targetLabel) {
    targetLabel.textContent = `현재 계정: ${authState.user?.email || "-"}`;
  }
}

function openAccountDeletionModal() {
  ensureAccountDeletionModal();
  const modal = $("#accountDeletionModal");
  if (!modal || !authState.authenticated) {
    return;
  }
  $("#accountDeletionError").hidden = true;
  $("#accountDeletionError").textContent = "";
  $("#accountDeletionConfirmEmail").value = "";
  modal.hidden = false;
  document.body.classList.add("is-modal-open");
  updateAccountDeletionModalState();
  window.setTimeout(() => {
    $("#accountDeletionConfirmEmail")?.focus();
  }, 0);
}

function closeAccountDeletionModal() {
  const modal = $("#accountDeletionModal");
  if (!modal) {
    return;
  }
  modal.hidden = true;
  document.body.classList.remove("is-modal-open");
  $("#accountDeletionError").hidden = true;
  $("#accountDeletionError").textContent = "";
  $("#accountDeletionConfirmEmail").value = "";
  updateAccountDeletionModalState();
}

async function deleteAccount() {
  if (!authState.authenticated) {
    showToast("로그인 후 사용할 수 있습니다");
    return;
  }
  const confirmEmail = $("#accountDeletionConfirmEmail").value.trim();
  const expectedEmail = (authState.user?.email || "").trim();
  if (!confirmEmail || confirmEmail.toLowerCase() !== expectedEmail.toLowerCase()) {
    $("#accountDeletionError").textContent = "이메일을 정확히 입력해 주세요.";
    $("#accountDeletionError").hidden = false;
    updateAccountDeletionModalState();
    return;
  }
  $("#confirmAccountDeletion").disabled = true;
  $("#confirmAccountDeletion").textContent = "삭제 중...";
  try {
    await apiJson("/api/account/delete", {
      method: "POST",
      body: JSON.stringify({ confirm_email: confirmEmail }),
    });
    sessionStorage.removeItem(SESSION_KEY);
    closeAccountDeletionModal();
    window.location.assign("/ui");
  } finally {
    $("#confirmAccountDeletion").textContent = "회원 탈퇴";
  }
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

async function openClusterGrafana(clusterId) {
  const grafanaWindow = window.open("about:blank", "_blank");
  if (grafanaWindow) {
    grafanaWindow.opener = null;
  }
  const body = await apiJson(`/api/clusters/${encodeURIComponent(clusterId)}/grafana/provision`, {
    method: "POST",
  });
  const url = body.grafana?.url || "";
  if (!url) {
    grafanaWindow?.close();
    showToast("Grafana URL 설정 필요");
    return;
  }
  if (grafanaWindow) {
    grafanaWindow.location.href = url;
  } else {
    window.location.href = url;
  }
  showToast("Grafana 대시보드 준비 완료");
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

async function permanentlyDeleteUserCluster(clusterId) {
  if (!window.confirm("휴지통의 클러스터를 영구 삭제할까요? 관련 런타임 이벤트와 적용 기록도 함께 삭제됩니다.")) {
    return;
  }
  await apiJson(`/api/clusters/${encodeURIComponent(clusterId)}/permanent`, {
    method: "DELETE",
  });
  await loadUserClusters();
  await refreshDashboardSummary();
  showToast("클러스터를 영구 삭제했습니다");
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
    const savedManifest = selectedRuntimeEvent.resource_manifest || "";
    $("#resourceManifest").value = savedManifest;
    renderResourceManifestHelp(selectedRuntimeEvent, !savedManifest);
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
    renderResourceManifestHelp(selectedRuntimeEvent, false);
    showToast("저장된 매니페스트를 불러왔습니다");
  } else if (body.kubectl_command) {
    renderResourceManifestHelp(selectedRuntimeEvent, true);
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
  setReportLoading(true);
  $("#reportResult").innerHTML = `
    <span class="badge loading">loading</span>
    <h2>리포트 생성 중</h2>
    <p>최근 Falco/Gatekeeper 이벤트를 집계하고 LLM 요약을 생성하고 있습니다.</p>
  `;
  try {
    const query = new URLSearchParams({
      cluster: $("#reportCluster")?.value || "",
    });
    const response = await fetch(`/compliance-report?${query.toString()}`, {
      headers: llmHeaders(),
    });
    const report = await response.json();
    if (!response.ok) {
      throw new Error(formatErrorMessage(report.error || report.detail || `HTTP ${response.status}`));
    }
    latestReportText = JSON.stringify(report, null, 2);
    latestReportReadableText = buildReadableReportText(report);
    latestReportRawVisible = false;
    $("#reportResult").innerHTML = `
      <span class="badge ready">JSON report</span>
      <h2>AI 컴플라이언스 리포트</h2>
      ${renderReportScope(report.scope || {})}
      <p>생성 날짜: ${escapeHtml(formatSeoulDateTime(report.generated_at))}</p>
      ${renderReportSummary(report.summary || {})}
      ${renderReportTopRules(report.top_rules || [])}
      ${renderReportBlastRadius(report.blast_radius || [])}
      ${renderReportTimeline(report.timeline || [])}
      ${renderReportRecommendations(report.recommendations || [])}
      ${renderReportNextActions(report.next_actions || [])}
      <div class="analysis-code-block report-terminal-window report-json-block" id="reportRawJsonBlock" hidden>
        <pre><code>${escapeHtml(latestReportText)}</code></pre>
      </div>
    `;
    latestReportHtml = $("#reportResult").innerHTML;
    $("#toggleReportJson").textContent = "원문 JSON 보기";
  } finally {
    setReportLoading(false);
  }
}

function renderReportScope(scope) {
  const label = scope.label || (scope.cluster ? scope.cluster : "전체 클러스터");
  return `<p class="report-scope">Scope: ${escapeHtml(label)}</p>`;
}

function renderReportSummary(summary) {
  const stats = [
    ["총 위반", formatNumber(summary.total_violations), "건"],
    ["심각도", summary.severity || "Low", ""],
    ["영향 클러스터", formatNumber(summary.affected_clusters), "개"],
    ["영향 네임스페이스", formatNumber(summary.affected_namespaces), "개"],
    ["영향 Pod", formatNumber(summary.affected_pods), "개"],
  ];
  return `
    <section class="report-section">
      <div class="report-stat-grid">
        ${stats
          .map(
            ([label, value, suffix]) => `
              <div class="report-stat">
                <span>${escapeHtml(label)}</span>
                <strong>${escapeHtml(value)}${suffix ? `<small>${escapeHtml(suffix)}</small>` : ""}</strong>
              </div>
            `,
          )
          .join("")}
      </div>
      <p class="report-summary-text">${escapeHtml(summary.description || "요약 정보가 없습니다.")}</p>
    </section>
  `;
}

function renderReportTopRules(topRules) {
  const maxCount = Math.max(1, ...topRules.map((item) => Number(item.count || 0)));
  const rows = topRules
    .map((item) => {
      const count = Number(item.count || 0);
      const width = Math.max(8, Math.round((count / maxCount) * 100));
      return `
        <li class="report-rule-row">
          <span class="report-rule-name">${escapeHtml(item.rule || "알 수 없는 rule")}</span>
          <span class="report-rule-count">${escapeHtml(formatNumber(count))}건</span>
          <span class="report-rule-bar" aria-hidden="true"><span style="width: ${width}%"></span></span>
          <span class="report-severity ${reportSeverityClass(item.severity)}">${escapeHtml(item.severity || "Low")}</span>
        </li>
      `;
    })
    .join("");
  return `
    <section class="report-section">
      <h3>상위 위반 Rule</h3>
      <ul class="report-rule-list">${rows || "<li>수집된 rule 없음</li>"}</ul>
    </section>
  `;
}

function renderReportBlastRadius(items) {
  const rows = items
    .map(
      (item) => `
        <tr>
          <td>${escapeHtml(item.cluster || "-")}</td>
          <td>${escapeHtml(item.namespace || "-")}</td>
          <td>${escapeHtml(item.pod || "-")}</td>
          <td>${escapeHtml(item.rule || "-")}</td>
          <td>${escapeHtml(formatSeoulDateTime(item.time))}</td>
        </tr>
      `,
    )
    .join("");
  return `
    <section class="report-section">
      <h3>영향 범위</h3>
      <div class="report-table-wrap">
        <table class="report-table">
          <thead>
            <tr><th>Cluster</th><th>Namespace</th><th>Pod</th><th>Rule</th><th>Time</th></tr>
          </thead>
          <tbody>${rows || '<tr><td colspan="5">영향 범위 데이터 없음</td></tr>'}</tbody>
        </table>
      </div>
    </section>
  `;
}

function renderReportTimeline(timeline) {
  const maxCount = Math.max(1, ...timeline.map((item) => Number(item.count || 0)));
  const bars = timeline
    .map((item) => {
      const count = Number(item.count || 0);
      const height = Math.max(10, Math.round((count / maxCount) * 88));
      return `
        <li class="report-timeline-item">
          <span class="report-timeline-count">${escapeHtml(formatNumber(count))}</span>
          <span class="report-timeline-bar" style="height: ${height}px" aria-hidden="true"></span>
          <span class="report-timeline-hour">${escapeHtml(item.hour || "-")}</span>
        </li>
      `;
    })
    .join("");
  return `
    <section class="report-section">
      <h3>24시간 타임라인</h3>
      <ul class="report-timeline">${bars || "<li>타임라인 데이터 없음</li>"}</ul>
    </section>
  `;
}

function renderReportRecommendations(recommendations) {
  const items = recommendations.map((item) => `<li>${escapeHtml(item)}</li>`).join("");
  return `
    <section class="report-section">
      <h3>권장 조치</h3>
      <div class="analysis-code-block report-terminal-window">
        <ul>${items || "<li>권장 조치 없음</li>"}</ul>
      </div>
    </section>
  `;
}

function renderReportNextActions(actions) {
  const buttons = actions
    .map(
      (item) => `
        <button class="secondary report-next-action" type="button" data-report-action="${escapeHtml(item.target || "")}">
          ${escapeHtml(item.label || "확인하기")} →
        </button>
      `,
    )
    .join("");
  return `
    <section class="report-section report-next-actions">
      <h3>Next Action</h3>
      <div>${buttons || "<p>연결할 작업 없음</p>"}</div>
    </section>
  `;
}

function reportSeverityClass(value) {
  return `is-${String(value || "low").toLowerCase()}`;
}

function formatNumber(value) {
  return Number(value || 0).toLocaleString("ko-KR");
}

function buildReadableReportText(report) {
  const summary = report.summary || {};
  const topRules = (report.top_rules || [])
    .map((item) => `- ${item.rule}: ${item.count}건 (${item.severity})`)
    .join("\n") || "- 수집된 rule 없음";
  const blastRadius = (report.blast_radius || [])
    .map((item) => `- ${item.cluster || "-"} / ${item.namespace || "-"} / ${item.pod || "-"} / ${item.rule || "-"} / ${formatSeoulDateTime(item.time)}`)
    .join("\n") || "- 영향 범위 데이터 없음";
  const timeline = (report.timeline || [])
    .map((item) => `- ${item.hour}: ${item.count}건`)
    .join("\n") || "- 타임라인 데이터 없음";
  const recommendations = (report.recommendations || [])
    .map((item) => `- ${item}`)
    .join("\n") || "- 권장 조치 없음";
  const nextActions = (report.next_actions || [])
    .map((item) => `- ${item.label} (${item.target})`)
    .join("\n") || "- 연결할 작업 없음";
  return [
    "AI 컴플라이언스 리포트",
    `생성 날짜: ${formatSeoulDateTime(report.generated_at)}`,
    "",
    "요약",
    `총 위반: ${formatNumber(summary.total_violations)}건`,
    `심각도: ${summary.severity || "Low"}`,
    `영향 클러스터: ${formatNumber(summary.affected_clusters)}개`,
    `영향 네임스페이스: ${formatNumber(summary.affected_namespaces)}개`,
    `영향 Pod: ${formatNumber(summary.affected_pods)}개`,
    summary.description || "요약 정보 없음",
    "",
    "상위 위반 Rule",
    topRules,
    "",
    "영향 범위",
    blastRadius,
    "",
    "타임라인",
    timeline,
    "",
    "권장 조치",
    recommendations,
    "",
    "Next Action",
    nextActions,
  ].join("\n");
}

function toggleReportRawJson() {
  const block = $("#reportRawJsonBlock");
  if (!block || !latestReportText) {
    showToast("먼저 리포트를 생성해 주세요");
    return;
  }
  latestReportRawVisible = !latestReportRawVisible;
  block.hidden = !latestReportRawVisible;
  $("#toggleReportJson").textContent = latestReportRawVisible ? "원문 JSON 숨기기" : "원문 JSON 보기";
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
    const tabName = tab.dataset.tab;
    if (!authState.authenticated && isAuthRequiredTab(tabName)) {
      showToast("로그인 후 이용할 수 있습니다");
      $("#loginLink")?.focus({ preventScroll: true });
      return;
    }
    activateTab(tabName);
    $(".sidebar")?.classList.remove("is-open");
    $("#navMenuToggle")?.setAttribute("aria-expanded", "false");
  });
});

ensureSlackSettingsPanel();
ensureAccountDeletionModal();
ensurePolicyApplyPanel();

$("#generatePolicy").addEventListener("click", () => {
  generatePolicy().catch((error) => {
    showInlineAlert(error.message);
    showToast(error.message);
  });
});

document.addEventListener("click", (event) => {
  const reportAction = event.target.closest("[data-report-action]");
  if (!reportAction) {
    return;
  }
  handleReportNextAction(reportAction.dataset.reportAction);
});

function handleReportNextAction(target) {
  if (target === "violation_detail") {
    activateTab("analysis");
    showToast("Violation Detail로 이동했습니다");
    return;
  }
  if (target === "policy_generator") {
    activateTab("policy");
    showToast("Policy Generator로 이동했습니다");
    return;
  }
  if (target === "grafana") {
    activateTab("setup");
    $("#clusterSetupContent")?.scrollIntoView({ behavior: "smooth", block: "start" });
    showToast("Cluster Setup으로 이동했습니다");
  }
}

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
  copyText(target?.innerText || target?.textContent || "")
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

$("#toggleRuntimeEvents").addEventListener("click", () => {
  const nextCollapsed = !runtimeEventsCollapsed;
  setRuntimeEventsCollapsed(nextCollapsed);
  if (!nextCollapsed) {
    refreshRuntimeEvents().catch((error) => {
      showInlineAlert(error.message);
      showToast("위반 목록 로드 실패");
    });
  }
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
  syncDeletedClusterToggleState();
  loadUserClusters().catch((error) => {
    showInlineAlert(error.message);
    showToast("클러스터 목록 로드 실패");
  });
});

$("#userClusters").addEventListener("click", (event) => {
  const rotateButton = event.target.closest("[data-user-rotate]");
  const grafanaButton = event.target.closest("[data-user-grafana]");
  const deleteButton = event.target.closest("[data-user-delete]");
  const restoreButton = event.target.closest("[data-user-restore]");
  const purgeButton = event.target.closest("[data-user-purge]");
  if (rotateButton) {
    rotateUserClusterToken(rotateButton.dataset.userRotate).catch((error) => {
      showInlineAlert(error.message);
      showToast("토큰 재발급 실패");
    });
    return;
  }
  if (grafanaButton) {
    openClusterGrafana(grafanaButton.dataset.userGrafana).catch((error) => {
      showInlineAlert(error.message);
      showToast("Grafana 준비 실패");
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
  if (purgeButton) {
    permanentlyDeleteUserCluster(purgeButton.dataset.userPurge).catch((error) => {
      showInlineAlert(error.message);
      showToast("클러스터 영구 삭제 실패");
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

$("#accountDeleteButton").addEventListener("click", () => {
  openAccountDeletionModal();
});

$("#cancelAccountDeletion").addEventListener("click", () => {
  closeAccountDeletionModal();
});

$("#accountDeletionConfirmEmail").addEventListener("input", () => {
  updateAccountDeletionModalState();
});

$("#confirmAccountDeletion").addEventListener("click", () => {
  deleteAccount().catch((error) => {
    $("#accountDeletionError").textContent = error.message;
    $("#accountDeletionError").hidden = false;
    updateAccountDeletionModalState();
    showToast("회원 탈퇴 실패");
  });
});

$("#accountDeletionModal").addEventListener("click", (event) => {
  if (event.target.closest("[data-account-delete-close]")) {
    closeAccountDeletionModal();
  }
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !$("#accountDeletionModal").hidden) {
    closeAccountDeletionModal();
  }
});

["#runtimeCluster", "#runtimeSource"].forEach((selector) => {
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
  copyText(latestReportReadableText || latestReportText).catch((error) => showToast(error.message));
});

$("#toggleReportJson").addEventListener("click", () => {
  toggleReportRawJson();
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

$("#applyLlmApiKey").addEventListener("click", () => {
  const apiKey = sanitizeApiKey($("#llmApiKey").value);
  if (!$("#useOwnApiKey").checked) {
    $("#useOwnApiKey").checked = true;
    $("#byokFields").hidden = false;
  }
  if (!apiKey) {
    sessionStorage.removeItem(SESSION_KEY);
    showInlineAlert("API key를 입력한 뒤 적용해 주세요.");
    showToast("API key 적용 실패");
    return;
  }
  if (!isSecureContextForKey()) {
    sessionStorage.removeItem(SESSION_KEY);
    showInlineAlert("HTTPS 연결에서만 사용자 API key를 전송할 수 있습니다.");
    showToast("API key 적용 실패");
    return;
  }
  sessionStorage.setItem(SESSION_KEY, apiKey);
  $("#llmApiKey").value = apiKey;
  clearInlineAlert();
  showToast("API key가 적용되었습니다");
});

$("#clearLlmApiKey").addEventListener("click", () => {
  sessionStorage.removeItem(SESSION_KEY);
  $("#llmApiKey").value = "";
  clearInlineAlert();
  showToast("API key를 초기화했습니다");
});

$("#llmApiKey").addEventListener("input", () => {
  const value = sanitizeApiKey($("#llmApiKey").value);
  if ($("#llmApiKey").value !== value) {
    $("#llmApiKey").value = value;
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

$("#themeToggle").addEventListener("click", () => {
  toggleTheme();
});

$("#sidebarHomeButton")?.addEventListener("click", () => {
  showLandingHome();
  $(".sidebar")?.classList.remove("is-open");
  $("#navMenuToggle")?.setAttribute("aria-expanded", "false");
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
  if (authState.authenticated) {
    activateTab("dashboard");
    $("#dashboardPanel")?.scrollIntoView({ behavior: "smooth", block: "start" });
    return;
  }
  activateTab("policy");
  $("#policyPanel")?.scrollIntoView({ behavior: "smooth", block: "start" });
}

$("#landingPolicyButton").addEventListener("click", () => {
  openPublicPolicyGenerator();
});

setupShowcaseDemo();
setupLandingScrollAnimation();

async function loadConfig() {
  const response = await fetch("/config");
  const config = await response.json();
  void config;
}

async function loadAuthStatus() {
  const response = await fetch("/me");
  authState = await response.json();
  renderAuthStatus();
}

function lastAuthEmail() {
  return (localStorage.getItem(LAST_AUTH_EMAIL_KEY) || "").trim().toLowerCase();
}

function updateLoginLinks() {
  const hint = lastAuthEmail();
  const quickHref = hint ? `/auth/google/login?login_hint=${encodeURIComponent(hint)}` : "/auth/google/login";
  const loginLink = $("#loginLink");
  const landingLoginLink = $("#landingLoginLink");
  if (loginLink) {
    loginLink.href = quickHref;
  }
  if (landingLoginLink) {
    landingLoginLink.href = "/auth/google/login?select_account=true";
  }
}

function renderAuthStatus() {
  const status = $("#authStatus");
  const loginLink = $("#loginLink");
  const accountDeleteButton = $("#accountDeleteButton");
  const logoutButton = $("#logoutButton");
  document.body.classList.toggle("logged-out", !authState.authenticated);
  document.body.classList.toggle("logged-in", Boolean(authState.authenticated));
  if (authState.authenticated) {
    status.textContent = authState.user?.email || "로그인됨";
    if (authState.user?.email) {
      localStorage.setItem(LAST_AUTH_EMAIL_KEY, authState.user.email.trim().toLowerCase());
    }
    updateLoginLinks();
    status.hidden = false;
    loginLink.hidden = true;
    accountDeleteButton.hidden = false;
    logoutButton.hidden = false;
    renderAuthGates();
    return;
  }
  updateLoginLinks();
  status.hidden = true;
  loginLink.hidden = false;
  accountDeleteButton.hidden = true;
  logoutButton.hidden = true;
  renderAuthGates();
}

async function logout() {
  const previousEmail = authState.user?.email || "";
  const response = await fetch("/logout", { method: "POST" });
  if (!response.ok) {
    throw new Error(await response.text());
  }
  if (previousEmail) {
    localStorage.setItem(LAST_AUTH_EMAIL_KEY, previousEmail.trim().toLowerCase());
  }
  closeAccountDeletionModal();
  authState = { authenticated: false, user: null, auth: authState.auth };
  userClusters = [];
  slackSettings = { webhook_url: "", configured: false };
  renderAuthStatus();
  renderUserClusters();
  renderSlackSettings();
  renderPolicyApplyPanel();
  renderDashboardSummary({});
  renderUserObservability({});
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
renderResourceManifestHelp();
setRuntimeEventsCollapsed(false);
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
