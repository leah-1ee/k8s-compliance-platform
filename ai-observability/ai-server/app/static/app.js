const $ = (selector) => document.querySelector(selector);

let latestPolicyText = "";
let latestAnalysisText = "";
let latestYamlSnippet = "";
let grafanaUrl = "";
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
    const actions = result.recommended_actions
      .map((item) => `<li>${escapeHtml(item)}</li>`)
      .join("");
    latestYamlSnippet = result.yaml_snippet || "";
    $("#analysisResult").innerHTML = `
      <div class="analysis-meta">
        <span class="badge ${result.severity}">${escapeHtml(result.severity)}</span>
        <span class="badge ${result.llm_used ? "ready" : "loading"}">${result.llm_used ? "LLM 분석" : "기본 분석"}</span>
      </div>
      <h2>${escapeHtml(result.summary)}</h2>
      <p>confidence: ${escapeHtml(result.confidence)}</p>
      <p>${escapeHtml(result.reason)}</p>
      <h3>원인 설명</h3>
      <p>${escapeHtml(result.root_cause)}</p>
      <h3>수정 방법</h3>
      <p>${escapeHtml(result.remediation)}</p>
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
        <pre><code id="analysisYamlOutput">${escapeHtml(latestYamlSnippet)}</code></pre>
      </div>
      ${result.llm_error ? `<p>${escapeHtml(result.llm_error)}</p>` : ""}
      <ul>${actions}</ul>
    `;
    latestAnalysisText = JSON.stringify(result, null, 2);
    showToast("분석 완료");
  } finally {
    setAnalysisLoading(false);
  }
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
loadConfig().catch(() => showToast("설정 로드 실패"));
