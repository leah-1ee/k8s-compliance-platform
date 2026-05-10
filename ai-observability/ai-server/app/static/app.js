const $ = (selector) => document.querySelector(selector);

let latestPolicyText = "";
let latestAnalysisText = "";
let grafanaUrl = "";
const SESSION_KEY = "complianceAiLlmApiKey";

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
      message = body.error || body.detail || message;
    } catch (error) {
      // 오류 본문 원문 사용
    }
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }
  return response.json();
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

async function generatePolicy() {
  clearInlineAlert();
  const useLlm = $("#useLlm").checked;
  setPolicyLoading(true);
  const payload = {
    prompt: $("#policyPrompt").value,
    policy_kind: $("#policyKind").value || null,
    constraint_name: $("#constraintName").value,
    enforcement_action: $("#enforcementAction").value,
    allowed_registries: splitList($("#allowedRegistries").value),
    excluded_namespaces: splitList($("#excludedNamespaces").value),
    use_llm: useLlm,
  };
  try {
    const result = await postJson("/generate-policy", payload);
    const llmText = result.llm_review || result.llm_error || "LLM 검토 미사용";
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

async function analyzeViolation() {
  clearInlineAlert();
  setAnalysisState("loading", "분석 처리 중", "이벤트 JSON을 분석하고 있습니다.");
  let payload;
  try {
    payload = JSON.parse($("#eventPayload").value);
  } catch (error) {
    setAnalysisState("error", "JSON 형식 오류", error.message);
    throw error;
  }
  const result = await postJson("/analyze-violation", payload);
  const actions = result.recommended_actions
    .map((item) => `<li>${escapeHtml(item)}</li>`)
    .join("");
  $("#analysisResult").innerHTML = `
    <span class="badge ${result.severity}">${escapeHtml(result.severity)}</span>
    <h2>${escapeHtml(result.summary)}</h2>
    <p>confidence: ${escapeHtml(result.confidence)}</p>
    <p>${escapeHtml(result.reason)}</p>
    <ul>${actions}</ul>
  `;
  latestAnalysisText = JSON.stringify(result, null, 2);
  showToast("분석 완료");
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
}

initLlmKeyPanel();
loadConfig().catch(() => showToast("설정 로드 실패"));
