const $ = (selector) => document.querySelector(selector);

let latestPolicyText = "";
let latestAnalysisText = "";
let grafanaUrl = "";

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

async function postJson(path, payload) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `HTTP ${response.status}`);
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

async function generatePolicy() {
  const payload = {
    prompt: $("#policyPrompt").value,
    policy_kind: $("#policyKind").value || null,
    constraint_name: $("#constraintName").value,
    enforcement_action: $("#enforcementAction").value,
    allowed_registries: splitList($("#allowedRegistries").value),
    excluded_namespaces: splitList($("#excludedNamespaces").value),
    use_llm: $("#useLlm").checked,
  };
  const result = await postJson("/generate-policy", payload);
  setOutput(
    "#templateOutput",
    result.constraint_template || "Mutation 정책은 ConstraintTemplate을 사용하지 않습니다.",
  );
  setOutput("#constraintOutput", result.constraint);
  setOutput("#regoOutput", result.rego || "Mutation 정책은 Rego를 사용하지 않습니다.");
  setOutput("#llmOutput", result.llm_review || "LLM 검토 미사용 또는 설정 없음");
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
    result.llm_review || "N/A",
  ].join("\n");
  showToast("정책 생성 완료");
}

async function analyzeViolation() {
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

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => activateTab(tab.dataset.tab));
});

$("#generatePolicy").addEventListener("click", () => {
  generatePolicy().catch((error) => showToast(error.message));
});

$("#analyzeViolation").addEventListener("click", () => {
  analyzeViolation().catch((error) => {
    if (!$("#analysisResult .badge.error")) {
      setAnalysisState("error", "분석 실패", error.message);
    }
    showToast(error.message);
  });
});

$("#copyPolicy").addEventListener("click", () => {
  copyText(latestPolicyText).catch((error) => showToast(error.message));
});

$("#copyAnalysis").addEventListener("click", () => {
  copyText(latestAnalysisText).catch((error) => showToast(error.message));
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

loadConfig().catch(() => showToast("설정 로드 실패"));
