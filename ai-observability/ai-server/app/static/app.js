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
  $("#templateOutput").textContent = result.constraint_template;
  $("#constraintOutput").textContent = result.constraint;
  $("#regoOutput").textContent = result.rego;
  $("#llmOutput").textContent = result.llm_review || "LLM 검토 미사용 또는 설정 없음";
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
  const payload = JSON.parse($("#eventPayload").value);
  const result = await postJson("/analyze-violation", payload);
  const actions = result.recommended_actions.map((item) => `<li>${item}</li>`).join("");
  $("#analysisResult").innerHTML = `
    <span class="badge ${result.severity}">${result.severity}</span>
    <h2>${result.summary}</h2>
    <p>confidence: ${result.confidence}</p>
    <p>${result.reason}</p>
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
  analyzeViolation().catch((error) => showToast(error.message));
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
