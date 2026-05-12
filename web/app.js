const dropzone = document.getElementById("dropzone");
const fileInput = document.getElementById("fileInput");
const browseButton = document.getElementById("browseButton");
const analyzeButton = document.getElementById("analyzeButton");
const selectedFile = document.getElementById("selectedFile");
const statusNode = document.getElementById("status");
const results = document.getElementById("results");
const riskScore = document.getElementById("riskScore");
const riskLevel = document.getElementById("riskLevel");
const summaryStats = document.getElementById("summaryStats");
const findingsList = document.getElementById("findingsList");
const recommendationsList = document.getElementById("recommendationsList");
const mermaidSource = document.getElementById("mermaidSource");
const graphRender = document.getElementById("graphRender");
const componentsTable = document.getElementById("componentsTable");

let currentFile = null;
let mermaidApi = null;

browseButton.addEventListener("click", () => fileInput.click());
analyzeButton.addEventListener("click", analyzeCurrentFile);
fileInput.addEventListener("change", (event) => {
  const [file] = event.target.files;
  setCurrentFile(file ?? null);
});

dropzone.addEventListener("dragover", (event) => {
  event.preventDefault();
  dropzone.classList.add("dragover");
});

dropzone.addEventListener("dragleave", () => {
  dropzone.classList.remove("dragover");
});

dropzone.addEventListener("drop", (event) => {
  event.preventDefault();
  dropzone.classList.remove("dragover");
  const [file] = event.dataTransfer.files;
  setCurrentFile(file ?? null);
});

dropzone.addEventListener("keydown", (event) => {
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    fileInput.click();
  }
});

async function analyzeCurrentFile() {
  if (!currentFile) {
    updateStatus("Select an APK or manifest first.", true);
    return;
  }

  analyzeButton.disabled = true;
  updateStatus(`Analyzing ${currentFile.name}...`);

  try {
    const bytes = await currentFile.arrayBuffer();
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: {
        "Content-Type": "application/octet-stream",
        "X-Filename": currentFile.name
      },
      body: bytes
    });

    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || "Analysis failed");
    }

    renderReport(payload.report);
    updateStatus(`Report generated for ${payload.fileName}.`);
  } catch (error) {
    updateStatus(error.message || "Unexpected error during analysis.", true);
  } finally {
    analyzeButton.disabled = false;
  }
}

function setCurrentFile(file) {
  currentFile = file;
  selectedFile.textContent = file
    ? `${file.name} - ${(file.size / 1024 / 1024).toFixed(2)} MB`
    : "No file selected yet.";
  analyzeButton.disabled = !file;
  if (file) {
    updateStatus("File ready. Launch analysis when you want.");
  }
}

function renderReport(report) {
  results.classList.remove("hidden");
  riskScore.textContent = report.riskScore;
  riskLevel.textContent = report.riskLevel;
  riskLevel.className = `metric-chip ${chipClass(report.riskLevel)}`;
  mermaidSource.textContent = report.mermaid;

  renderSummary(report);
  renderFindings(report.findings);
  renderRecommendations(report.recommendations);
  renderComponents(report.components);
  renderGraph(report.mermaid);
}

function renderSummary(report) {
  const exportedCount = report.components.filter((component) => component.exported).length;
  const deepLinkCount = report.components.reduce((count, component) => {
    return count + component.intentFilters.reduce((inner, filter) => {
      return inner + filter.dataSpecs.filter((spec) => spec.scheme || spec.host || spec.mimeType).length;
    }, 0);
  }, 0);

  const highSeverity = report.findings.filter((finding) => finding.severity === "HIGH" || finding.severity === "CRITICAL").length;

  summaryStats.innerHTML = "";
  summaryStats.append(
    statBox(String(exportedCount), "exported components"),
    statBox(String(deepLinkCount), "deep links"),
    statBox(String(highSeverity), "high-severity findings")
  );
}

function renderFindings(findings) {
  findingsList.innerHTML = "";
  if (!findings.length) {
    findingsList.innerHTML = "<p>No high-signal attack surface issue was flagged from this file.</p>";
    return;
  }

  for (const finding of findings) {
    const article = document.createElement("article");
    article.className = `finding ${finding.severity.toLowerCase()}`;
    article.innerHTML = `
      <span class="severity">${escapeHtml(finding.severity)}</span>
      <h3>${escapeHtml(finding.title)}</h3>
      <p><strong>Why risky:</strong> ${escapeHtml(finding.whyRisky)}</p>
      <p><strong>How to fix:</strong> ${escapeHtml(finding.remediation)}</p>
    `;
    findingsList.append(article);
  }
}

function renderRecommendations(recommendations) {
  recommendationsList.innerHTML = "";
  for (const recommendation of recommendations) {
    const item = document.createElement("li");
    item.textContent = recommendation;
    recommendationsList.append(item);
  }
}

function renderComponents(components) {
  componentsTable.innerHTML = "";
  for (const component of components) {
    const row = document.createElement("tr");
    const permission = component.permission || component.readPermission || component.writePermission || "None";
    const intentSummary = summarizeIntentFilters(component.intentFilters);
    row.innerHTML = `
      <td>${escapeHtml(component.type)}</td>
      <td><code>${escapeHtml(component.name)}</code></td>
      <td>${component.exported ? "Yes" : "No"}</td>
      <td><code>${escapeHtml(permission)}</code></td>
      <td><code>${escapeHtml(intentSummary)}</code></td>
    `;
    componentsTable.append(row);
  }
}

function summarizeIntentFilters(intentFilters) {
  if (!intentFilters.length) {
    return "No intent filters";
  }
  return intentFilters.map((filter) => {
    const actions = filter.actions.join(", ");
    const data = filter.dataSpecs.map((spec) => {
      return [spec.scheme && `${spec.scheme}://`, spec.host, spec.path || spec.pathPrefix || spec.pathPattern, spec.mimeType && `(${spec.mimeType})`]
        .filter(Boolean)
        .join("");
    }).join(", ");
    return [actions, data].filter(Boolean).join(" | ");
  }).join(" ; ");
}

async function renderGraph(mermaidText) {
  graphRender.textContent = "Rendering graph...";
  try {
    const mermaid = await loadMermaid();
    const graphId = `graph-${Date.now()}`;
    const { svg } = await mermaid.render(graphId, mermaidText);
    graphRender.innerHTML = svg;
    const svgNode = graphRender.querySelector("svg");
    if (svgNode) {
      svgNode.removeAttribute("width");
      svgNode.removeAttribute("height");
      svgNode.style.width = "max-content";
      svgNode.style.minWidth = "100%";
      svgNode.style.height = "auto";
      svgNode.style.display = "block";
    }
  } catch (error) {
    graphRender.innerHTML = `
      <p>Rendered Mermaid preview is unavailable in this browser session.</p>
      <p>The Mermaid source is still shown on the right and can be reused directly.</p>
    `;
  }
}

async function loadMermaid() {
  if (mermaidApi) {
    return mermaidApi;
  }
  const module = await import("https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs");
  module.default.initialize({
    startOnLoad: false,
    securityLevel: "loose",
    theme: "base",
    flowchart: {
      useMaxWidth: false,
      htmlLabels: true,
      nodeSpacing: 34,
      rankSpacing: 54,
      curve: "basis"
    },
    themeVariables: {
      primaryColor: "#ffe9db",
      primaryTextColor: "#1d2430",
      primaryBorderColor: "#d95d39",
      lineColor: "#8f4e3b",
      secondaryColor: "#fff6eb",
      tertiaryColor: "#f7ecdf"
    }
  });
  mermaidApi = module.default;
  return mermaidApi;
}

function statBox(value, label) {
  const node = document.createElement("div");
  node.className = "stat-box";
  node.innerHTML = `<strong>${escapeHtml(value)}</strong><span>${escapeHtml(label)}</span>`;
  return node;
}

function updateStatus(message, isError = false) {
  statusNode.textContent = message;
  statusNode.style.color = isError ? "#b42318" : "";
}

function chipClass(level) {
  if (level === "HIGH" || level === "CRITICAL") {
    return "metric-chip-high";
  }
  if (level === "MEDIUM") {
    return "metric-chip-medium";
  }
  return "metric-chip-low";
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")
    .replaceAll("'", "&#39;");
}
