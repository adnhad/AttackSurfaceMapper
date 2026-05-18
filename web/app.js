const STORAGE_KEY = "asm-last-report";

const page = document.body.dataset.page;

const common = {
  artifactBadge: document.getElementById("artifactBadge"),
  emptyState: document.getElementById("emptyState"),
  results: document.getElementById("results")
};

document.addEventListener("DOMContentLoaded", () => {
  if (page === "overview") {
    initOverviewPage();
  } else if (page === "components") {
    initComponentsPage();
  } else if (page === "graph") {
    initGraphPage();
  } else if (page === "findings") {
    initFindingsPage();
  } else if (page === "recommendations") {
    initRecommendationsPage();
  }
});

function initOverviewPage() {
  const dropzone = document.getElementById("dropzone");
  const fileInput = document.getElementById("fileInput");
  const browseButton = document.getElementById("browseButton");
  const analyzeButton = document.getElementById("analyzeButton");
  const selectedFile = document.getElementById("selectedFile");
  const statusNode = document.getElementById("status");
  const packageName = document.getElementById("packageName");
  const artifactSource = document.getElementById("artifactSource");
  const backupFlag = document.getElementById("backupFlag");
  const debuggableFlag = document.getElementById("debuggableFlag");
  const fullBackupFlag = document.getElementById("fullBackupFlag");
  const permissionsChips = document.getElementById("permissionsChips");
  const riskScore = document.getElementById("riskScore");
  const riskLevel = document.getElementById("riskLevel");
  const severityBreakdown = document.getElementById("severityBreakdown");
  const summaryStats = document.getElementById("summaryStats");
  const leadInsight = document.getElementById("leadInsight");

  let currentFile = null;

  browseButton.addEventListener("click", () => fileInput.click());
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

  analyzeButton.addEventListener("click", async () => {
    if (!currentFile) {
      updateStatus(statusNode, "Select an APK or manifest first.", true);
      return;
    }

    analyzeButton.disabled = true;
    updateStatus(statusNode, `Analyzing ${currentFile.name}...`);

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

      savePayload(payload);
      renderArtifactBadge(payload);
      renderOverview(payload.fileName, payload.report, {
        packageName,
        artifactSource,
        backupFlag,
        debuggableFlag,
        fullBackupFlag,
        permissionsChips,
        riskScore,
        riskLevel,
        severityBreakdown,
        summaryStats,
        leadInsight
      });
      showResults(true);
      updateStatus(statusNode, `Report generated for ${payload.fileName}.`);
    } catch (error) {
      updateStatus(statusNode, error.message || "Unexpected error during analysis.", true);
    } finally {
      analyzeButton.disabled = false;
    }
  });

  const stored = loadPayload();
  renderArtifactBadge(stored);
  if (stored?.report) {
    renderOverview(stored.fileName, stored.report, {
      packageName,
      artifactSource,
      backupFlag,
      debuggableFlag,
      fullBackupFlag,
      permissionsChips,
      riskScore,
      riskLevel,
      severityBreakdown,
      summaryStats,
      leadInsight
    });
    showResults(true);
  } else {
    showResults(false);
  }

  function setCurrentFile(file) {
    currentFile = file;
    selectedFile.textContent = file
      ? `${file.name} - ${(file.size / 1024 / 1024).toFixed(2)} MB`
      : "No file selected yet.";
    analyzeButton.disabled = !file;
    if (file) {
      updateStatus(statusNode, "File ready. Launch analysis when you want.");
    }
  }
}

function initComponentsPage() {
  const componentSearch = document.getElementById("componentSearch");
  const componentFilter = document.getElementById("componentFilter");
  const componentCards = document.getElementById("componentCards");
  const componentsTable = document.getElementById("componentsTable");

  const stored = loadPayload();
  renderArtifactBadge(stored);
  if (!stored?.report) {
    showResults(false);
    return;
  }

  showResults(true);
  componentSearch.addEventListener("input", render);
  componentFilter.addEventListener("change", render);
  render();

  function render() {
    const report = stored.report;
    const searchValue = componentSearch.value.trim().toLowerCase();
    const filterValue = componentFilter.value;
    const filtered = report.components.filter((component) => {
      const haystack = `${component.type} ${component.name} ${component.permission} ${component.readPermission} ${component.writePermission}`.toLowerCase();
      if (searchValue && !haystack.includes(searchValue)) {
        return false;
      }
      if (filterValue === "EXPORTED" && !component.exported) {
        return false;
      }
      if (filterValue === "UNPROTECTED" && (!component.exported || hasPermission(component))) {
        return false;
      }
      if (filterValue === "DEEPLINK" && !hasDeepLink(component)) {
        return false;
      }
      return true;
    });

    componentCards.innerHTML = "";
    componentsTable.innerHTML = "";

    if (!filtered.length) {
      componentCards.innerHTML = "<p class=\"muted-copy\">No component matches the current filter.</p>";
      return;
    }

    for (const component of filtered) {
      const article = document.createElement("article");
      article.className = `component-card ${component.exported ? "exported" : "private"}`;
      article.innerHTML = `
        <div class="component-card-head">
          <span class="component-type">${escapeHtml(component.type.replaceAll("_", " "))}</span>
          <span class="component-state ${component.exported ? "exported" : "private"}">${component.exported ? "exported" : "private"}</span>
        </div>
        <h3>${escapeHtml(component.name)}</h3>
        <p class="component-meta">${escapeHtml(component.permission || component.readPermission || component.writePermission || "No permission gate declared")}</p>
        <div class="component-badges">
          ${component.intentFilters.length ? `<span class="mini-badge">${component.intentFilters.length} intent filter(s)</span>` : ""}
          ${hasDeepLink(component) ? "<span class=\"mini-badge warning\">deep link</span>" : ""}
          ${component.grantUriPermissions ? "<span class=\"mini-badge warning\">URI grants</span>" : ""}
        </div>
        <p class="component-summary">${escapeHtml(summarizeIntentFilters(component.intentFilters))}</p>
      `;
      componentCards.append(article);

      const row = document.createElement("tr");
      row.innerHTML = `
        <td>${escapeHtml(component.type)}</td>
        <td><code>${escapeHtml(component.name)}</code></td>
        <td>${component.exported ? "Yes" : "No"}</td>
        <td><code>${escapeHtml(component.permission || component.readPermission || component.writePermission || "None")}</code></td>
        <td><code>${escapeHtml(summarizeIntentFilters(component.intentFilters))}</code></td>
      `;
      componentsTable.append(row);
    }
  }
}

function initGraphPage() {
  const graphRender = document.getElementById("graphRender");
  const mermaidSource = document.getElementById("mermaidSource");
  const copyMermaidButton = document.getElementById("copyMermaidButton");
  const stored = loadPayload();

  renderArtifactBadge(stored);
  if (!stored?.report) {
    showResults(false);
    return;
  }

  showResults(true);
  mermaidSource.textContent = stored.report.mermaid;
  renderGraph(graphRender, stored.report.mermaid);
  copyMermaidButton.addEventListener("click", () => copyText(stored.report.mermaid));
}

function initFindingsPage() {
  const findingsMeta = document.getElementById("findingsMeta");
  const severityBreakdown = document.getElementById("severityBreakdown");
  const findingsList = document.getElementById("findingsList");
  const stored = loadPayload();

  renderArtifactBadge(stored);
  if (!stored?.report) {
    showResults(false);
    return;
  }

  showResults(true);
  renderSeverity(findingsMeta, severityBreakdown, stored.report.findings);
  findingsList.innerHTML = "";

  if (!stored.report.findings.length) {
    findingsList.innerHTML = "<p class=\"muted-copy\">No findings were generated for this artifact.</p>";
    return;
  }

  for (const finding of stored.report.findings) {
    const article = document.createElement("article");
    article.className = `finding-card ${finding.severity.toLowerCase()}`;
    article.innerHTML = `
      <div class="finding-card-head">
        <span class="severity-pill ${finding.severity.toLowerCase()}">${escapeHtml(finding.severity)}</span>
      </div>
      <h3>${escapeHtml(finding.title)}</h3>
      <p><strong>Why risky:</strong> ${escapeHtml(finding.whyRisky)}</p>
      <p><strong>Fix:</strong> ${escapeHtml(finding.remediation)}</p>
    `;
    findingsList.append(article);
  }
}

function initRecommendationsPage() {
  const recommendationsList = document.getElementById("recommendationsList");
  const permissionsChips = document.getElementById("permissionsChips");
  const backupFlag = document.getElementById("backupFlag");
  const debuggableFlag = document.getElementById("debuggableFlag");
  const fullBackupFlag = document.getElementById("fullBackupFlag");
  const stored = loadPayload();

  renderArtifactBadge(stored);
  if (!stored?.report) {
    showResults(false);
    return;
  }

  showResults(true);
  recommendationsList.innerHTML = "";
  for (const recommendation of stored.report.recommendations) {
    const item = document.createElement("li");
    item.textContent = recommendation;
    recommendationsList.append(item);
  }

  toggleFlag(backupFlag, !!stored.report.appConfig.allowBackup);
  toggleFlag(debuggableFlag, !!stored.report.appConfig.debuggable);
  toggleFlag(fullBackupFlag, !!stored.report.appConfig.fullBackupOnly);
  permissionsChips.innerHTML = "";
  if (!stored.report.usesPermissions.length) {
    permissionsChips.innerHTML = "<p class=\"muted-copy\">No manifest permissions declared in the parsed metadata.</p>";
  } else {
    for (const permission of stored.report.usesPermissions) {
      const chip = document.createElement("span");
      chip.className = "permission-chip";
      chip.textContent = permission;
      permissionsChips.append(chip);
    }
  }
}

function renderOverview(fileName, report, nodes) {
    nodes.packageName.textContent = report.package || "Unknown package";
    nodes.artifactSource.textContent = `${fileName} - source ${shortSourceName(report.source)}`;
  toggleFlag(nodes.backupFlag, !!report.appConfig.allowBackup);
  toggleFlag(nodes.debuggableFlag, !!report.appConfig.debuggable);
  toggleFlag(nodes.fullBackupFlag, !!report.appConfig.fullBackupOnly);

  nodes.permissionsChips.innerHTML = "";
  if (!report.usesPermissions.length) {
    nodes.permissionsChips.innerHTML = "<p class=\"muted-copy\">No manifest permissions declared in the parsed metadata.</p>";
  } else {
    for (const permission of report.usesPermissions) {
      const chip = document.createElement("span");
      chip.className = "permission-chip";
      chip.textContent = permission;
      nodes.permissionsChips.append(chip);
    }
  }

  nodes.riskScore.textContent = report.riskScore;
  nodes.riskLevel.textContent = report.riskLevel;
  nodes.riskLevel.className = `metric-chip ${chipClass(report.riskLevel)}`;
  document.documentElement.style.setProperty("--score-angle", `${Math.max(0, Math.min(100, report.riskScore)) * 3.6}deg`);

  nodes.summaryStats.innerHTML = "";
  const cards = [
    ["Components", report.summary.componentCount],
    ["Exported", report.summary.exportedCount],
    ["Deep links", report.summary.deepLinkCount],
    ["Permissions", report.summary.permissionCount],
    ["Protected", report.summary.permissionProtectedCount],
    ["Findings", report.summary.findingCount]
  ];

  for (const [label, value] of cards) {
    const card = document.createElement("article");
    card.className = "stat-card";
    card.innerHTML = `<span>${escapeHtml(label)}</span><strong>${escapeHtml(String(value))}</strong>`;
    nodes.summaryStats.append(card);
  }

  renderSeverity(null, nodes.severityBreakdown, report.findings);

  const topFinding = report.findings[0];
  nodes.leadInsight.innerHTML = topFinding
    ? `
      <div class="insight-callout ${topFinding.severity.toLowerCase()}">
        <span class="severity-pill ${topFinding.severity.toLowerCase()}">${escapeHtml(topFinding.severity)}</span>
        <h4>${escapeHtml(topFinding.title)}</h4>
        <p>${escapeHtml(topFinding.whyRisky)}</p>
        <p><strong>Fix:</strong> ${escapeHtml(topFinding.remediation)}</p>
      </div>
    `
    : "<p class=\"muted-copy\">No high-signal finding was generated for this artifact.</p>";
}

function renderSeverity(metaNode, breakdownNode, findings) {
  const counts = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0
  };

  for (const finding of findings) {
    counts[finding.severity] = (counts[finding.severity] || 0) + 1;
  }

  if (metaNode) {
    metaNode.innerHTML = "";
    for (const severity of ["CRITICAL", "HIGH", "MEDIUM", "LOW"]) {
      if (counts[severity]) {
        const pill = document.createElement("span");
        pill.className = `severity-pill ${severity.toLowerCase()}`;
        pill.textContent = `${counts[severity]} ${severity.toLowerCase()}`;
        metaNode.append(pill);
      }
    }
  }

  breakdownNode.innerHTML = "";
  for (const severity of ["CRITICAL", "HIGH", "MEDIUM", "LOW"]) {
    const count = counts[severity];
    const row = document.createElement("div");
    row.className = "severity-row";
    row.innerHTML = `
      <span class="severity-name">${severity}</span>
      <div class="severity-bar"><span class="severity-fill severity-${severity.toLowerCase()}" style="width:${Math.min(100, count * 18)}%"></span></div>
      <strong>${count}</strong>
    `;
    breakdownNode.append(row);
  }
}

async function renderGraph(container, mermaidText) {
  container.textContent = "Rendering graph...";
  try {
    const mermaid = await loadMermaid();
    const graphId = `graph-${Date.now()}`;
    const { svg } = await mermaid.render(graphId, mermaidText);
    container.innerHTML = svg;
    const svgNode = container.querySelector("svg");
    if (svgNode) {
      svgNode.removeAttribute("width");
      svgNode.removeAttribute("height");
      svgNode.style.width = "max-content";
      svgNode.style.minWidth = "100%";
      svgNode.style.height = "auto";
      svgNode.style.display = "block";
    }
  } catch {
    container.innerHTML = "<p class=\"muted-copy\">Rendered Mermaid preview is unavailable in this browser session.</p>";
  }
}

let mermaidApi = null;
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
    return [actions && `actions: ${actions}`, data && `data: ${data}`].filter(Boolean).join(" | ");
  }).join(" ; ");
}

function hasPermission(component) {
  return Boolean(component.permission || component.readPermission || component.writePermission);
}

function hasDeepLink(component) {
  return component.intentFilters.some((filter) => filter.dataSpecs.some((spec) => spec.scheme || spec.host || spec.mimeType));
}

function showResults(hasReport) {
  common.emptyState?.classList.toggle("hidden", hasReport);
  common.results?.classList.toggle("hidden", !hasReport);
}

function renderArtifactBadge(payload) {
  if (!common.artifactBadge) {
    return;
  }
  if (!payload?.report) {
    common.artifactBadge.textContent = "No artifact loaded";
    common.artifactBadge.className = "artifact-badge muted";
    return;
  }
  common.artifactBadge.textContent = `${payload.report.package || payload.fileName} - ${payload.report.riskScore}/100 ${payload.report.riskLevel}`;
  common.artifactBadge.className = "artifact-badge";
}

function shortSourceName(source) {
  if (!source) {
    return "unknown source";
  }
  const parts = source.split(/[/\\\\]/);
  return parts[parts.length - 1] || source;
}

function savePayload(payload) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
}

function loadPayload() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function updateStatus(node, message, isError = false) {
  node.textContent = message;
  node.style.color = isError ? "#b42318" : "";
}

function toggleFlag(node, show) {
  if (!node) {
    return;
  }
  node.classList.toggle("hidden", !show);
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

async function copyText(value) {
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    // Ignore clipboard errors silently on static pages.
  }
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")
    .replaceAll("'", "&#39;");
}
