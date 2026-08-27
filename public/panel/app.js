const state = {
  alerts: [],
  pagination: { page: 1, limit: 50, total: 0, pages: 1 },
  selectedId: null,
  selectedAlert: null,
};

const els = {
  apiStatus: document.querySelector("#apiStatus"),
  refreshButton: document.querySelector("#refreshButton"),
  searchInput: document.querySelector("#searchInput"),
  severityFilter: document.querySelector("#severityFilter"),
  aiFilter: document.querySelector("#aiFilter"),
  queueState: document.querySelector("#queueState"),
  tableBody: document.querySelector("#alertTableBody"),
  metricAlerts: document.querySelector("#metricAlerts"),
  metricMatched: document.querySelector("#metricMatched"),
  metricAnalyzed: document.querySelector("#metricAnalyzed"),
  paginationInfo: document.querySelector("#paginationInfo"),
  prevPageButton: document.querySelector("#prevPageButton"),
  nextPageButton: document.querySelector("#nextPageButton"),
  drawer: document.querySelector("#triageDrawer"),
  drawerBackdrop: document.querySelector("#drawerBackdrop"),
  drawerTitle: document.querySelector("#drawerTitle"),
  drawerMeta: document.querySelector("#drawerMeta"),
  drawerBody: document.querySelector("#drawerBody"),
  drawerFooter: document.querySelector("#drawerFooter"),
  analysisHint: document.querySelector("#analysisHint"),
  analyzeButton: document.querySelector("#analyzeButton"),
  closeDrawerButton: document.querySelector("#closeDrawerButton"),
  emptyQueueTemplate: document.querySelector("#emptyQueueTemplate"),
};

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: options.body ? { "Content-Type": "application/json", ...(options.headers || {}) } : options.headers,
    ...options,
  });

  let payload = null;
  const text = await response.text();
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch (_) {
      payload = { detail: text };
    }
  }

  if (!response.ok) {
    const error = new Error(payload?.detail || `Request failed with status ${response.status}`);
    error.status = response.status;
    error.payload = payload;
    throw error;
  }

  return payload;
}

function setConnection(online, label) {
  els.apiStatus.classList.toggle("online", online);
  els.apiStatus.classList.toggle("offline", !online);
  els.apiStatus.lastChild.textContent = ` ${label}`;
}

function setQueueMessage(message) {
  els.queueState.textContent = message || "";
  els.queueState.classList.toggle("visible", Boolean(message));
}

function aiLabel(status) {
  return {
    not_analyzed: "Not analyzed",
    analyzing: "Analyzing",
    analyzed: "Analyzed",
    failed: "Failed",
  }[status] || "Not analyzed";
}

function actionLabel(status) {
  return {
    not_analyzed: "AI Analyze",
    analyzing: "Analyzing…",
    analyzed: "View AI",
    failed: "Retry AI",
  }[status] || "AI Analyze";
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function renderMetrics() {
  els.metricAlerts.textContent = state.pagination.total ?? state.alerts.length;
  els.metricMatched.textContent = state.alerts.filter((a) => a.ruleMatch?.status === "matched").length;
  els.metricAnalyzed.textContent = state.alerts.filter((a) => a.aiStatus === "analyzed").length;
}

function filteredAlerts() {
  const q = els.searchInput.value.trim().toLowerCase();
  if (!q) return state.alerts;

  return state.alerts.filter((alert) => {
    const haystack = [
      alert.alertId,
      alert.signature,
      alert.source,
      alert.host,
      alert.eventType,
      alert.ruleMatch?.ruleId,
      alert.ruleMatch?.title,
      alert.ruleMatch?.sourceFile,
    ].filter(Boolean).join(" ").toLowerCase();

    return haystack.includes(q);
  });
}

function ruleCell(alert) {
  const match = alert.ruleMatch;
  if (!match) {
    return '<span class="rule-match rule-miss">— Not resolved</span>';
  }

  if (match.status === "matched") {
    return `
      <div class="rule-match"><span class="rule-check">●</span><strong>SID ${escapeHtml(match.ruleId || "—")}</strong></div>
      <div class="rule-subtitle">${escapeHtml(match.title || "Matched rule")} · rev ${escapeHtml(match.revision ?? "—")}</div>
    `;
  }

  if (match.status === "ambiguous") {
    return `
      <div class="rule-match rule-warn">● Ambiguous</div>
      <div class="rule-subtitle">${escapeHtml(match.candidateCount || 0)} candidate rules</div>
    `;
  }

  return `
    <div class="rule-match rule-miss">● Unresolved</div>
    <div class="rule-subtitle">${escapeHtml(match.reason || "No matching rule")}</div>
  `;
}

function renderRows() {
  const alerts = filteredAlerts();
  els.tableBody.innerHTML = "";

  if (alerts.length === 0) {
    els.tableBody.appendChild(els.emptyQueueTemplate.content.cloneNode(true));
    return;
  }

  for (const alert of alerts) {
    const tr = document.createElement("tr");
    tr.dataset.alertId = alert.alertId;
    tr.innerHTML = `
      <td><span class="badge ${escapeHtml((alert.severity || "unknown").toLowerCase())}">${escapeHtml(alert.severity || "unknown")}</span></td>
      <td>
        <div class="alert-title" title="${escapeHtml(alert.signature || alert.alertId)}">${escapeHtml(alert.signature || alert.alertId)}</div>
        <div class="alert-subtitle">${escapeHtml(alert.alertId)}${alert.host ? ` · ${escapeHtml(alert.host)}` : ""}</div>
      </td>
      <td>${ruleCell(alert)}</td>
      <td>
        <span class="ai-pill ${escapeHtml(alert.aiStatus || "not_analyzed")}">
          <span class="ai-dot"></span>
          ${escapeHtml(aiLabel(alert.aiStatus))}
        </span>
      </td>
      <td>${escapeHtml(formatDate(alert.createdAt))}</td>
      <td class="align-right">
        <button
          class="button ${alert.aiStatus === "analyzed" ? "button-secondary" : "button-primary"} row-action"
          type="button"
          data-action="ai"
          data-alert-id="${escapeHtml(alert.alertId)}"
          ${alert.aiStatus === "analyzing" ? "disabled" : ""}
        >${escapeHtml(actionLabel(alert.aiStatus))}</button>
      </td>
    `;
    els.tableBody.appendChild(tr);
  }
}

function renderPagination() {
  const { page, limit, total, pages } = state.pagination;
  const start = total === 0 ? 0 : (page - 1) * limit + 1;
  const end = Math.min(page * limit, total);
  els.paginationInfo.textContent = `${start}–${end} of ${total} alerts`;
  els.prevPageButton.disabled = page <= 1;
  els.nextPageButton.disabled = page >= Math.max(pages, 1);
}

async function loadAlerts(page = state.pagination.page) {
  setQueueMessage("Loading alerts…");
  els.refreshButton.disabled = true;

  const params = new URLSearchParams({
    page: String(page),
    limit: String(state.pagination.limit),
  });

  if (els.severityFilter.value) params.set("severity", els.severityFilter.value);
  if (els.aiFilter.value) params.set("aiStatus", els.aiFilter.value);

  try {
    const result = await api(`/alerts?${params.toString()}`);
    state.alerts = result.alerts || [];
    state.pagination = {
      page: result.pagination?.page || page,
      limit: result.pagination?.limit || state.pagination.limit,
      total: result.pagination?.total || 0,
      pages: result.pagination?.pages || 1,
    };
    setConnection(true, "API online");
    setQueueMessage("");
    renderMetrics();
    renderRows();
    renderPagination();
  } catch (error) {
    setConnection(false, "API unavailable");
    setQueueMessage(error.message);
  } finally {
    els.refreshButton.disabled = false;
  }
}

function openDrawerShell() {
  els.drawer.classList.add("open");
  els.drawer.setAttribute("aria-hidden", "false");
  els.drawerBackdrop.hidden = false;
  document.body.style.overflow = "hidden";
}

function closeDrawer() {
  els.drawer.classList.remove("open");
  els.drawer.setAttribute("aria-hidden", "true");
  els.drawerBackdrop.hidden = true;
  document.body.style.overflow = "";
}

function kvItem(key, value) {
  if (value === null || value === undefined || value === "") return "";
  return `
    <div class="kv-item">
      <span class="kv-key">${escapeHtml(key)}</span>
      <span class="kv-value">${escapeHtml(value)}</span>
    </div>
  `;
}

function compactObjectText(value) {
  if (value === null || value === undefined) return "No data supplied.";
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map((item) => typeof item === "string" ? item : JSON.stringify(item)).join("\n");
  if (typeof value === "object") {
    const preferred = value.summary || value.what_happened || value.reasoning || value.assessment || value.description;
    if (preferred) return String(preferred);
    return JSON.stringify(value, null, 2);
  }
  return String(value);
}

function renderObservedEvidence(alert) {
  const raw = alert.rawEvent || {};
  const fields = [
    ["Signature", raw.signature || raw.Signature || raw.rule_name],
    ["Event ID", raw.event_id || raw.alert_id || alert.alertId],
    ["Event type", raw.eventtype],
    ["Host", raw.host],
    ["Source IP", raw.src_ip || raw.source_ip],
    ["Source port", raw.src_port],
    ["Destination IP", raw.dst_ip || raw.dest_ip],
    ["Destination port", raw.dst_port || raw.dest_port],
    ["Protocol", raw.protocol || raw.proto],
    ["Severity", raw.severity || alert.severity],
    ["Timestamp", raw.timestamp || raw._time],
  ];

  return `
    <section class="section-card">
      <div class="section-title">
        <div>
          <div class="section-kicker">Observed Evidence</div>
          <h3>Splunk telemetry</h3>
        </div>
      </div>
      <div class="kv-grid">
        ${fields.map(([k, v]) => kvItem(k, v)).join("")}
      </div>
      <details style="margin-top:12px">
        <summary class="details-summary">View raw event</summary>
        <pre class="raw-rule" style="margin-top:10px">${escapeHtml(JSON.stringify(raw, null, 2))}</pre>
      </details>
    </section>
  `;
}

function renderDetectionRule(alert) {
  const detection = alert.detectionRule;
  const match = alert.ruleMatch || {};
  if (!detection || detection.status !== "matched" || !detection.rule) {
    return `
      <section class="section-card">
        <div class="section-title">
          <div>
            <div class="section-kicker">Detection Logic</div>
            <h3>Rule ${escapeHtml(detection?.status || match.status || "unavailable")}</h3>
          </div>
        </div>
        <div class="analysis-copy">
          <p>${escapeHtml(detection?.reason || match.reason || "No deterministic detection rule is available for this alert.")}</p>
        </div>
      </section>
    `;
  }

  const rule = detection.rule;
  const contents = Array.isArray(rule.contents) ? rule.contents : [];
  const header = rule.header || {};

  return `
    <section class="section-card">
      <div class="section-title">
        <div>
          <div class="section-kicker">Detection Logic</div>
          <h3>${escapeHtml(rule.title || "Matched detection rule")}</h3>
        </div>
        <span class="badge low">Exact rule context</span>
      </div>
      <div class="kv-grid">
        ${kvItem("Action", rule.action || "alert")}
        ${kvItem("SID", rule.rule_id)}
        ${kvItem("Revision", rule.revision)}
        ${kvItem("Class", rule.classtype)}
        ${kvItem("Protocol", rule.protocol)}
        ${kvItem("Flow", (rule.flow || []).join(", "))}
        ${kvItem("Source", [header.src, header.src_port].filter(Boolean).join(" : "))}
        ${kvItem("Destination", [header.dst, header.dst_port].filter(Boolean).join(" : "))}
      </div>
      ${contents.length ? `
        <div class="analysis-block" style="margin-top:12px">
          <h4>Detection content</h4>
          <ul class="rule-content-list">
            ${contents.map((content) => `<li><code>${escapeHtml(content.value)}</code>${content.negative ? " (negative match)" : ""}</li>`).join("")}
          </ul>
        </div>
      ` : ""}
      <details style="margin-top:12px">
        <summary class="details-summary">View raw rule</summary>
        <pre class="raw-rule" style="margin-top:10px">${escapeHtml(rule.raw_rule || "Raw rule unavailable")}</pre>
      </details>
    </section>
  `;
}

function renderAiAnalysis(alert) {
  const status = alert.aiStatus || (alert.fullAnalysis ? "analyzed" : "not_analyzed");
  const analysis = alert.fullAnalysis;

  if (status === "analyzing") {
    return `
      <section class="section-card">
        <div class="section-title">
          <div><div class="section-kicker">AI Assessment</div><h3>Analysis in progress</h3></div>
          <span class="ai-pill analyzing"><span class="ai-dot"></span>Analyzing</span>
        </div>
        <div class="analysis-copy"><p>The selected incident and matched detection rule are being sent to the LLM for Tier-1 triage.</p></div>
      </section>
    `;
  }

  if (status === "failed") {
    return `
      <section class="section-card">
        <div class="section-title">
          <div><div class="section-kicker">AI Assessment</div><h3>Analysis failed</h3></div>
        </div>
        <div class="error-box">${escapeHtml(alert.processing?.lastError || "The last AI analysis attempt failed.")}</div>
      </section>
    `;
  }

  if (!analysis) {
    return `
      <section class="section-card">
        <div class="section-title">
          <div><div class="section-kicker">AI Assessment</div><h3>Not analyzed yet</h3></div>
        </div>
        <div class="analysis-copy">
          <p>No LLM request has been made for this alert. Use <strong>Analyze with AI</strong> when you want an initial Tier-1 assessment.</p>
        </div>
      </section>
    `;
  }

  const risk = analysis.risk_assessment || {};
  const severity = String(risk.severity || alert.severity || "unknown").toLowerCase();
  const confidence = risk.confidence !== undefined ? `${risk.confidence}% confidence` : "Confidence not provided";
  const recommendations = analysis.recommended_investigation_steps || [];

  return `
    <section class="section-card">
      <div class="section-title">
        <div><div class="section-kicker">AI Assessment</div><h3>Initial SOC triage</h3></div>
        <span class="ai-pill analyzed"><span class="ai-dot"></span>Analyzed</span>
      </div>

      <div class="analysis-hero">
        <div class="risk-score ${escapeHtml(severity)}">${escapeHtml(severity)} risk</div>
        <div class="confidence">${escapeHtml(confidence)}</div>
      </div>

      <div class="analysis-grid">
        <div class="analysis-block">
          <h4>Incident summary</h4>
          <pre>${escapeHtml(compactObjectText(analysis.incident_summary))}</pre>
        </div>
        <div class="analysis-block">
          <h4>Why the alert triggered</h4>
          <pre>${escapeHtml(compactObjectText(analysis.why_alert_triggered || analysis.detection_analysis))}</pre>
        </div>
        <div class="analysis-block">
          <h4>Behavior assessment</h4>
          <pre>${escapeHtml(compactObjectText(analysis.behavior_analysis))}</pre>
        </div>
        <div class="analysis-block">
          <h4>False-positive analysis</h4>
          <pre>${escapeHtml(compactObjectText(analysis.false_positive_analysis))}</pre>
        </div>
      </div>

      ${recommendations.length ? `
        <div class="analysis-block" style="margin-top:12px">
          <h4>Recommended investigation</h4>
          <ol class="recommendation-list">
            ${recommendations.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}
          </ol>
        </div>
      ` : ""}

      <div class="analysis-block" style="margin-top:12px">
        <h4>Analyst note</h4>
        <pre>${escapeHtml(analysis.analyst_note || analysis.final_soc_note || "No analyst note returned.")}</pre>
      </div>
    </section>
  `;
}

function renderDrawer(alert) {
  state.selectedAlert = alert;
  state.selectedId = alert.alertId;
  els.drawerTitle.textContent = alert.rawEvent?.signature || alert.rawEvent?.Signature || alert.rawEvent?.rule_name || alert.alertId;
  els.drawerMeta.textContent = `${alert.alertId} · ${alert.source || "splunk"} · ${formatDate(alert.createdAt)}`;

  els.drawerBody.innerHTML = [
    renderObservedEvidence(alert),
    renderDetectionRule(alert),
    renderAiAnalysis(alert),
  ].join("");

  const status = alert.aiStatus || (alert.fullAnalysis ? "analyzed" : "not_analyzed");
  els.drawerFooter.hidden = false;
  els.analyzeButton.disabled = status === "analyzing";
  els.analyzeButton.innerHTML = status === "analyzing"
    ? '<span class="spinner"></span> Analyzing…'
    : escapeHtml(status === "analyzed" ? "Re-analyze with AI" : status === "failed" ? "Retry AI Analysis" : "Analyze with AI");

  els.analysisHint.textContent = status === "analyzed"
    ? "A new run will append a fresh summary and replace the latest full analysis."
    : "LLM analysis runs only after this analyst action.";
}

async function openAlert(alertId) {
  state.selectedId = alertId;
  openDrawerShell();
  els.drawerTitle.textContent = "Loading alert…";
  els.drawerMeta.textContent = alertId;
  els.drawerBody.innerHTML = '<div class="drawer-loading">Loading incident, detection rule, and AI state…</div>';
  els.drawerFooter.hidden = true;

  try {
    const alert = await api(`/alerts/${encodeURIComponent(alertId)}`);
    renderDrawer(alert);
  } catch (error) {
    els.drawerBody.innerHTML = `<div class="error-box">${escapeHtml(error.message)}</div>`;
  }
}

async function analyzeSelected() {
  const alertId = state.selectedId;
  if (!alertId) return;

  const alert = state.selectedAlert || { alertId };
  alert.aiStatus = "analyzing";
  renderDrawer(alert);

  try {
    await api(`/alerts/${encodeURIComponent(alertId)}/analyze`, { method: "POST" });
    const refreshed = await api(`/alerts/${encodeURIComponent(alertId)}`);
    renderDrawer(refreshed);
    await loadAlerts(state.pagination.page);
  } catch (error) {
    try {
      const refreshed = await api(`/alerts/${encodeURIComponent(alertId)}`);
      renderDrawer(refreshed);
    } catch (_) {
      els.drawerBody.insertAdjacentHTML("afterbegin", `<div class="error-box">${escapeHtml(error.message)}</div>`);
    }
    await loadAlerts(state.pagination.page);
  }
}

els.tableBody.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-action='ai']");
  if (button) {
    event.stopPropagation();
    const alertId = button.dataset.alertId;
    const alert = state.alerts.find((item) => item.alertId === alertId);
    await openAlert(alertId);
    if (alert && ["not_analyzed", "failed"].includes(alert.aiStatus || "not_analyzed")) {
      await analyzeSelected();
    }
    return;
  }

  const row = event.target.closest("tr[data-alert-id]");
  if (row) await openAlert(row.dataset.alertId);
});

els.refreshButton.addEventListener("click", () => loadAlerts(state.pagination.page));
els.searchInput.addEventListener("input", renderRows);
els.severityFilter.addEventListener("change", () => loadAlerts(1));
els.aiFilter.addEventListener("change", () => loadAlerts(1));
els.prevPageButton.addEventListener("click", () => loadAlerts(Math.max(1, state.pagination.page - 1)));
els.nextPageButton.addEventListener("click", () => loadAlerts(Math.min(state.pagination.pages, state.pagination.page + 1)));
els.closeDrawerButton.addEventListener("click", closeDrawer);
els.drawerBackdrop.addEventListener("click", closeDrawer);
els.analyzeButton.addEventListener("click", analyzeSelected);
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeDrawer();
});

loadAlerts(1);
