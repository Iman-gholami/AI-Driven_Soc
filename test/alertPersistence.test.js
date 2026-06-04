const assert = require("node:assert/strict");
const Module = require("node:module");
const test = require("node:test");

function installMongooseMock(overrides = {}) {
  const originalLoad = Module._load;
  const schemas = [];

  function Schema(definition, options) {
    this.definition = definition;
    this.options = options;
    this.indexes = [];
    schemas.push(this);
  }
  Schema.Types = { Mixed: Symbol("Mixed"), ObjectId: Symbol("ObjectId") };
  Schema.prototype.index = function index(fields) {
    this.indexes.push(fields);
  };

  const mongooseMock = {
    Schema,
    models: {},
    model(name, schema) {
      const model = { modelName: name, schema, create: async (record) => ({ ...record, _id: "mock-id" }) };
      this.models[name] = model;
      return model;
    },
    connection: {
      readyState: 0,
      on() {},
    },
    connect: async () => {
      mongooseMock.connection.readyState = 1;
      return mongooseMock;
    },
    disconnect: async () => {
      mongooseMock.connection.readyState = 0;
    },
    ...overrides,
  };

  Module._load = function mockedLoad(request, parent, isMain) {
    if (request === "mongoose") return mongooseMock;
    return originalLoad(request, parent, isMain);
  };

  return {
    mongooseMock,
    schemas,
    restore() {
      Module._load = originalLoad;
    },
  };
}

function clearModule(modulePath) {
  delete require.cache[require.resolve(modulePath)];
}

test("createEventHash is deterministic regardless of object key order", () => {
  const { createEventHash } = require("../src/services/eventHash");

  const first = createEventHash({ user: "alice", nested: { b: 2, a: 1 } });
  const second = createEventHash({ nested: { a: 1, b: 2 }, user: "alice" });

  assert.equal(first, second);
  assert.match(first, /^[a-f0-9]{64}$/);
});

test("Alert model stores alert-level fields without embedded primary analysis history", () => {
  const mock = installMongooseMock();
  clearModule("../src/models/Alert");

  try {
    const Alert = require("../src/models/Alert");
    const definition = Alert.schema.definition;

    assert.ok(definition.alertId);
    assert.ok(definition.rawEvent);
    assert.ok(definition.latestAnalysisId);
    assert.equal(definition.latestAnalysisId.ref, "AlertAnalysis");
    assert.ok(definition.analysisCount);
    assert.ok(definition.lastAnalyzedAt);
    assert.equal(definition.analysis, undefined);
    assert.equal(definition.fullAnalysis, undefined);
    assert.equal(definition.llmProvider, undefined);
    assert.equal(definition.model, undefined);
    assert.equal(definition.processingTimeMs, undefined);

    assert.deepEqual(Alert.schema.indexes, [
      { alertId: 1 },
      { status: 1 },
      { createdAt: -1 },
      { severity: 1 },
      { eventHash: 1 },
      { latestAnalysisId: 1 },
    ]);
  } finally {
    mock.restore();
  }
});

test("AlertAnalysis model references Alert and defines analysis indexes", () => {
  const mock = installMongooseMock();
  clearModule("../src/models/AlertAnalysis");

  try {
    const AlertAnalysis = require("../src/models/AlertAnalysis");
    const definition = AlertAnalysis.schema.definition;

    assert.equal(definition.alert.ref, "Alert");
    assert.equal(definition.alert.required, true);
    assert.ok(definition.alertId);
    assert.ok(definition.analysis);
    assert.ok(definition.fullAnalysis);
    assert.ok(definition.soc);
    assert.ok(definition.processing);
    assert.deepEqual(AlertAnalysis.schema.indexes, [
      { alert: 1 },
      { alertId: 1 },
      { createdAt: -1 },
      { "analysis.severity": 1 },
      { llmProvider: 1 },
      { model: 1 },
    ]);
  } finally {
    mock.restore();
  }
});

test("AlertRepository delegates creation to the model", async () => {
  const mock = installMongooseMock();
  clearModule("../src/repositories/AlertRepository");

  try {
    const { AlertRepository } = require("../src/repositories/AlertRepository");
    const calls = [];
    const repository = new AlertRepository({ alertModel: { create: async (record) => { calls.push(record); return record; } } });
    const record = { alertId: "alert-1", eventHash: "hash" };

    const created = await repository.create(record);

    assert.equal(created, record);
    assert.deepEqual(calls, [record]);
  } finally {
    mock.restore();
  }
});

test("IncidentAnalyzer returns analysis even when persistence fails", async () => {
  const mock = installMongooseMock();
  clearModule("../src/services/analyzer");

  try {
    const { IncidentAnalyzer } = require("../src/services/analyzer");
    const errors = [];
    const analyzer = new IncidentAnalyzer({
      llm: {
        getMetadata: () => ({ provider: "test-provider", model: "test-model" }),
        analyze: async () => validAnalysis,
      },
      alertRepository: {
        upsertAnalyzedAlert: async () => {
          throw new Error("database unavailable");
        },
      },
      logger: { info() {}, error(entry, message) { errors.push({ entry, message }); } },
    });

    const response = await analyzer.analyzeIncident({ id: "alert-1", rule_name: "Suspicious PowerShell" });

    assert.deepEqual(response, validAnalysis);
    assert.equal(errors.length, 1);
    assert.equal(errors[0].message, "Alert storage failure");
  } finally {
    mock.restore();
  }
});

test("IncidentAnalyzer persists immediate analysis as Alert plus AlertAnalysis when possible", async () => {
  const mock = installMongooseMock();
  clearModule("../src/services/analyzer");

  try {
    const { IncidentAnalyzer } = require("../src/services/analyzer");
    const alert = { _id: "alert-object-id", alertId: "alert-1", rawEvent: { id: "alert-1" }, analysisCount: 0 };
    const analysis = { _id: "analysis-1" };
    const calls = [];
    const analyzer = new IncidentAnalyzer({
      llm: {
        getMetadata: () => ({ provider: "test-provider", model: "test-model" }),
        analyze: async () => validAnalysis,
      },
      alertRepository: {
        upsertAnalyzedAlert: async (record) => { calls.push(["upsert", record]); return alert; },
        incrementAnalysisCount: async (alertId) => { calls.push(["increment", alertId]); return { ...alert, analysisCount: 1 }; },
        updateLatestAnalysisReference: async (alertId, record) => { calls.push(["latest", alertId, record]); return { ...alert, ...record }; },
      },
      alertAnalysisRepository: {
        createForAlert: async (storedAlert, record) => { calls.push(["analysis", storedAlert, record]); return analysis; },
      },
      logger: { info() {}, error() {} },
    });

    const response = await analyzer.analyzeIncident({ id: "alert-1", rule_name: "Suspicious PowerShell" });

    assert.deepEqual(response, validAnalysis);
    assert.equal(calls[0][0], "upsert");
    assert.equal(calls[1][0], "analysis");
    assert.equal(calls[1][2].analysis.severity, "high");
    assert.equal(calls[1][2].processing.attemptNumber, 1);
    assert.equal(calls[2][0], "increment");
    assert.equal(calls[3][0], "latest");
    assert.equal(calls[3][2].analysisId, "analysis-1");
  } finally {
    mock.restore();
  }
});

test("connectMongo skips connection without a configured URI", async () => {
  const mock = installMongooseMock({
    connect: async () => {
      throw new Error("connect should not be called");
    },
  });
  clearModule("../src/database/mongo");

  try {
    const { connectMongo } = require("../src/database/mongo");
    const warnings = [];
    const connected = await connectMongo({ info() {}, warn(message) { warnings.push(message); }, error() {} }, { uri: "" });

    assert.equal(connected, false);
    assert.deepEqual(warnings, ["MONGODB_URI is not configured; alert persistence is disabled"]);
  } finally {
    mock.restore();
  }
});

function createTestApp({ alertRepository, alertAnalysisRepository, analyzer }) {
  const express = require("express");
  clearModule("../src/api/routes");
  const { createRouter } = require("../src/api/routes");
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.log = { info() {}, warn() {}, error() {} };
    next();
  });
  app.use(createRouter({ alertRepository, alertAnalysisRepository, analyzer }));
  return app;
}

async function request(app, { method = "GET", path, body }) {
  const server = app.listen(0);
  try {
    const { port } = server.address();
    const response = await fetch(`http://127.0.0.1:${port}${path}`, {
      method,
      headers: body === undefined ? undefined : { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const json = await response.json();
    return { status: response.status, body: json };
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

class InMemoryAlertRepository {
  constructor() {
    this.alerts = [];
    this.upsertCalls = [];
    this.statusCalls = [];
  }

  async upsertNewAlert(record) {
    this.upsertCalls.push(record);
    const now = new Date().toISOString();
    const existingIndex = this.alerts.findIndex((alert) => alert.alertId === record.alertId || alert.eventHash === record.eventHash);
    const existing = existingIndex >= 0 ? this.alerts[existingIndex] : {};
    const stored = {
      ...existing,
      ...record,
      _id: existing._id || `alert-${this.alerts.length + 1}`,
      status: "new",
      analysisCount: existing.analysisCount || 0,
      latestAnalysisId: existing.latestAnalysisId,
      lastAnalyzedAt: existing.lastAnalyzedAt,
      createdAt: existing.createdAt || now,
      updatedAt: now,
      processing: existing.processing || { attempts: 0 },
    };
    if (existingIndex >= 0) this.alerts[existingIndex] = stored;
    else this.alerts.push(stored);
    return stored;
  }

  async listAlerts({ status, severity, page = 1, limit = 50 } = {}) {
    let filtered = [...this.alerts];
    if (status) filtered = filtered.filter((alert) => alert.status === status);
    if (severity) filtered = filtered.filter((alert) => alert.severity === severity);
    filtered.sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
    const safePage = Number(page) || 1;
    const safeLimit = Number(limit) || 50;
    const paged = filtered.slice((safePage - 1) * safeLimit, safePage * safeLimit);
    return {
      alerts: paged,
      pagination: { page: safePage, limit: safeLimit, total: filtered.length, pages: Math.ceil(filtered.length / safeLimit) },
      filters: { status, severity },
      sort: { createdAt: "desc" },
    };
  }

  async findByAlertId(alertId) {
    return this.alerts.find((alert) => alert.alertId === alertId) || null;
  }

  async incrementAnalysisCount(alertId) {
    const existing = await this.findByAlertId(alertId);
    existing.analysisCount = (existing.analysisCount || 0) + 1;
    existing.processing = { ...(existing.processing || {}), attempts: (existing.processing?.attempts || 0) + 1 };
    existing.updatedAt = new Date().toISOString();
    return existing;
  }

  async updateLatestAnalysisReference(alertId, { analysisId, severity, analyzedAt, attemptNumber }) {
    const existing = await this.findByAlertId(alertId);
    Object.assign(existing, {
      latestAnalysisId: analysisId,
      severity,
      status: "analyzed",
      lastAnalyzedAt: analyzedAt.toISOString ? analyzedAt.toISOString() : analyzedAt,
      updatedAt: new Date().toISOString(),
      processing: { ...(existing.processing || {}), attempts: attemptNumber, completedAt: analyzedAt.toISOString ? analyzedAt.toISOString() : analyzedAt },
    });
    return existing;
  }

  async updateStatus(alertId, status) {
    this.statusCalls.push({ alertId, status });
    const existing = await this.findByAlertId(alertId);
    existing.status = status;
    return existing;
  }
}

class InMemoryAlertAnalysisRepository {
  constructor() {
    this.analyses = [];
  }

  async createForAlert(alert, record) {
    const now = new Date().toISOString();
    const stored = {
      _id: `analysis-${this.analyses.length + 1}`,
      alert: alert._id,
      alertId: alert.alertId,
      ...record,
      createdAt: now,
      updatedAt: now,
    };
    this.analyses.push(stored);
    return stored;
  }

  async listByAlertId(alertId) {
    return this.analyses.filter((analysis) => analysis.alertId === alertId).sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
  }

  async findLatestByAlertId(alertId) {
    const [latest] = await this.listByAlertId(alertId);
    return latest || null;
  }

  async findById(id) {
    return this.analyses.find((analysis) => analysis._id === id) || null;
  }
}

const validAnalysis = {
  incident_summary: { what_happened: "Suspicious login" },
  detection_analysis: {},
  behavior_analysis: {},
  attack_mapping: { tactic: "Credential Access" },
  risk_assessment: { severity: "high" },
  false_positive_analysis: {},
  recommended_investigation_steps: ["Review source IP"],
  final_soc_note: "Escalate to tier 2.",
};

function buildAnalyzer() {
  return {
    async analyzeStoredAlert(alert) {
      assert.ok(alert.rawEvent);
      return {
        analysis: validAnalysis,
        metadata: { provider: "test", model: "stub-model", processingTimeMs: 12 },
        persistence: {
          analysis: { severity: "high", summary: "Suspicious login", recommendations: ["Review source IP"] },
          fullAnalysis: validAnalysis,
          soc: { mitreAttack: validAnalysis.attack_mapping, iocs: [{ type: "ip", value: "10.0.0.1" }], providerMetadata: { provider: "test", model: "stub-model" } },
          llmProvider: "test",
          model: "stub-model",
          processingTimeMs: 12,
        },
      };
    },
  };
}

test("POST /webhook-alert stores a single alert as new without invoking AI or creating AlertAnalysis", async () => {
  const alertRepository = new InMemoryAlertRepository();
  const alertAnalysisRepository = new InMemoryAlertAnalysisRepository();
  const analyzer = { analyzeStoredAlert: async () => { throw new Error("AI should not be called"); } };
  const app = createTestApp({ alertRepository, alertAnalysisRepository, analyzer });

  const response = await request(app, {
    method: "POST",
    path: "/webhook-alert",
    body: { alertId: "splunk-1", source: "splunk", severity: "medium", host: "srv-1" },
  });

  assert.equal(response.status, 201);
  assert.equal(response.body.count, 1);
  assert.equal(response.body.alerts[0].alertId, "splunk-1");
  assert.equal(response.body.alerts[0].status, "new");
  assert.equal(response.body.alerts[0].analysisCount, 0);
  assert.equal(response.body.alerts[0].latestAnalysis, undefined);
  assert.equal(alertRepository.alerts[0].rawEvent.host, "srv-1");
  assert.match(alertRepository.alerts[0].eventHash, /^[a-f0-9]{64}$/);
  assert.equal(alertAnalysisRepository.analyses.length, 0);
});

test("POST /webhook-alert stores bulk alerts and overwrites duplicates without deleting analysis history", async () => {
  const alertRepository = new InMemoryAlertRepository();
  const alertAnalysisRepository = new InMemoryAlertAnalysisRepository();
  const app = createTestApp({ alertRepository, alertAnalysisRepository, analyzer: {} });
  const duplicateBody = { source: "splunk", severity: "low", user: "alice" };

  let response = await request(app, {
    method: "POST",
    path: "/webhook-alert",
    body: { alerts: [duplicateBody, { id: "bulk-2", severity: "critical" }] },
  });
  assert.equal(response.status, 201);
  assert.equal(response.body.count, 2);

  alertAnalysisRepository.analyses.push({ _id: "analysis-existing", alertId: alertRepository.alerts[0].alertId, analysis: { severity: "low" } });
  response = await request(app, { method: "POST", path: "/webhook-alert", body: duplicateBody });

  assert.equal(response.status, 201);
  assert.equal(alertRepository.alerts.length, 2);
  assert.equal(alertRepository.alerts[0].rawEvent.user, "alice");
  assert.equal(alertRepository.alerts[0].status, "new");
  assert.equal(alertRepository.upsertCalls[0].eventHash, alertRepository.upsertCalls[2].eventHash);
  assert.equal(alertAnalysisRepository.analyses.length, 1);
});

test("POST /alerts/:id/analyze creates AlertAnalysis and points Alert to newest analysis", async () => {
  const alertRepository = new InMemoryAlertRepository();
  const alertAnalysisRepository = new InMemoryAlertAnalysisRepository();
  await alertRepository.upsertNewAlert({ alertId: "a1", source: "splunk", severity: "low", rawEvent: { host: "srv-1" }, eventHash: "h1" });
  const app = createTestApp({ alertRepository, alertAnalysisRepository, analyzer: buildAnalyzer() });

  const response = await request(app, { method: "POST", path: "/alerts/a1/analyze" });

  assert.equal(response.status, 200);
  assert.deepEqual(response.body.analysis, validAnalysis);
  assert.equal(response.body.metadata.provider, "test");
  assert.equal(response.body.latestAnalysis.analysis.summary, "Suspicious login");
  assert.equal(alertAnalysisRepository.analyses.length, 1);
  assert.equal(alertAnalysisRepository.analyses[0].alert, "alert-1");
  assert.equal(alertRepository.alerts[0].status, "analyzed");
  assert.equal(alertRepository.alerts[0].severity, "high");
  assert.equal(alertRepository.alerts[0].analysisCount, 1);
  assert.equal(alertRepository.alerts[0].latestAnalysisId, "analysis-1");
  assert.deepEqual(alertRepository.alerts[0].rawEvent, { host: "srv-1" });
});

test("multiple analyze calls create multiple AlertAnalysis documents and latestAnalysisId advances", async () => {
  const alertRepository = new InMemoryAlertRepository();
  const alertAnalysisRepository = new InMemoryAlertAnalysisRepository();
  await alertRepository.upsertNewAlert({ alertId: "a1", source: "splunk", severity: "low", rawEvent: { host: "srv-1" }, eventHash: "h1" });
  const app = createTestApp({ alertRepository, alertAnalysisRepository, analyzer: buildAnalyzer() });

  let response = await request(app, { method: "POST", path: "/alerts/a1/analyze" });
  assert.equal(response.status, 200);
  response = await request(app, { method: "POST", path: "/alerts/a1/analyze" });

  assert.equal(response.status, 200);
  assert.equal(alertAnalysisRepository.analyses.length, 2);
  assert.equal(alertAnalysisRepository.analyses[0].processing.attemptNumber, 1);
  assert.equal(alertAnalysisRepository.analyses[1].processing.attemptNumber, 2);
  assert.equal(alertRepository.alerts[0].analysisCount, 2);
  assert.equal(alertRepository.alerts[0].latestAnalysisId, "analysis-2");
});

test("GET /alerts lists summary alerts with filters, pagination, and latest analysis summary", async () => {
  const alertRepository = new InMemoryAlertRepository();
  const alertAnalysisRepository = new InMemoryAlertAnalysisRepository();
  await alertRepository.upsertNewAlert({ alertId: "a1", source: "splunk", severity: "high", rawEvent: {}, eventHash: "h1" });
  await alertRepository.upsertNewAlert({ alertId: "a2", source: "splunk", severity: "low", rawEvent: {}, eventHash: "h2" });
  const analysis = await alertAnalysisRepository.createForAlert(alertRepository.alerts[0], {
    analysis: { severity: "high", summary: "latest", recommendations: [] },
    fullAnalysis: validAnalysis,
  });
  alertRepository.alerts[0].latestAnalysisId = analysis;
  alertRepository.alerts[0].analysisCount = 1;
  const app = createTestApp({ alertRepository, alertAnalysisRepository, analyzer: {} });

  const response = await request(app, { path: "/alerts?status=new&severity=high&page=1&limit=10" });

  assert.equal(response.status, 200);
  assert.equal(response.body.alerts.length, 1);
  assert.deepEqual(Object.keys(response.body.alerts[0]).sort(), ["alertId", "analysisCount", "createdAt", "eventHash", "latestAnalysis", "severity", "source", "status", "updatedAt"].sort());
  assert.equal(response.body.alerts[0].alertId, "a1");
  assert.equal(response.body.alerts[0].latestAnalysis.analysis.summary, "latest");
  assert.equal(response.body.sort.createdAt, "desc");
});

test("GET /alerts/:id returns full alert with latestAnalysis and requested SOC fields", async () => {
  const alertRepository = new InMemoryAlertRepository();
  const alertAnalysisRepository = new InMemoryAlertAnalysisRepository();
  await alertRepository.upsertNewAlert({ alertId: "a1", source: "splunk", severity: "high", rawEvent: { user: "alice" }, eventHash: "h1" });
  const analysis = await alertAnalysisRepository.createForAlert(alertRepository.alerts[0], {
    analysis: { severity: "high", summary: "summary", recommendations: [] },
    soc: { mitreAttack: { tactic: "Credential Access" }, iocs: [{ type: "ip", value: "10.0.0.1" }] },
    fullAnalysis: validAnalysis,
  });
  await alertRepository.updateLatestAnalysisReference("a1", { analysisId: analysis._id, severity: "high", analyzedAt: new Date(), attemptNumber: 1 });
  const app = createTestApp({ alertRepository, alertAnalysisRepository, analyzer: {} });

  const response = await request(app, { path: "/alerts/a1?socFields=mitreAttack,iocs" });

  assert.equal(response.status, 200);
  assert.deepEqual(response.body.rawEvent, { user: "alice" });
  assert.equal(response.body.latestAnalysis.analysis.summary, "summary");
  assert.equal(response.body.analyses, undefined);
  assert.deepEqual(response.body.socFields.mitreAttack, { tactic: "Credential Access" });
  assert.deepEqual(response.body.socFields.iocs, [{ type: "ip", value: "10.0.0.1" }]);
});

test("GET /alerts/:id?includeAnalyses=true returns all analyses", async () => {
  const alertRepository = new InMemoryAlertRepository();
  const alertAnalysisRepository = new InMemoryAlertAnalysisRepository();
  await alertRepository.upsertNewAlert({ alertId: "a1", source: "splunk", severity: "low", rawEvent: { user: "alice" }, eventHash: "h1" });
  const first = await alertAnalysisRepository.createForAlert(alertRepository.alerts[0], { analysis: { severity: "low", summary: "first", recommendations: [] } });
  const second = await alertAnalysisRepository.createForAlert(alertRepository.alerts[0], { analysis: { severity: "high", summary: "second", recommendations: [] } });
  await alertRepository.updateLatestAnalysisReference("a1", { analysisId: second._id, severity: "high", analyzedAt: new Date(), attemptNumber: 2 });
  const app = createTestApp({ alertRepository, alertAnalysisRepository, analyzer: {} });

  const response = await request(app, { path: "/alerts/a1?includeAnalyses=true" });

  assert.equal(response.status, 200);
  assert.equal(response.body.latestAnalysis.id, second._id);
  assert.equal(response.body.analyses.length, 2);
  assert.deepEqual(response.body.analyses.map((analysis) => analysis.id), [first._id, second._id]);
});
