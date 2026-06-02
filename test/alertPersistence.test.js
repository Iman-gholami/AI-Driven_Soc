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
  Schema.Types = { Mixed: Symbol("Mixed") };
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

test("createEventHash is deterministic regardless of object key order", () => {
  const { createEventHash } = require("../src/services/eventHash");

  const first = createEventHash({ user: "alice", nested: { b: 2, a: 1 } });
  const second = createEventHash({ nested: { a: 1, b: 2 }, user: "alice" });

  assert.equal(first, second);
  assert.match(first, /^[a-f0-9]{64}$/);
});

test("Alert model defines required persistence indexes", () => {
  const mock = installMongooseMock();
  delete require.cache[require.resolve("../src/models/Alert")];

  try {
    const Alert = require("../src/models/Alert");
    const indexes = Alert.schema.indexes;

    assert.deepEqual(indexes, [
      { alertId: 1 },
      { status: 1 },
      { createdAt: -1 },
      { severity: 1 },
      { "analysis.severity": 1 },
      { eventHash: 1 },
    ]);
  } finally {
    mock.restore();
  }
});

test("AlertRepository delegates creation to the model", async () => {
  const mock = installMongooseMock();
  delete require.cache[require.resolve("../src/repositories/AlertRepository")];

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
  delete require.cache[require.resolve("../src/services/analyzer")];

  try {
    const { IncidentAnalyzer } = require("../src/services/analyzer");
    const llmResponse = {
      incident_summary: { what_happened: "Suspicious PowerShell execution" },
      detection_analysis: {},
      behavior_analysis: {},
      attack_mapping: {},
      risk_assessment: { severity: "high" },
      false_positive_analysis: {},
      recommended_investigation_steps: ["Review process tree"],
      final_soc_note: "Investigate promptly.",
    };
    const errors = [];
    const analyzer = new IncidentAnalyzer({
      llm: {
        getMetadata: () => ({ provider: "test-provider", model: "test-model" }),
        analyze: async () => llmResponse,
      },
      alertRepository: {
        upsertAnalyzedAlert: async () => {
          throw new Error("database unavailable");
        },
      },
      logger: { info() {}, error(entry, message) { errors.push({ entry, message }); } },
    });

    const response = await analyzer.analyzeIncident({ id: "alert-1", rule_name: "Suspicious PowerShell" });

    assert.deepEqual(response, llmResponse);
    assert.equal(errors.length, 1);
    assert.equal(errors[0].message, "Alert storage failure");
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
  delete require.cache[require.resolve("../src/database/mongo")];

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

function createTestApp({ alertRepository, analyzer }) {
  const express = require("express");
  delete require.cache[require.resolve("../src/api/routes")];
  const { createRouter } = require("../src/api/routes");
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.log = { info() {}, warn() {}, error() {} };
    next();
  });
  app.use(createRouter({ alertRepository, analyzer }));
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
    this.updateCalls = [];
  }

  async upsertNewAlert(record) {
    this.upsertCalls.push(record);
    const now = new Date().toISOString();
    const existingIndex = this.alerts.findIndex((alert) => alert.alertId === record.alertId || alert.eventHash === record.eventHash);
    const stored = {
      ...(existingIndex >= 0 ? this.alerts[existingIndex] : {}),
      ...record,
      status: "new",
      analysis: undefined,
      fullAnalysis: undefined,
      llmProvider: undefined,
      model: undefined,
      processingTimeMs: undefined,
      createdAt: existingIndex >= 0 ? this.alerts[existingIndex].createdAt : now,
      updatedAt: now,
      soc: {},
      processing: { attempts: 0 },
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

  async updateAnalysis(alertId, persistence) {
    this.updateCalls.push({ alertId, persistence });
    const existing = await this.findByAlertId(alertId);
    Object.assign(existing, persistence, {
      severity: persistence.analysis.severity,
      status: "analyzed",
      updatedAt: new Date().toISOString(),
      processing: { attempts: (existing.processing?.attempts || 0) + 1, completedAt: new Date().toISOString() },
    });
    return existing;
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

test("POST /webhook-alert stores a single alert as new without invoking AI", async () => {
  const repository = new InMemoryAlertRepository();
  const analyzer = { analyzeStoredAlert: async () => { throw new Error("AI should not be called"); } };
  const app = createTestApp({ alertRepository: repository, analyzer });

  const response = await request(app, {
    method: "POST",
    path: "/webhook-alert",
    body: { alertId: "splunk-1", source: "splunk", severity: "medium", host: "srv-1" },
  });

  assert.equal(response.status, 201);
  assert.equal(response.body.count, 1);
  assert.equal(response.body.alerts[0].alertId, "splunk-1");
  assert.equal(response.body.alerts[0].status, "new");
  assert.equal(repository.alerts[0].rawEvent.host, "srv-1");
  assert.match(repository.alerts[0].eventHash, /^[a-f0-9]{64}$/);
});

test("POST /webhook-alert stores bulk alerts and overwrites duplicates by eventHash", async () => {
  const repository = new InMemoryAlertRepository();
  const app = createTestApp({ alertRepository: repository, analyzer: {} });
  const duplicateBody = { source: "splunk", severity: "low", user: "alice" };

  let response = await request(app, {
    method: "POST",
    path: "/webhook-alert",
    body: { alerts: [duplicateBody, { id: "bulk-2", severity: "critical" }] },
  });
  assert.equal(response.status, 201);
  assert.equal(response.body.count, 2);

  response = await request(app, { method: "POST", path: "/webhook-alert", body: duplicateBody });

  assert.equal(response.status, 201);
  assert.equal(repository.alerts.length, 2);
  assert.equal(repository.alerts[0].rawEvent.user, "alice");
  assert.equal(repository.upsertCalls[0].eventHash, repository.upsertCalls[2].eventHash);
});

test("GET /alerts lists summary alerts with filters and pagination", async () => {
  const repository = new InMemoryAlertRepository();
  await repository.upsertNewAlert({ alertId: "a1", source: "splunk", severity: "high", rawEvent: {}, eventHash: "h1" });
  await repository.upsertNewAlert({ alertId: "a2", source: "splunk", severity: "low", rawEvent: {}, eventHash: "h2" });
  const app = createTestApp({ alertRepository: repository, analyzer: {} });

  const response = await request(app, { path: "/alerts?status=new&severity=high&page=1&limit=10" });

  assert.equal(response.status, 200);
  assert.equal(response.body.alerts.length, 1);
  assert.deepEqual(Object.keys(response.body.alerts[0]).sort(), ["alertId", "createdAt", "eventHash", "severity", "source", "status", "updatedAt"].sort());
  assert.equal(response.body.alerts[0].alertId, "a1");
  assert.equal(response.body.sort.createdAt, "desc");
});

test("POST /alerts/:id/analyze overwrites previous analysis and preserves rawEvent", async () => {
  const repository = new InMemoryAlertRepository();
  await repository.upsertNewAlert({ alertId: "a1", source: "splunk", severity: "low", rawEvent: { host: "srv-1" }, eventHash: "h1" });
  repository.alerts[0].analysis = { severity: "low", summary: "old", recommendations: [] };
  const analyzer = {
    async analyzeStoredAlert(alert) {
      assert.deepEqual(alert.rawEvent, { host: "srv-1" });
      return {
        analysis: validAnalysis,
        metadata: { provider: "test", model: "stub-model", processingTimeMs: 12 },
        persistence: {
          analysis: { severity: "high", summary: "Suspicious login", recommendations: ["Review source IP"] },
          fullAnalysis: validAnalysis,
          soc: { mitreAttack: validAnalysis.attack_mapping, providerMetadata: { provider: "test", model: "stub-model" } },
          llmProvider: "test",
          model: "stub-model",
          processingTimeMs: 12,
        },
      };
    },
  };
  const app = createTestApp({ alertRepository: repository, analyzer });

  const response = await request(app, { method: "POST", path: "/alerts/a1/analyze" });

  assert.equal(response.status, 200);
  assert.deepEqual(response.body.analysis, validAnalysis);
  assert.equal(response.body.metadata.provider, "test");
  assert.equal(repository.alerts[0].status, "analyzed");
  assert.equal(repository.alerts[0].analysis.summary, "Suspicious login");
  assert.deepEqual(repository.alerts[0].rawEvent, { host: "srv-1" });
});

test("GET /alerts/:id returns full alert and requested SOC fields", async () => {
  const repository = new InMemoryAlertRepository();
  await repository.upsertNewAlert({ alertId: "a1", source: "splunk", severity: "high", rawEvent: { user: "alice" }, eventHash: "h1" });
  repository.alerts[0].analysis = { severity: "high", summary: "summary", recommendations: [] };
  repository.alerts[0].soc = { mitreAttack: { tactic: "Credential Access" }, iocs: [{ type: "ip", value: "10.0.0.1" }] };
  const app = createTestApp({ alertRepository: repository, analyzer: {} });

  const response = await request(app, { path: "/alerts/a1?socFields=mitreAttack,iocs" });

  assert.equal(response.status, 200);
  assert.deepEqual(response.body.rawEvent, { user: "alice" });
  assert.equal(response.body.analysis.summary, "summary");
  assert.deepEqual(response.body.socFields.mitreAttack, { tactic: "Credential Access" });
  assert.deepEqual(response.body.socFields.iocs, [{ type: "ip", value: "10.0.0.1" }]);
});
