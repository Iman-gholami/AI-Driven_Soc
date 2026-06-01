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
        create: async () => {
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
