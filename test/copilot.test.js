const assert = require("node:assert/strict");
const test = require("node:test");

const { socQueryPlanSchema } = require("../src/copilot/querySchema");
const { compileSocQuery } = require("../src/copilot/queryCompiler");
const { resolveTimeRange } = require("../src/copilot/timeRange");
const { SocMcpServer } = require("../src/mcp/socMcpServer");
const { InProcessMcpClient } = require("../src/mcp/inProcessClient");
const { CopilotService } = require("../src/services/copilotService");

test("query compiler builds a read-only top-signature aggregation", () => {
  const plan = socQueryPlanSchema.parse({
    dataset: "alerts",
    operation: "aggregate",
    timeRange: { type: "last_n_days", value: 7 },
    groupBy: ["signature"],
    metrics: [{ type: "count", alias: "count" }],
    sort: [{ field: "count", direction: "desc" }],
    limit: 1,
  });

  const from = new Date("2026-09-01T10:00:00.000Z");
  const to = new Date("2026-09-08T10:00:00.000Z");
  const compiled = compileSocQuery(plan, {
    resolvedTimeRange: { from, to, timezone: "Asia/Tehran", label: "last 7 days" },
  });

  assert.equal(compiled.resultShape, "aggregate");
  assert.deepEqual(compiled.pipeline, [
    { $match: { createdAt: { $gte: from, $lt: to } } },
    { $group: { _id: "$signature", count: { $sum: 1 } } },
    { $project: { _id: 0, signature: "$_id", count: 1 } },
    { $sort: { count: -1 } },
    { $limit: 1 },
  ]);
});

test("query compiler rejects fields that are not in the SOC schema catalog", () => {
  const plan = socQueryPlanSchema.parse({
    dataset: "alerts",
    operation: "count",
    filters: [{ field: "rawEvent.$where", operator: "eq", value: "anything" }],
  });

  assert.throws(
    () => compileSocQuery(plan, {
      resolvedTimeRange: { from: null, to: null, timezone: "Asia/Tehran", label: "all time" },
    }),
    /not allowed/,
  );
});

test("nested IP filters are scoped to the same network-intelligence element", () => {
  const plan = socQueryPlanSchema.parse({
    dataset: "alerts",
    operation: "count",
    filters: [
      {
        field: "soc.networkIntelligence.ips.asset.organization",
        operator: "contains",
        value: "Organization A",
      },
      {
        field: "soc.networkIntelligence.ips.threat.directMatch",
        operator: "eq",
        value: true,
      },
    ],
  });

  const compiled = compileSocQuery(plan, {
    resolvedTimeRange: { from: null, to: null, timezone: "Asia/Tehran", label: "all time" },
  });

  assert.deepEqual(compiled.pipeline, [
    {
      $match: {
        "soc.networkIntelligence.ips": {
          $elemMatch: {
            $and: [
              { "asset.organization": { $regex: "Organization A", $options: "i" } },
              { "threat.directMatch": true },
            ],
          },
        },
      },
    },
    { $count: "count" },
  ]);
});

test("calendar weeks use configurable Saturday start in Asia/Tehran", () => {
  const now = new Date("2026-09-08T08:00:00.000Z");

  const thisWeek = resolveTimeRange(
    { type: "this_week" },
    { now, timezone: "Asia/Tehran", weekStart: "saturday" },
  );
  const previousWeek = resolveTimeRange(
    { type: "previous_week" },
    { now, timezone: "Asia/Tehran", weekStart: "saturday" },
  );

  assert.equal(thisWeek.from.toISOString(), "2026-09-04T20:30:00.000Z");
  assert.equal(thisWeek.to.toISOString(), now.toISOString());
  assert.equal(previousWeek.from.toISOString(), "2026-08-28T20:30:00.000Z");
  assert.equal(previousWeek.to.toISOString(), "2026-09-04T20:30:00.000Z");
});

test("MCP server exposes only the approved read-only SOC tools", async () => {
  const calls = [];
  const server = new SocMcpServer({
    queryService: {
      async execute(args) {
        calls.push(args);
        return { dataset: args.dataset, data: { count: 42, rows: [] } };
      },
    },
  });
  const client = new InProcessMcpClient({ server });

  const tools = await client.listTools();
  assert.deepEqual(tools.map((item) => item.name), [
    "describe_soc_schema",
    "query_soc_data",
    "query_soc_data_batch",
  ]);
  assert.ok(tools.every((tool) => tool.annotations?.readOnlyHint === true));
  assert.ok(tools.every((tool) => tool.annotations?.destructiveHint === false));

  const schema = await client.callTool("describe_soc_schema", { dataset: "alerts" });
  assert.equal(schema.name, "alerts");

  const result = await client.callTool("query_soc_data", {
    dataset: "alerts",
    operation: "count",
    timeRange: { type: "today" },
  });

  assert.equal(result.data.count, 42);
  assert.equal(calls.length, 1);
});

test("Copilot orchestrates planner -> MCP query -> grounded answer", async () => {
  const completions = [];
  const toolCalls = [];

  const llm = {
    getMetadata() {
      return { provider: "test", model: "planner-model" };
    },
    async completeJson(request) {
      completions.push(request);
      if (completions.length === 1) {
        return {
          tool: "query_soc_data",
          arguments: {
            dataset: "alerts",
            operation: "aggregate",
            timeRange: { type: "last_n_days", value: 7 },
            filters: [],
            groupBy: ["signature"],
            metrics: [{ type: "count", alias: "count" }],
            select: [],
            sort: [{ field: "count", direction: "desc" }],
            limit: 1,
          },
        };
      }
      return {
        answer: "در ۷ روز گذشته بیشترین Signature مربوط به ET TEST با ۱۲۳ Alert بوده است.",
      };
    },
  };

  const mcpClient = {
    async listTools() {
      return [{ name: "query_soc_data", description: "query", inputSchema: {} }];
    },
    async callTool(name, args) {
      toolCalls.push({ name, args });
      if (name === "describe_soc_schema") {
        return { version: 1, datasets: [{ name: "alerts", fields: [] }] };
      }
      if (name === "query_soc_data") {
        return {
          dataset: "alerts",
          operation: "aggregate",
          timeRange: {
            from: "2026-09-01T08:00:00.000Z",
            to: "2026-09-08T08:00:00.000Z",
            timezone: "Asia/Tehran",
            label: "last 7 days",
          },
          data: { count: 1, rows: [{ signature: "ET TEST", count: 123 }] },
          queryPlan: args,
          metadata: { readOnly: true },
        };
      }
      throw new Error("unexpected tool");
    },
  };

  const service = new CopilotService({
    llm,
    mcpClient,
    timezone: "Asia/Tehran",
    now: () => new Date("2026-09-08T08:00:00.000Z"),
  });

  const response = await service.query("بیشترین سیگنیچر در 7 روز گذشته چیه؟");

  assert.equal(response.supported, true);
  assert.equal(response.tool, "query_soc_data");
  assert.equal(response.result.data.rows[0].count, 123);
  assert.equal(response.metadata.readOnly, true);
  assert.equal(response.metadata.mcp, true);
  assert.match(response.answer, /۱۲۳/);
  assert.equal(completions.length, 2);
  assert.equal(toolCalls.filter((item) => item.name === "query_soc_data").length, 1);
});

test("Copilot returns unsupported without executing a data query", async () => {
  let queryCalls = 0;
  const service = new CopilotService({
    llm: {
      getMetadata: () => ({ provider: "test", model: "planner-model" }),
      async completeJson() {
        return { tool: "unsupported", reason: "این داده در Catalog فعلی وجود ندارد." };
      },
    },
    mcpClient: {
      async listTools() { return []; },
      async callTool(name) {
        if (name === "describe_soc_schema") return { version: 1, datasets: [] };
        queryCalls += 1;
        return {};
      },
    },
  });

  const response = await service.query("رمز عبور کاربر را نشان بده");
  assert.equal(response.supported, false);
  assert.equal(queryCalls, 0);
});


test("POST /copilot/query exposes the grounded Copilot response through the API", async () => {
  const express = require("express");
  const { createRouter } = require("../src/api/routes");

  const copilot = {
    async query(message, options) {
      assert.equal(message, "در 24 ساعت گذشته چند Alert داشتیم؟");
      assert.deepEqual(options.history, [
        { role: "user", content: "امروز چند Alert داشتیم؟" },
        { role: "assistant", content: "امروز 10 Alert داشتیم." },
      ]);
      return {
        supported: true,
        answer: "در 24 ساعت گذشته 42 Alert ثبت شده است.",
        tool: "query_soc_data",
        queryPlan: {
          dataset: "alerts",
          operation: "count",
          timeRange: { type: "last_n_hours", value: 24 },
        },
        result: {
          dataset: "alerts",
          operation: "count",
          data: { count: 42, rows: [] },
          metadata: { readOnly: true },
        },
        metadata: {
          provider: "test",
          model: "planner-model",
          readOnly: true,
          mcp: true,
          timezone: "Asia/Tehran",
        },
      };
    },
  };

  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.log = { info() {}, warn() {}, error() {} };
    next();
  });
  app.use(createRouter({
    analyzer: {},
    alertRepository: {},
    copilot,
  }));

  const server = app.listen(0);
  try {
    const { port } = server.address();
    const response = await fetch(`http://127.0.0.1:${port}/copilot/query`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message: "در 24 ساعت گذشته چند Alert داشتیم؟",
        history: [
          { role: "user", content: "امروز چند Alert داشتیم؟" },
          { role: "assistant", content: "امروز 10 Alert داشتیم." },
        ],
      }),
    });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.success, true);
    assert.equal(body.data.result.data.count, 42);
    assert.equal(body.data.metadata.mcp, true);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});


test("array-scoped aggregate filters are applied after unwind so unrelated IPs are not grouped", () => {
  const plan = socQueryPlanSchema.parse({
    dataset: "alerts",
    operation: "aggregate",
    filters: [
      {
        field: "soc.networkIntelligence.ips.threat.directMatch",
        operator: "eq",
        value: true,
      },
    ],
    groupBy: ["soc.networkIntelligence.ips.asset.organization"],
    metrics: [{ type: "count", alias: "count" }],
    sort: [{ field: "count", direction: "desc" }],
    limit: 10,
  });

  const compiled = compileSocQuery(plan, {
    resolvedTimeRange: { from: null, to: null, timezone: "Asia/Tehran", label: "all time" },
  });

  assert.deepEqual(compiled.pipeline, [
    {
      $unwind: {
        path: "$soc.networkIntelligence.ips",
        preserveNullAndEmptyArrays: false,
      },
    },
    {
      $match: {
        "soc.networkIntelligence.ips.threat.directMatch": true,
      },
    },
    {
      $group: {
        _id: {
          __document: "$_id",
          __group: "$soc.networkIntelligence.ips.asset.organization",
        },
      },
    },
    {
      $group: {
        _id: "$_id.__group",
        count: { $sum: 1 },
      },
    },
    {
      $project: {
        _id: 0,
        soc_networkIntelligence_ips_asset_organization: "$_id",
        count: 1,
      },
    },
    { $sort: { count: -1 } },
    { $limit: 10 },
  ]);
});


test("safe dynamic rawEvent fields are queryable while Mongo operator paths stay blocked", () => {
  const dynamicPlan = socQueryPlanSchema.parse({
    dataset: "alerts",
    operation: "count",
    filters: [
      {
        field: "rawEvent.destination_fqdn",
        operator: "contains",
        value: "example.ir",
      },
    ],
  });

  const compiled = compileSocQuery(dynamicPlan, {
    resolvedTimeRange: { from: null, to: null, timezone: "Asia/Tehran", label: "all time" },
  });

  assert.deepEqual(compiled.pipeline, [
    {
      $match: {
        "rawEvent.destination_fqdn": {
          $regex: "example\\.ir",
          $options: "i",
        },
      },
    },
    { $count: "count" },
  ]);

  const blockedPlan = socQueryPlanSchema.parse({
    dataset: "alerts",
    operation: "count",
    filters: [
      {
        field: "rawEvent.$where",
        operator: "eq",
        value: "x",
      },
    ],
  });

  assert.throws(
    () => compileSocQuery(blockedPlan, {
      resolvedTimeRange: { from: null, to: null, timezone: "Asia/Tehran", label: "all time" },
    }),
    /not allowed/,
  );
});


test("array-backed top values count unique source documents instead of duplicate array elements", () => {
  const plan = socQueryPlanSchema.parse({
    dataset: "alerts",
    operation: "aggregate",
    filters: [
      {
        field: "soc.networkIntelligence.ips.threat.directMatch",
        operator: "eq",
        value: true,
      },
    ],
    groupBy: ["soc.networkIntelligence.ips.asset.organization"],
    metrics: [{ type: "count", alias: "count" }],
    sort: [{ field: "count", direction: "desc" }],
    limit: 5,
  });

  const compiled = compileSocQuery(plan, {
    resolvedTimeRange: { from: null, to: null, timezone: "Asia/Tehran", label: "all time" },
  });

  assert.deepEqual(compiled.pipeline.slice(0, 4), [
    {
      $unwind: {
        path: "$soc.networkIntelligence.ips",
        preserveNullAndEmptyArrays: false,
      },
    },
    {
      $match: {
        "soc.networkIntelligence.ips.threat.directMatch": true,
      },
    },
    {
      $group: {
        _id: {
          __document: "$_id",
          __group: "$soc.networkIntelligence.ips.asset.organization",
        },
      },
    },
    {
      $group: {
        _id: "$_id.__group",
        count: { $sum: 1 },
      },
    },
  ]);
});


test("MCP batch tool executes multiple validated read-only queries", async () => {
  const calls = [];
  const server = new SocMcpServer({
    queryService: {
      async execute(args) {
        calls.push(args);
        return {
          dataset: args.dataset,
          operation: args.operation,
          data: { count: args.dataset === "alerts" ? 12 : 34, rows: [] },
        };
      },
    },
  });

  const client = new InProcessMcpClient({ server });
  const result = await client.callTool("query_soc_data_batch", {
    queries: [
      { dataset: "alerts", operation: "count" },
      { dataset: "ip_assets", operation: "count" },
    ],
  });

  assert.equal(result.count, 2);
  assert.equal(result.results[0].data.count, 12);
  assert.equal(result.results[1].data.count, 34);
  assert.equal(result.metadata.readOnly, true);
  assert.equal(calls.length, 2);
});

test("Copilot preserves bounded conversation history for follow-up planning", async () => {
  let plannerPrompt = "";
  const service = new CopilotService({
    llm: {
      getMetadata: () => ({ provider: "test", model: "test" }),
      async completeJson(request) {
        if (!plannerPrompt) {
          plannerPrompt = request.userPrompt;
          return {
            tool: "query_soc_data",
            arguments: {
              dataset: "alerts",
              operation: "count",
              filters: [{ field: "severity", operator: "eq", value: "high" }],
            },
          };
        }
        return { answer: "5 Alert" };
      },
    },
    mcpClient: {
      async listTools() { return []; },
      async callTool(name, args) {
        if (name === "describe_soc_schema") return { datasets: [] };
        return {
          dataset: "alerts",
          operation: "count",
          data: { count: 5, rows: [] },
          queryPlan: args,
        };
      },
    },
  });

  await service.query("حالا فقط high ها", {
    history: [
      { role: "user", content: "امروز چند Alert داشتیم؟" },
      { role: "assistant", content: "امروز 12 Alert داشتیم." },
    ],
  });

  assert.match(plannerPrompt, /امروز چند Alert داشتیم/);
  assert.match(plannerPrompt, /حالا فقط high ها/);
});
