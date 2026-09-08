const assert = require("node:assert/strict");
const test = require("node:test");

const { socQueryPlanSchema } = require("../src/copilot/querySchema");
const { compileSocQuery } = require("../src/copilot/queryCompiler");
const { resolveTimeRange } = require("../src/copilot/timeRange");
const { SocMcpServer } = require("../src/mcp/socMcpServer");
const { InProcessMcpClient } = require("../src/mcp/inProcessClient");
const {
  CopilotService,
  buildUnsupportedAnswer,
} = require("../src/services/copilotService");
const {
  getFieldSchema,
  registerDiscoveredFields,
  describeSocSchema,
} = require("../src/copilot/schemaCatalog");
const {
  deriveConversationState,
} = require("../src/copilot/conversationState");
const { SocMetricService } = require("../src/services/socMetricService");
const { buildAlertTimeMatch } = require("../src/services/socCorrelationService");

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
    "correlate_soc_entities",
    "analyze_soc_metric",
    "get_soc_entity_context",
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


test("list queries require an explicit minimal projection", () => {
  const plan = socQueryPlanSchema.parse({
    dataset: "alerts",
    operation: "list",
    filters: [],
    limit: 10,
  });

  assert.throws(
    () => compileSocQuery(plan, {
      resolvedTimeRange: { from: null, to: null, timezone: "Asia/Tehran", label: "all time" },
    }),
    /requires at least one selected field/,
  );
});


test("registered Mongoose datasets automatically expose newly added safe schema fields", () => {
  const fakeModel = {
    schema: {
      paths: {
        futureBooleanField: { instance: "Boolean", path: "futureBooleanField" },
        futureScore: { instance: "Number", path: "futureScore" },
        futureTags: {
          instance: "Array",
          path: "futureTags",
          caster: { instance: "String" },
        },
        _id: { instance: "ObjectId", path: "_id" },
      },
    },
  };

  const added = registerDiscoveredFields("detection_rules", fakeModel);

  assert.equal(added, 3);
  assert.equal(getFieldSchema("detection_rules", "futureBooleanField").type, "boolean");
  assert.equal(getFieldSchema("detection_rules", "futureScore").type, "number");
  assert.equal(getFieldSchema("detection_rules", "futureTags").unwind, "futureTags");
  assert.equal(getFieldSchema("detection_rules", "_id"), null);
});


test("unsupported Copilot answers are localized to the analyst language", () => {
  assert.match(buildUnsupportedAnswer("هوا خوبه؟"), /این سؤال با داده‌های فعلی SOC قابل پاسخ نیست/);
  assert.match(buildUnsupportedAnswer("is the weather good?"), /cannot be answered from the current SOC data/i);
});

test("answer formatter prompt avoids raw UTC timestamps unless explicitly requested", () => {
  const { ANSWER_SYSTEM_PROMPT } = require("../src/copilot/prompts");
  assert.match(ANSWER_SYSTEM_PROMPT, /Do not print raw ISO\/UTC timestamps/);
});


test("Copilot state focuses the alert returned by a latest-alert query", () => {
  const state = deriveConversationState({
    previousState: {},
    tool: "query_soc_data",
    queryPlan: {
      dataset: "alerts",
      operation: "list",
      select: ["alertId", "signature"],
      limit: 1,
    },
    result: {
      dataset: "alerts",
      operation: "list",
      data: {
        count: 1,
        rows: [
          {
            alertId: "alert-latest-1",
            signature: "Example Signature",
            rawEvent: {
              src_ip: "151.234.175.98",
              dst_ip: "10.0.0.190",
            },
          },
        ],
      },
    },
  });

  assert.deepEqual(state.focus, {
    entityType: "alert",
    id: "alert-latest-1",
  });
  assert.equal(state.relatedEntities.sourceIp, "151.234.175.98");
  assert.equal(state.relatedEntities.destinationIp, "10.0.0.190");
});

test("MCP exposes grounded focused-entity investigation context", async () => {
  const server = new SocMcpServer({
    queryService: { async execute() { return {}; } },
    metricService: { async analyze() { return {}; } },
    correlationService: { async correlate() { return {}; } },
    entityContextService: {
      async getContext(args) {
        assert.deepEqual(args, { entityType: "alert", id: "a-1" });
        return {
          entity: { type: "alert", id: "a-1" },
          analysis: { verdict: "MALICIOUS" },
          relatedEntities: {
            sourceIp: "151.234.175.98",
            destinationIp: "10.0.0.190",
          },
        };
      },
    },
  });

  const client = new InProcessMcpClient({ server });
  const result = await client.callTool("get_soc_entity_context", {
    entityType: "alert",
    id: "a-1",
  });

  assert.equal(result.entity.id, "a-1");
  assert.equal(result.analysis.verdict, "MALICIOUS");
  assert.equal(result.relatedEntities.destinationIp, "10.0.0.190");
});

test("SOC metric compare and percentage calculations are deterministic", async () => {
  const counts = [15, 10, 4, 20];
  const queryService = {
    async execute(query) {
      assert.equal(query.operation, "count");
      return {
        dataset: query.dataset,
        operation: "count",
        data: { count: counts.shift(), rows: [] },
      };
    },
  };

  const service = new SocMetricService({ queryService });

  const compared = await service.analyze({
    operation: "compare",
    left: { label: "this week", query: { dataset: "alerts", operation: "count" } },
    right: { label: "previous week", query: { dataset: "alerts", operation: "count" } },
  });

  assert.equal(compared.difference, 5);
  assert.equal(compared.changePercent, 50);

  const percentage = await service.analyze({
    operation: "percentage",
    numerator: { label: "high", query: { dataset: "alerts", operation: "count" } },
    denominator: { label: "all", query: { dataset: "alerts", operation: "count" } },
  });

  assert.equal(percentage.percentage, 20);
});

test("alert correlation time filters use eventTime with createdAt fallback", () => {
  const from = new Date("2026-09-01T00:00:00.000Z");
  const to = new Date("2026-09-08T00:00:00.000Z");
  assert.deepEqual(buildAlertTimeMatch({ from, to }), {
    $expr: {
      $and: [
        {
          $gte: [
            { $ifNull: ["$eventTime", "$createdAt"] },
            from,
          ],
        },
        {
          $lt: [
            { $ifNull: ["$eventTime", "$createdAt"] },
            to,
          ],
        },
      ],
    },
  });
});

test("SOC schema describes relationships and semantic concepts", () => {
  const schema = describeSocSchema();
  assert.ok(Array.isArray(schema.relationships));
  assert.ok(schema.relationships.some((item) => item.name === "alert_source_ip_to_threat_source"));
  assert.ok(Array.isArray(schema.concepts));
  assert.ok(schema.concepts.some((item) => item.name === "organization"));
});

test("alert time-range compilation falls back from eventTime to createdAt", () => {
  const plan = socQueryPlanSchema.parse({
    dataset: "alerts",
    operation: "count",
    timeRange: { type: "last_n_hours", value: 24 },
  });
  const from = new Date("2026-09-07T10:00:00.000Z");
  const to = new Date("2026-09-08T10:00:00.000Z");

  const compiled = compileSocQuery(plan, {
    resolvedTimeRange: {
      from,
      to,
      timezone: "Asia/Tehran",
      label: "last 24 hours",
    },
  });

  assert.deepEqual(compiled.pipeline, [
    {
      $match: {
        $expr: {
          $and: [
            {
              $gte: [
                { $ifNull: ["$eventTime", "$createdAt"] },
                from,
              ],
            },
            {
              $lt: [
                { $ifNull: ["$eventTime", "$createdAt"] },
                to,
              ],
            },
          ],
        },
      },
    },
    { $count: "count" },
  ]);
});

test("Copilot retries one rejected query plan with backend validation feedback", async () => {
  const completions = [];
  const toolCalls = [];

  const llm = {
    getMetadata: () => ({ provider: "test", model: "repair-model" }),
    async completeJson(request) {
      completions.push(request);

      if (completions.length === 1) {
        return {
          tool: "query_soc_data",
          arguments: {
            dataset: "alerts",
            operation: "count",
            filters: [
              { field: "source_ip", operator: "eq", value: "1.2.3.4" },
            ],
          },
        };
      }

      if (completions.length === 2) {
        assert.match(request.userPrompt, /previous plan was rejected/i);
        assert.match(request.userPrompt, /source_ip/);
        return {
          tool: "query_soc_data",
          arguments: {
            dataset: "alerts",
            operation: "count",
            filters: [
              { field: "rawEvent.src_ip", operator: "eq", value: "1.2.3.4" },
            ],
          },
        };
      }

      return { answer: "یک Alert پیدا شد." };
    },
  };

  const mcpClient = {
    async listTools() {
      return [{ name: "query_soc_data", description: "query", inputSchema: {} }];
    },
    async callTool(name, args) {
      if (name === "describe_soc_schema") {
        return {
          datasets: [
            {
              name: "alerts",
              fields: [{ name: "rawEvent.src_ip" }],
            },
          ],
        };
      }

      toolCalls.push({ name, args });
      if (toolCalls.length === 1) {
        throw new Error('Field "source_ip" is not allowed for dataset "alerts"');
      }

      return {
        dataset: "alerts",
        operation: "count",
        data: { count: 1, rows: [] },
        queryPlan: args,
      };
    },
  };

  const service = new CopilotService({
    llm,
    mcpClient,
    now: () => new Date("2026-09-08T10:00:00.000Z"),
  });

  const response = await service.query("از آی‌پی 1.2.3.4 چند Alert داشتیم؟");

  assert.equal(response.result.data.count, 1);
  assert.equal(response.metadata.plannerRepair.attempted, true);
  assert.equal(response.metadata.plannerRepair.succeeded, true);
  assert.equal(toolCalls.length, 2);
  assert.equal(completions.length, 3);
});
