require("dotenv").config();

const { settings } = require("../src/core/config");
const { createLogger } = require("../src/core/logging");
const { connectMongo, disconnectMongo } = require("../src/database/mongo");
const { SocQueryService } = require("../src/services/socQueryService");

const logger = createLogger(settings.logLevel);

async function main() {
  const connected = await connectMongo(logger);
  if (!connected) {
    throw new Error("MongoDB is required for the Copilot smoke test");
  }

  const service = new SocQueryService();

  const cases = [
    {
      name: "alerts_last_24_hours",
      plan: {
        dataset: "alerts",
        operation: "count",
        timeRange: { type: "last_n_hours", value: 24 },
      },
    },
    {
      name: "top_signature_last_7_days",
      plan: {
        dataset: "alerts",
        operation: "aggregate",
        timeRange: { type: "last_n_days", value: 7 },
        groupBy: ["signature"],
        metrics: [{ type: "count", alias: "count" }],
        sort: [{ field: "count", direction: "desc" }],
        limit: 1,
      },
    },
    {
      name: "syn_flood_today",
      plan: {
        dataset: "alerts",
        operation: "count",
        timeRange: { type: "today" },
        filters: [
          {
            field: "signature",
            operator: "contains",
            value: "syn flood",
          },
        ],
      },
    },
  ];

  const output = [];
  for (const item of cases) {
    const result = await service.execute(item.plan);
    output.push({
      name: item.name,
      queryPlan: result.queryPlan,
      timeRange: result.timeRange,
      data: result.data,
      metadata: result.metadata,
    });
  }

  process.stdout.write(JSON.stringify({
    success: true,
    timezone: settings.socTimezone,
    weekStart: settings.socWeekStart,
    results: output,
  }, null, 2) + "\n");
}

main()
  .catch((error) => {
    process.stderr.write(JSON.stringify({
      success: false,
      error: String(error?.message || error),
    }, null, 2) + "\n");
    process.exitCode = 1;
  })
  .finally(async () => {
    await disconnectMongo(logger);
  });
