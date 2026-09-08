const { settings } = require("../core/config");
const { socQueryPlanSchema } = require("../copilot/querySchema");
const { getDatasetSchema, SOC_SCHEMA_VERSION } = require("../copilot/schemaCatalog");
const { createDefaultDatasetRegistry } = require("../copilot/datasetRegistry");
const { resolveTimeRange } = require("../copilot/timeRange");
const { compileSocQuery } = require("../copilot/queryCompiler");

class SocQueryService {
  constructor({
    registry = createDefaultDatasetRegistry(),
    timezone = settings.socTimezone || "Asia/Tehran",
    now = () => new Date(),
  } = {}) {
    this.registry = registry;
    this.timezone = timezone;
    this.now = now;
  }

  async execute(inputPlan) {
    const plan = socQueryPlanSchema.parse(inputPlan);
    const datasetSchema = getDatasetSchema(plan.dataset);
    const dataset = this.registry[plan.dataset];

    if (!datasetSchema || !dataset?.model) {
      throw new Error(`Dataset "${plan.dataset}" is not available`);
    }

    const baseContext = dataset.getBaseContext
      ? await dataset.getBaseContext()
      : { match: {}, metadata: {} };

    const resolvedTimeRange = resolveTimeRange(plan.timeRange, {
      now: this.now(),
      timezone: this.timezone,
    });

    const compiled = compileSocQuery(plan, {
      resolvedTimeRange,
      baseMatch: baseContext?.match || {},
    });

    const aggregation = dataset.model.aggregate(compiled.pipeline);
    if (typeof aggregation.allowDiskUse === "function") aggregation.allowDiskUse(true);
    const rows = typeof aggregation.exec === "function"
      ? await aggregation.exec()
      : await aggregation;

    return {
      dataset: plan.dataset,
      operation: plan.operation,
      timeRange: {
        field: plan.timeRange?.field || datasetSchema.defaultTimeField || null,
        from: resolvedTimeRange.from ? resolvedTimeRange.from.toISOString() : null,
        to: resolvedTimeRange.to ? resolvedTimeRange.to.toISOString() : null,
        timezone: resolvedTimeRange.timezone,
        label: resolvedTimeRange.label,
      },
      data: normalizeResult(compiled.resultShape, rows),
      metadata: {
        readOnly: true,
        schemaVersion: SOC_SCHEMA_VERSION,
        ...(baseContext?.metadata || {}),
      },
      queryPlan: plan,
    };
  }
}

function normalizeResult(shape, rows) {
  const safeRows = Array.isArray(rows) ? rows : [];

  if (shape === "count") {
    return {
      count: Number(safeRows[0]?.count || 0),
      rows: [],
    };
  }

  return {
    count: safeRows.length,
    rows: safeRows,
  };
}

module.exports = {
  SocQueryService,
  normalizeResult,
};
