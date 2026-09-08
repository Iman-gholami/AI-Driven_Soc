const { settings } = require("../core/config");
const { SocQueryService } = require("./socQueryService");
const { resolveTimeRange } = require("../copilot/timeRange");

class SocMetricService {
  constructor({
    queryService = new SocQueryService(),
    timezone = settings.socTimezone || "Asia/Tehran",
    weekStart = settings.socWeekStart || "saturday",
    now = () => new Date(),
  } = {}) {
    this.queryService = queryService;
    this.timezone = timezone;
    this.weekStart = weekStart;
    this.now = now;
  }

  async analyze(input = {}) {
    const operation = String(input.operation || "").trim();

    if (operation === "compare") return this.compare(input);
    if (operation === "percentage") return this.percentage(input);
    if (operation === "trend") return this.trend(input);

    throw new Error("Unsupported SOC metric operation: " + operation);
  }

  async compare(input) {
    const left = normalizeLabeledCountQuery(input.left, "left");
    const right = normalizeLabeledCountQuery(input.right, "right");

    const [leftResult, rightResult] = await Promise.all([
      this.queryService.execute(left.query),
      this.queryService.execute(right.query),
    ]);

    const leftCount = Number(leftResult.data?.count || 0);
    const rightCount = Number(rightResult.data?.count || 0);
    const difference = leftCount - rightCount;
    const changePercent = rightCount === 0
      ? null
      : round((difference / rightCount) * 100, 2);

    return {
      operation: "compare",
      left: {
        label: left.label,
        count: leftCount,
        result: leftResult,
      },
      right: {
        label: right.label,
        count: rightCount,
        result: rightResult,
      },
      difference,
      changePercent,
      metadata: {
        readOnly: true,
        deterministicCalculation: true,
      },
    };
  }

  async percentage(input) {
    const numerator = normalizeLabeledCountQuery(input.numerator, "numerator");
    const denominator = normalizeLabeledCountQuery(input.denominator, "denominator");

    const [numeratorResult, denominatorResult] = await Promise.all([
      this.queryService.execute(numerator.query),
      this.queryService.execute(denominator.query),
    ]);

    const numeratorCount = Number(numeratorResult.data?.count || 0);
    const denominatorCount = Number(denominatorResult.data?.count || 0);
    const percentage = denominatorCount === 0
      ? null
      : round((numeratorCount / denominatorCount) * 100, 2);

    return {
      operation: "percentage",
      numerator: {
        label: numerator.label,
        count: numeratorCount,
        result: numeratorResult,
      },
      denominator: {
        label: denominator.label,
        count: denominatorCount,
        result: denominatorResult,
      },
      percentage,
      metadata: {
        readOnly: true,
        deterministicCalculation: true,
      },
    };
  }

  async trend(input) {
    const baseQuery = normalizeCountQuery(input.query, "query");
    const bucket = String(input.bucket || "day").trim().toLowerCase();
    if (!["hour", "day"].includes(bucket)) {
      throw new Error("trend.bucket must be hour or day");
    }

    const range = resolveTimeRange(input.timeRange, {
      now: this.now(),
      timezone: this.timezone,
      weekStart: this.weekStart,
    });

    if (!range.from || !range.to) {
      throw new Error("trend requires a bounded timeRange");
    }

    const bucketMs = bucket === "hour" ? 60 * 60 * 1000 : 24 * 60 * 60 * 1000;
    const totalMs = range.to.getTime() - range.from.getTime();
    const pointCount = Math.ceil(totalMs / bucketMs);
    const maxPoints = bucket === "hour" ? 48 : 60;

    if (pointCount <= 0 || pointCount > maxPoints) {
      throw new Error(`trend would create ${pointCount} points; maximum for ${bucket} buckets is ${maxPoints}`);
    }

    const points = [];
    for (let index = 0; index < pointCount; index += 1) {
      const from = new Date(range.from.getTime() + index * bucketMs);
      const to = new Date(Math.min(from.getTime() + bucketMs, range.to.getTime()));
      const query = {
        ...baseQuery,
        timeRange: {
          type: "between",
          from: from.toISOString(),
          to: to.toISOString(),
          ...(baseQuery.timeRange?.field ? { field: baseQuery.timeRange.field } : {}),
        },
      };

      const result = await this.queryService.execute(query);
      points.push({
        from: from.toISOString(),
        to: to.toISOString(),
        count: Number(result.data?.count || 0),
      });
    }

    return {
      operation: "trend",
      dataset: baseQuery.dataset,
      bucket,
      timeRange: {
        from: range.from.toISOString(),
        to: range.to.toISOString(),
        timezone: range.timezone,
        label: range.label,
      },
      points,
      metadata: {
        readOnly: true,
        deterministicCalculation: true,
        pointCount: points.length,
      },
    };
  }
}

function normalizeLabeledCountQuery(value, label) {
  if (!value || typeof value !== "object") {
    throw new Error(label + " count query is required");
  }

  return {
    label: String(value.label || label).slice(0, 200),
    query: normalizeCountQuery(value.query, label + ".query"),
  };
}

function normalizeCountQuery(query, label) {
  if (!query || typeof query !== "object") {
    throw new Error(label + " is required");
  }

  if (query.operation !== "count") {
    throw new Error(label + " must use operation=count");
  }

  return {
    ...query,
    operation: "count",
  };
}

function round(value, digits) {
  const factor = 10 ** digits;
  return Math.round((Number(value) + Number.EPSILON) * factor) / factor;
}

module.exports = {
  SocMetricService,
  normalizeCountQuery,
  normalizeLabeledCountQuery,
  round,
};
