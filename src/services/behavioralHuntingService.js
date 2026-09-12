const Alert = require("../models/Alert");

const DIMENSIONS = Object.freeze({
  signature: "signature",
  host: "host",
  source: "source",
  rule: "ruleMatch.ruleId",
});

class BehavioralHuntingService {
  constructor({ alertModel = Alert, now = () => new Date() } = {}) {
    this.alertModel = alertModel;
    this.now = now;
  }

  async scan({ dimension = "signature", hours = 24, baselineDays = 7, limit = 20 } = {}) {
    const field = DIMENSIONS[String(dimension || "")];
    if (!field) throw new BehavioralHuntingInputError("Unsupported behavioral dimension");

    const recentHours = clampInteger(hours, 1, 168, 24);
    const safeBaselineDays = clampInteger(baselineDays, 2, 90, 7);
    const safeLimit = clampInteger(limit, 1, 50, 20);
    const now = this.now();
    const recentFrom = new Date(now.getTime() - recentHours * 60 * 60 * 1000);
    const baselineTo = recentFrom;
    const baselineFrom = new Date(baselineTo.getTime() - safeBaselineDays * 24 * 60 * 60 * 1000);

    const [recentRows, baselineRows] = await Promise.all([
      this.alertModel.aggregate(buildCountPipeline({ field, from: recentFrom, to: now, limit: 500 })).exec(),
      this.alertModel.aggregate(buildCountPipeline({ field, from: baselineFrom, to: baselineTo, limit: 2000 })).exec(),
    ]);

    const baselineMap = new Map(
      baselineRows.map((row) => [String(row._id), Number(row.count || 0)]),
    );
    const baselineHours = safeBaselineDays * 24;

    const anomalies = recentRows
      .map((row) => {
        const key = String(row._id);
        const recentCount = Number(row.count || 0);
        const baselineCount = Number(baselineMap.get(key) || 0);
        const metrics = scoreBehaviorChange({
          recentCount,
          baselineCount,
          recentHours,
          baselineHours,
        });
        return {
          dimension: String(dimension),
          key,
          recentCount,
          baselineCount,
          expectedRecentCount: metrics.expectedRecentCount,
          ratio: metrics.ratio,
          standardizedDelta: metrics.standardizedDelta,
          anomalyScore: metrics.anomalyScore,
          classification: classifyBehaviorChange({ baselineCount, ...metrics }),
          huntGoal: buildHuntGoal({
            dimension: String(dimension),
            key,
            recentCount,
            expectedRecentCount: metrics.expectedRecentCount,
            recentHours,
          }),
        };
      })
      .filter((item) => item.recentCount >= 2)
      .filter((item) => item.baselineCount === 0 || item.ratio >= 1.5 || item.standardizedDelta >= 2)
      .sort((a, b) => b.anomalyScore - a.anomalyScore || b.recentCount - a.recentCount)
      .slice(0, safeLimit);

    return {
      dimension: String(dimension),
      window: {
        recentHours,
        recentFrom: recentFrom.toISOString(),
        recentTo: now.toISOString(),
        baselineDays: safeBaselineDays,
        baselineFrom: baselineFrom.toISOString(),
        baselineTo: baselineTo.toISOString(),
      },
      anomalies,
      count: anomalies.length,
      scoring: {
        method: "volume-normalized standardized delta plus lift",
        deterministic: true,
        note: "This is a prioritization signal, not a machine-learning verdict.",
      },
    };
  }
}

class BehavioralHuntingInputError extends Error {
  constructor(message) {
    super(message);
    this.name = "BehavioralHuntingInputError";
  }
}

function buildCountPipeline({ field, from, to, limit }) {
  return [
    {
      $addFields: {
        _behaviorEventTime: { $ifNull: ["$eventTime", "$createdAt"] },
      },
    },
    {
      $match: {
        _behaviorEventTime: { $gte: from, $lt: to },
      },
    },
    {
      $project: {
        key: `$${field}`,
      },
    },
    {
      $match: {
        key: { $nin: [null, ""] },
      },
    },
    {
      $group: {
        _id: "$key",
        count: { $sum: 1 },
      },
    },
    { $sort: { count: -1, _id: 1 } },
    { $limit: limit },
  ];
}

function scoreBehaviorChange({ recentCount, baselineCount, recentHours, baselineHours }) {
  const recent = Math.max(Number(recentCount) || 0, 0);
  const baseline = Math.max(Number(baselineCount) || 0, 0);
  const safeRecentHours = Math.max(Number(recentHours) || 1, 1);
  const safeBaselineHours = Math.max(Number(baselineHours) || 1, 1);
  const expected = baseline * (safeRecentHours / safeBaselineHours);
  const ratio = expected > 0 ? recent / expected : (recent > 0 ? null : 0);
  const standardizedDelta = (recent - expected) / Math.sqrt(expected + 1);

  let anomalyScore;
  if (baseline === 0) {
    if (recent >= 10) anomalyScore = 10;
    else if (recent >= 5) anomalyScore = 9;
    else if (recent >= 3) anomalyScore = 8;
    else if (recent >= 2) anomalyScore = 6;
    else anomalyScore = 0;
  } else {
    const zComponent = Math.min(Math.max(standardizedDelta, 0) / 10, 1) * 6;
    const lift = Math.max(Math.log2(Math.max(ratio || 0, 1)), 0);
    const liftComponent = Math.min(lift / 4, 1) * 4;
    anomalyScore = zComponent + liftComponent;
  }

  return {
    expectedRecentCount: round(expected, 2),
    ratio: ratio === null ? null : round(ratio, 2),
    standardizedDelta: round(standardizedDelta, 2),
    anomalyScore: round(Math.min(Math.max(anomalyScore, 0), 10), 1),
  };
}

function classifyBehaviorChange({ baselineCount, anomalyScore, ratio }) {
  if (baselineCount === 0 && anomalyScore >= 6) return "novel";
  if (anomalyScore >= 8) return "spike";
  if ((ratio || 0) >= 2 || anomalyScore >= 5) return "elevated";
  return "watch";
}

function buildHuntGoal({ dimension, key, recentCount, expectedRecentCount, recentHours }) {
  return `Investigate the unexpected ${dimension} activity for \"${key}\". It appeared ${recentCount} time(s) in the last ${recentHours} hour(s), while the normalized baseline expected about ${expectedRecentCount}. Determine whether the increase represents suspicious or malicious activity using SOC evidence.`;
}

function clampInteger(value, min, max, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(Math.max(Math.trunc(parsed), min), max);
}

function round(value, digits = 2) {
  const factor = 10 ** digits;
  return Math.round(Number(value || 0) * factor) / factor;
}

module.exports = {
  BehavioralHuntingService,
  BehavioralHuntingInputError,
  DIMENSIONS,
  buildCountPipeline,
  scoreBehaviorChange,
  classifyBehaviorChange,
  buildHuntGoal,
};
