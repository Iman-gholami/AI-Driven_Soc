const Alert = require("../models/Alert");
const { resolveAlertEventTime } = require("../services/eventTime");

class AlertRepository {
  constructor({ alertModel = Alert } = {}) {
    this.alertModel = alertModel;
  }

  async create(alertRecord) {
    return this.alertModel.create(alertRecord);
  }

  async upsertNewAlert({ alertId, source, severity, rawEvent, eventHash, ruleMatch }) {
    const now = new Date();
    const update = {
      $set: {
        alertId,
        source,
        signature: getRawSignature(rawEvent),
        eventType: rawEvent?.eventtype ? String(rawEvent.eventtype) : undefined,
        host: rawEvent?.host ? String(rawEvent.host) : undefined,
        eventTime: resolveAlertEventTime(rawEvent, now),
        severity: severity || "unknown",
        rawEvent,
        eventHash,
        ruleMatch,
        "processing.lastIngestedAt": now,
      },
      $setOnInsert: {
        status: "new",
        aiStatus: "not_analyzed",
        analysis: [],
        soc: {},
        "processing.attempts": 0,
      },
    };

    return this.alertModel.findOneAndUpdate(
      { $or: [{ alertId }, { eventHash }] },
      update,
      { new: true, upsert: true, setDefaultsOnInsert: true },
    );
  }

  async upsertAnalyzedAlert({
    alertId,
    source,
    severity,
    rawEvent,
    eventHash,
    analysis,
    fullAnalysis,
    ruleMatch,
    soc,
    llmProvider,
    model,
    processingTimeMs,
  }) {
    const now = new Date();
    return this.alertModel.findOneAndUpdate(
      { $or: [{ alertId }, { eventHash }] },
      {
        $set: {
          alertId,
          source,
          signature: getRawSignature(rawEvent),
          eventType: rawEvent?.eventtype ? String(rawEvent.eventtype) : undefined,
          host: rawEvent?.host ? String(rawEvent.host) : undefined,
          eventTime: resolveAlertEventTime(rawEvent, now),
          rawEvent,
          eventHash,
          ruleMatch,
          severity: analysis?.severity || severity || "unknown",
          fullAnalysis,
          soc,
          llmProvider,
          model,
          processingTimeMs,
          status: "analyzed",
          aiStatus: "analyzed",
          "processing.completedAt": now,
          "processing.failedAt": undefined,
          "processing.lastError": undefined,
        },
        $push: { analysis },
        $inc: { "processing.attempts": 1 },
      },
      { new: true, upsert: true, setDefaultsOnInsert: true },
    );
  }

  async listAlerts({
    status,
    aiStatus,
    severity,
    source,
    search,
    createdAtFrom,
    createdAtTo,
    page = 1,
    limit = 50,
    sortBy = "eventTime",
    sortDirection = "desc",
  } = {}) {
    const filters = buildListFilters({
      status,
      aiStatus,
      severity,
      source,
      search,
      createdAtFrom,
      createdAtTo,
    });
    const safePage = Math.max(Number(page) || 1, 1);
    const safeLimit = Math.min(Math.max(Number(limit) || 50, 1), 100);
    const skip = (safePage - 1) * safeLimit;
    const safeSortBy = ["eventTime", "createdAt", "updatedAt", "alertId", "severity", "source"].includes(sortBy)
      ? sortBy
      : "eventTime";
    const direction = String(sortDirection).toLowerCase() === "asc" ? 1 : -1;
    const sort = { [safeSortBy]: direction };

    const query = this.alertModel
      .find(filters)
      .sort(sort)
      .skip(skip)
      .limit(safeLimit)
      .select("alertId source signature eventType host status aiStatus severity analysis ruleMatch rawEvent.signature rawEvent.Signature rawEvent.rule_name rawEvent.eventtype rawEvent.host createdAt updatedAt eventHash processing processingTimeMs fullAnalysis.risk_assessment fullAnalysis.attack_mapping")
      .lean();

    const [alerts, total] = await Promise.all([
      query.exec(),
      this.alertModel.countDocuments(filters),
    ]);

    return {
      alerts,
      pagination: {
        page: safePage,
        limit: safeLimit,
        total,
        pages: Math.ceil(total / safeLimit),
      },
      filters,
      sort: {[safeSortBy]: direction === 1 ? "asc" : "desc"},
    };
  }

  async getDashboardStats({ createdAtFrom, createdAtTo, recentLimit = 8 } = {}) {
    const match = buildDateFilter(createdAtFrom, createdAtTo);
    const safeRecentLimit = Math.min(Math.max(Number(recentLimit) || 8, 1), 20);

    const [summaryRows, sourceRows, mitreRows, recentAlerts] = await Promise.all([
      this.alertModel.aggregate([
        { $match: match },
        {
          $group: {
            _id: null,
            total: { $sum: 1 },
            critical: { $sum: { $cond: [{ $eq: ["$severity", "critical"] }, 1, 0] } },
            high: { $sum: { $cond: [{ $eq: ["$severity", "high"] }, 1, 0] } },
            medium: { $sum: { $cond: [{ $eq: ["$severity", "medium"] }, 1, 0] } },
            low: { $sum: { $cond: [{ $eq: ["$severity", "low"] }, 1, 0] } },
            info: { $sum: { $cond: [{ $eq: ["$severity", "info"] }, 1, 0] } },
            unknown: {
              $sum: {
                $cond: [
                  { $in: [{ $ifNull: ["$severity", "unknown"] }, ["critical", "high", "medium", "low", "info"]] },
                  0,
                  1,
                ],
              },
            },
            analyzed: { $sum: { $cond: [{ $eq: ["$aiStatus", "analyzed"] }, 1, 0] } },
            analyzing: { $sum: { $cond: [{ $eq: ["$aiStatus", "analyzing"] }, 1, 0] } },
            failed: { $sum: { $cond: [{ $eq: ["$aiStatus", "failed"] }, 1, 0] } },
            notAnalyzed: {
              $sum: {
                $cond: [
                  { $in: [{ $ifNull: ["$aiStatus", "not_analyzed"] }, ["analyzed", "analyzing", "failed"]] },
                  0,
                  1,
                ],
              },
            },
            matchedRules: { $sum: { $cond: [{ $eq: ["$ruleMatch.status", "matched"] }, 1, 0] } },
            avgProcessingTimeMs: { $avg: "$processingTimeMs" },
            hosts: { $addToSet: "$host" },
          },
        },
        {
          $project: {
            _id: 0,
            total: 1,
            critical: 1,
            high: 1,
            medium: 1,
            low: 1,
            info: 1,
            unknown: 1,
            analyzed: 1,
            analyzing: 1,
            failed: 1,
            notAnalyzed: 1,
            matchedRules: 1,
            avgProcessingTimeMs: { $ifNull: ["$avgProcessingTimeMs", 0] },
            uniqueHosts: {
              $size: {
                $filter: {
                  input: "$hosts",
                  as: "host",
                  cond: {
                    $and: [
                      { $ne: ["$$host", null] },
                      { $ne: ["$$host", ""] },
                    ],
                  },
                },
              },
            },
          },
        },
      ]).exec(),
      this.alertModel.aggregate([
        { $match: match },
        {
          $group: {
            _id: { $ifNull: ["$source", "unknown"] },
            count: { $sum: 1 },
          },
        },
        { $sort: { count: -1, _id: 1 } },
        { $limit: 12 },
        { $project: { _id: 0, name: "$_id", count: 1 } },
      ]).exec(),
      this.alertModel.aggregate([
        { $match: { ...match, aiStatus: "analyzed" } },
        {
          $project: {
            alertId: 1,
            attackMapping: {
              $cond: [
                { $isArray: "$fullAnalysis.attack_mapping" },
                "$fullAnalysis.attack_mapping",
                [],
              ],
            },
          },
        },
        { $unwind: "$attackMapping" },
        {
          $project: {
            alertId: 1,
            technique: {
              $ifNull: ["$attackMapping.technique", "$attackMapping.id"],
            },
          },
        },
        { $match: { technique: { $nin: [null, ""] } } },
        {
          $group: {
            _id: null,
            techniques: { $addToSet: "$technique" },
            mappedAlerts: { $addToSet: "$alertId" },
          },
        },
        {
          $project: {
            _id: 0,
            techniqueCount: { $size: "$techniques" },
            mappedAlertCount: { $size: "$mappedAlerts" },
          },
        },
      ]).exec(),
      this.alertModel
        .find(match)
        .sort({ createdAt: -1 })
        .limit(safeRecentLimit)
        .select("alertId source signature eventType host status aiStatus severity analysis ruleMatch rawEvent.signature rawEvent.Signature rawEvent.rule_name rawEvent.eventtype rawEvent.host createdAt updatedAt eventHash processing processingTimeMs fullAnalysis.risk_assessment fullAnalysis.attack_mapping")
        .lean()
        .exec(),
    ]);

    const summary = summaryRows[0] || emptyDashboardSummary();
    const mitre = mitreRows[0] || { techniqueCount: 0, mappedAlertCount: 0 };

    return {
      summary,
      sources: sourceRows,
      mitre,
      recentAlerts,
      window: {
        from: createdAtFrom || null,
        to: createdAtTo || null,
      },
    };
  }

  async findByAlertId(alertId) {
    return this.alertModel.findOne({ alertId }).lean().exec();
  }

  async markAnalysisStarted(alertId) {
    return this.alertModel.findOneAndUpdate(
      {
        alertId,
        aiStatus: { $ne: "analyzing" },
      },
      {
        $set: {
          aiStatus: "analyzing",
          "processing.startedAt": new Date(),
          "processing.failedAt": undefined,
          "processing.lastError": undefined,
        },
      },
      { new: true },
    );
  }

  async updateAnalysis(alertId, {
    analysis,
    fullAnalysis,
    ruleMatch,
    soc,
    llmProvider,
    model,
    processingTimeMs,
  }) {
    return this.alertModel.findOneAndUpdate(
     { alertId },
     {
      $set: {
        ruleMatch,
        severity: analysis?.severity || "unknown",
        fullAnalysis,
        soc,
        llmProvider,
        model,
        processingTimeMs,
        status: "analyzed",
        aiStatus: "analyzed",
        "processing.completedAt": new Date(),
        "processing.failedAt": undefined,
        "processing.lastError": undefined,
      },
      $push: { analysis },
      $inc: { "processing.attempts": 1 },
    },
    { new: true },
  );
  }

  async markAnalysisFailed(alertId, error) {
    const message = String(error?.message || error || "Unknown analysis error").slice(0, 2000);
    const at = new Date();

    return this.alertModel.findOneAndUpdate(
     { alertId },
     {
      $set: {
        aiStatus: "failed",
        "processing.failedAt": at,
        "processing.lastError": message,
      },
      $push: { "processing.errors": { at, message } },
      $inc: { "processing.attempts": 1 },
    },
    { new: true },
   );
  }
}

function getRawSignature(rawEvent) {
  const value = rawEvent?.signature || rawEvent?.Signature || rawEvent?.rule_name || rawEvent?.ruleName;
  return value ? String(value).trim() : undefined;
}

function buildListFilters({
  status,
  aiStatus,
  severity,
  source,
  search,
  createdAtFrom,
  createdAtTo,
} = {}) {
  const filters = buildDateFilter(createdAtFrom, createdAtTo);
  const clauses = [];

  if (status) filters.status = String(status);
  if (severity) filters.severity = String(severity);
  if (source) filters.source = String(source);

  if (aiStatus === "not_analyzed") {
    clauses.push({
      $or : [
        { aiStatus: "not_analyzed" },
        { aiStatus: { $exists: false }, fullAnalysis: { $exists: false } },
      ],
    });
  } else if (aiStatus === "analyzed") {
    clauses.push({
      $or : [
        { aiStatus: "analyzed" },
        { aiStatus: { $exists: false }, fullAnalysis: { $exists: true } },
      ],
    });
  } else if (aiStatus) {
    filters.aiStatus = String(aiStatus);
  }

  if (search) {
    const expression = new RegExp(escapeRegex(String(search).trim()), "i");
    clauses.push({
      $or: [
        { alertId: expression },
        { signature: expression },
        { host: expression },
        { source: expression },
        { eventType: expression },
      ],
    });
  }

  if (clauses.length > 0) filters.$and = clauses;
  return filters;
}

function buildDateFilter(createdAtFrom, createdAtTo) {
  const filters = {};
  if (createdAtFrom || createdAtTo) {
    filters.createdAt = {};
    if (createdAtFrom) filters.createdAt.$gte = new Date(createdAtFrom);
    if (createdAtTo) filters.createdAt.$lte = new Date(createdAtTo);
  }
  return filters;
}

function emptyDashboardSummary() {
  return {
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    unknown: 0,
    analyzed: 0,
    analyzing: 0,
    failed: 0,
    notAnalyzed: 0,
    matchedRules: 0,
    avgProcessingTimeMs: 0,
    uniqueHosts: 0,
  };
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

module.exports = {
  AlertRepository,
  buildListFilters,
  buildDateFilter,
};
