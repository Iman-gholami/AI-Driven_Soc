const Alert = require("../models/Alert");

class AlertRepository {
  constructor({ alertModel = Alert } = {}) {
    this.alertModel = alertModel;
  }

  async create(alertRecord) {
    return this.alertModel.create(alertRecord);
  }

  async upsertNewAlert({ alertId, source, severity, rawEvent, eventHash, ruleMatch }) {
    const update = {
      $set: {
        alertId,
        source,
        severity: severity || "unknown",
        rawEvent,
        eventHash,
        ruleMatch,
        status: "new",
        aiStatus: "not_analyzed",
        analysis: undefined,
        fullAnalysis: undefined,
        llmProvider: undefined,
        model: undefined,
        processingTimeMs: undefined,
        soc: {
          mitreAttack: undefined,
          iocs: undefined,
          correlation: undefined,
          threatIntelligence: undefined,
          providerMetadata: undefined,
        },
        processing: {
          attempts: 0,
          startedAt: undefined,
          completedAt: undefined,
          failedAt: undefined,
          lastError: undefined,
          errors: undefined,
        },
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
    return this.alertModel.findOneAndUpdate(
      { $or: [{ alertId }, { eventHash }] },
      {
        $set: {
          alertId,
          source,
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
          "processing.completedAt": new Date(),
          "processing.failedAt": undefined,
          "processing.lastError": undefined,
        },
        $push: { analysis },
        $inc: { "processing.attempts": 1 },
      },
      { new: true, upsert: true, setDefaultsOnInsert: true },
    );
  }

  async listAlerts({ status, aiStatus, severity, createdAtFrom, createdAtTo, page = 1, limit = 50 } = {}) {
    const filters = buildListFilters({ status, aiStatus, severity, createdAtFrom, createdAtTo });
    const safePage = Math.max(Number(page) || 1, 1);
    const safeLimit = Math.min(Math.max(Number(limit) || 50, 1), 100);
    const skip = (safePage - 1) * safeLimit;

    const query = this.alertModel
      .find(filters)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(safeLimit)
      .select("alertId source status aiStatus severity analysis.severity ruleMatch createdAt updatedAt eventHash processing")
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
      sort: { createdAt: "desc" },
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
        $push: {
          "processing.errors": {
            at,
            message,
          },
        },
        $inc: { "processing.attempts": 1 },
      },
      { new: true },
    );
  }
}

function buildListFilters({ status, aiStatus, severity, createdAtFrom, createdAtTo } = {}) {
  const filters = {};

  if (status) filters.status = String(status);
  if (aiStatus) filters.aiStatus = String(aiStatus);
  if (severity) filters.severity = String(severity);

  if (createdAtFrom || createdAtTo) {
    filters.createdAt = {};
    if (createdAtFrom) filters.createdAt.$gte = new Date(createdAtFrom);
    if (createdAtTo) filters.createdAt.$lte = new Date(createdAtTo);
  }

  return filters;
}

module.exports = { AlertRepository, buildListFilters };
