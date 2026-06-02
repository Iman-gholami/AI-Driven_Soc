const Alert = require("../models/Alert");

class AlertRepository {
  constructor({ alertModel = Alert } = {}) {
    this.alertModel = alertModel;
  }

  async create(alertRecord) {
    return this.alertModel.create(alertRecord);
  }

  async upsertNewAlert({ alertId, source, severity, rawEvent, eventHash }) {
    const update = {
      $set: {
        alertId,
        source,
        severity: severity || "unknown",
        rawEvent,
        eventHash,
        status: "new",
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
          errors: undefined,
          completedAt: undefined,
        },
      },
    };

    return this.alertModel.findOneAndUpdate(
      { $or: [{ alertId }, { eventHash }] },
      update,
      { new: true, upsert: true, setDefaultsOnInsert: true },
    );
  }


  async upsertAnalyzedAlert({ alertId, source, severity, rawEvent, eventHash, analysis, fullAnalysis, soc, llmProvider, model, processingTimeMs }) {
    return this.alertModel.findOneAndUpdate(
      { $or: [{ alertId }, { eventHash }] },
      {
        $set: {
          alertId,
          source,
          severity,
          rawEvent,
          eventHash,
          analysis,
          severity: analysis?.severity || "unknown",
          fullAnalysis,
          soc,
          llmProvider,
          model,
          processingTimeMs,
          status: "analyzed",
          "processing.completedAt": new Date(),
        },
        $inc: { "processing.attempts": 1 },
      },
      { new: true, upsert: true, setDefaultsOnInsert: true },
    );
  }

  async listAlerts({ status, severity, createdAtFrom, createdAtTo, page = 1, limit = 50 } = {}) {
    const filters = buildListFilters({ status, severity, createdAtFrom, createdAtTo });
    const safePage = Math.max(Number(page) || 1, 1);
    const safeLimit = Math.min(Math.max(Number(limit) || 50, 1), 100);
    const skip = (safePage - 1) * safeLimit;

    const query = this.alertModel
      .find(filters)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(safeLimit)
      .select("alertId source status severity analysis.severity createdAt updatedAt eventHash")
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

  async updateAnalysis(alertId, { analysis, fullAnalysis, soc, llmProvider, model, processingTimeMs }) {
    return this.alertModel.findOneAndUpdate(
      { alertId },
      {
        $set: {
          analysis,
          severity: analysis?.severity || "unknown",
          fullAnalysis,
          soc,
          llmProvider,
          model,
          processingTimeMs,
          status: "analyzed",
          "processing.completedAt": new Date(),
        },
        $inc: { "processing.attempts": 1 },
      },
      { new: true },
    );
  }
}

function buildListFilters({ status, severity, createdAtFrom, createdAtTo } = {}) {
  const filters = {};

  if (status) filters.status = String(status);
  if (severity) filters.severity = String(severity);

  if (createdAtFrom || createdAtTo) {
    filters.createdAt = {};
    if (createdAtFrom) filters.createdAt.$gte = new Date(createdAtFrom);
    if (createdAtTo) filters.createdAt.$lte = new Date(createdAtTo);
  }

  return filters;
}

module.exports = { AlertRepository, buildListFilters };
