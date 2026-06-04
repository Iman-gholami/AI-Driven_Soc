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
      },
      $setOnInsert: {
        analysisCount: 0,
        latestAnalysisId: undefined,
        lastAnalyzedAt: undefined,
        processing: { attempts: 0 },
      },
    };

    return this.alertModel.findOneAndUpdate(
      { $or: [{ alertId }, { eventHash }] },
      update,
      { new: true, upsert: true, setDefaultsOnInsert: true },
    );
  }

  async upsertAnalyzedAlert({ alertId, source, severity, rawEvent, eventHash }) {
    return this.alertModel.findOneAndUpdate(
      { $or: [{ alertId }, { eventHash }] },
      {
        $set: {
          alertId,
          source,
          severity: severity || "unknown",
          rawEvent,
          eventHash,
          status: "analyzed",
        },
        $setOnInsert: {
          analysisCount: 0,
          processing: { attempts: 0 },
        },
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
      .select("alertId source status severity latestAnalysisId analysisCount lastAnalyzedAt createdAt updatedAt eventHash")
      .populate({ path: "latestAnalysisId", select: "analysis fullAnalysis llmProvider model processingTimeMs soc processing createdAt updatedAt" })
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

  async updateLatestAnalysisReference(alertId, { analysisId, severity, analyzedAt = new Date(), attemptNumber } = {}) {
    return this.alertModel.findOneAndUpdate(
      { alertId },
      {
        $set: {
          latestAnalysisId: analysisId,
          severity: severity || "unknown",
          status: "analyzed",
          lastAnalyzedAt: analyzedAt,
          "processing.completedAt": analyzedAt,
          ...(attemptNumber ? { "processing.attempts": attemptNumber } : {}),
        },
      },
      { new: true },
    ).lean().exec();
  }

  async incrementAnalysisCount(alertId) {
    return this.alertModel.findOneAndUpdate(
      { alertId },
      { $inc: { analysisCount: 1, "processing.attempts": 1 } },
      { new: true },
    ).lean().exec();
  }

  async updateStatus(alertId, status) {
    return this.alertModel.findOneAndUpdate(
      { alertId },
      { $set: { status } },
      { new: true },
    ).lean().exec();
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
