const AlertAnalysis = require("../models/AlertAnalysis");

class AlertAnalysisRepository {
  constructor({ alertAnalysisModel = AlertAnalysis } = {}) {
    this.alertAnalysisModel = alertAnalysisModel;
  }

  async createForAlert(alert, analysisRecord) {
    const alertObjectId = alert?._id || alert?.id;
    const alertId = alert?.alertId || analysisRecord?.alertId;

    return this.alertAnalysisModel.create({
      alert: alertObjectId,
      alertId,
      analysis: analysisRecord.analysis,
      fullAnalysis: analysisRecord.fullAnalysis,
      llmProvider: analysisRecord.llmProvider,
      model: analysisRecord.model,
      processingTimeMs: analysisRecord.processingTimeMs,
      soc: analysisRecord.soc || {},
      processing: {
        attemptNumber: analysisRecord.processing?.attemptNumber || analysisRecord.attemptNumber,
        completedAt: analysisRecord.processing?.completedAt || new Date(),
        errors: analysisRecord.processing?.errors,
      },
    });
  }

  async listByAlertId(alertId) {
    return this.alertAnalysisModel
      .find({ alertId })
      .sort({ createdAt: -1 })
      .lean()
      .exec();
  }

  async findLatestByAlertId(alertId) {
    return this.alertAnalysisModel
      .findOne({ alertId })
      .sort({ createdAt: -1 })
      .lean()
      .exec();
  }

  async findById(id) {
    return this.alertAnalysisModel.findById(id).lean().exec();
  }
}

module.exports = { AlertAnalysisRepository };
