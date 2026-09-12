const Alert = require('../models/Alert');
const DetectionRule = require('../models/DetectionRule');

class WorkbenchAnalyticsService {
  constructor({ alertModel = Alert, detectionRuleModel = DetectionRule } = {}) {
    this.alertModel = alertModel;
    this.detectionRuleModel = detectionRuleModel;
  }

  async getAiEvaluation({ days = 30 } = {}) {
    const safeDays = clampInteger(days, 1, 365, 30);
    const from = new Date(Date.now() - safeDays * 24 * 60 * 60 * 1000);
    const match = { createdAt: { $gte: from } };

    const [summaryRows, modelRows] = await Promise.all([
      this.alertModel.aggregate([
        { $match: match },
        {
          $group: {
            _id: null,
            total: { $sum: 1 },
            analyzed: { $sum: { $cond: [{ $eq: ['$aiStatus', 'analyzed'] }, 1, 0] } },
            failed: { $sum: { $cond: [{ $eq: ['$aiStatus', 'failed'] }, 1, 0] } },
            analyzing: { $sum: { $cond: [{ $eq: ['$aiStatus', 'analyzing'] }, 1, 0] } },
            avgLatencyMs: { $avg: '$processingTimeMs' },
            p95Inputs: { $push: '$processingTimeMs' },
          },
        },
      ]).exec(),
      this.alertModel.aggregate([
        {
          $match: {
            ...match,
            $or: [
              { llmProvider: { $nin: [null, ''] } },
              { model: { $nin: [null, ''] } },
            ],
          },
        },
        {
          $group: {
            _id: {
              provider: { $ifNull: ['$llmProvider', 'unknown'] },
              model: { $ifNull: ['$model', 'unknown'] },
            },
            runs: { $sum: 1 },
            analyzed: { $sum: { $cond: [{ $eq: ['$aiStatus', 'analyzed'] }, 1, 0] } },
            failed: { $sum: { $cond: [{ $eq: ['$aiStatus', 'failed'] }, 1, 0] } },
            avgLatencyMs: { $avg: '$processingTimeMs' },
            minLatencyMs: { $min: '$processingTimeMs' },
            maxLatencyMs: { $max: '$processingTimeMs' },
          },
        },
        { $sort: { runs: -1, '_id.provider': 1, '_id.model': 1 } },
        {
          $project: {
            _id: 0,
            provider: '$_id.provider',
            model: '$_id.model',
            runs: 1,
            analyzed: 1,
            failed: 1,
            avgLatencyMs: { $round: [{ $ifNull: ['$avgLatencyMs', 0] }, 0] },
            minLatencyMs: { $round: [{ $ifNull: ['$minLatencyMs', 0] }, 0] },
            maxLatencyMs: { $round: [{ $ifNull: ['$maxLatencyMs', 0] }, 0] },
          },
        },
      ]).exec(),
    ]);

    const row = summaryRows[0] || {};
    const total = Number(row.total || 0);
    const analyzed = Number(row.analyzed || 0);
    const failed = Number(row.failed || 0);

    return {
      window: { days: safeDays, from: from.toISOString(), to: new Date().toISOString() },
      summary: {
        total,
        analyzed,
        failed,
        analyzing: Number(row.analyzing || 0),
        coveragePercent: percent(analyzed, total),
        successPercent: percent(analyzed, analyzed + failed),
        avgLatencyMs: Math.round(Number(row.avgLatencyMs || 0)),
      },
      models: modelRows.map((model) => ({
        ...model,
        successPercent: percent(Number(model.analyzed || 0), Number(model.analyzed || 0) + Number(model.failed || 0)),
      })),
      limitations: [
        'Accuracy is not estimated until analyst feedback is persisted.',
        'Latency reflects stored alert analysis processing time, not standalone model-token latency.',
      ],
    };
  }

  async getRuleInsights(ruleId, { days = 30 } = {}) {
    const normalizedRuleId = String(ruleId || '').trim();
    if (!normalizedRuleId) throw new WorkbenchInputError('ruleId is required');

    const safeDays = clampInteger(days, 1, 365, 30);
    const from = new Date(Date.now() - safeDays * 24 * 60 * 60 * 1000);
    const rule = await this.detectionRuleModel
      .findOne({ ruleId: normalizedRuleId, isCurrent: true })
      .select('ruleId revision title classtype protocol tier quarantined mitre')
      .lean()
      .exec();

    if (!rule) return null;

    const match = {
      'ruleMatch.ruleId': normalizedRuleId,
      createdAt: { $gte: from },
    };

    const [summaryRows, hostRows, signatureRows] = await Promise.all([
      this.alertModel.aggregate([
        { $match: match },
        {
          $group: {
            _id: null,
            total: { $sum: 1 },
            critical: { $sum: { $cond: [{ $eq: ['$severity', 'critical'] }, 1, 0] } },
            high: { $sum: { $cond: [{ $eq: ['$severity', 'high'] }, 1, 0] } },
            medium: { $sum: { $cond: [{ $eq: ['$severity', 'medium'] }, 1, 0] } },
            low: { $sum: { $cond: [{ $eq: ['$severity', 'low'] }, 1, 0] } },
            analyzed: { $sum: { $cond: [{ $eq: ['$aiStatus', 'analyzed'] }, 1, 0] } },
            failed: { $sum: { $cond: [{ $eq: ['$aiStatus', 'failed'] }, 1, 0] } },
            avgLatencyMs: { $avg: '$processingTimeMs' },
            firstSeen: { $min: { $ifNull: ['$eventTime', '$createdAt'] } },
            lastSeen: { $max: { $ifNull: ['$eventTime', '$createdAt'] } },
          },
        },
      ]).exec(),
      this.alertModel.aggregate([
        { $match: { ...match, host: { $nin: [null, ''] } } },
        { $group: { _id: '$host', count: { $sum: 1 } } },
        { $sort: { count: -1, _id: 1 } },
        { $limit: 8 },
        { $project: { _id: 0, host: '$_id', count: 1 } },
      ]).exec(),
      this.alertModel.aggregate([
        { $match: { ...match, signature: { $nin: [null, ''] } } },
        { $group: { _id: '$signature', count: { $sum: 1 } } },
        { $sort: { count: -1, _id: 1 } },
        { $limit: 5 },
        { $project: { _id: 0, signature: '$_id', count: 1 } },
      ]).exec(),
    ]);

    const stats = summaryRows[0] || {};
    const total = Number(stats.total || 0);
    const highRisk = Number(stats.critical || 0) + Number(stats.high || 0);

    return {
      window: { days: safeDays, from: from.toISOString(), to: new Date().toISOString() },
      rule: {
        ruleId: rule.ruleId,
        revision: rule.revision,
        title: rule.title,
        classtype: rule.classtype || null,
        protocol: rule.protocol || null,
        tier: rule.tier || null,
        quarantined: Boolean(rule.quarantined),
        mitre: rule.mitre || {},
      },
      stats: {
        total,
        analyzed: Number(stats.analyzed || 0),
        failed: Number(stats.failed || 0),
        aiCoveragePercent: percent(Number(stats.analyzed || 0), total),
        highRiskPercent: percent(highRisk, total),
        avgLatencyMs: Math.round(Number(stats.avgLatencyMs || 0)),
        firstSeen: stats.firstSeen || null,
        lastSeen: stats.lastSeen || null,
        severity: {
          critical: Number(stats.critical || 0),
          high: Number(stats.high || 0),
          medium: Number(stats.medium || 0),
          low: Number(stats.low || 0),
        },
      },
      topHosts: hostRows,
      topSignatures: signatureRows,
      signals: buildRuleSignals({ total, highRisk, hostRows, rule }),
    };
  }
}

class WorkbenchInputError extends Error {
  constructor(message) {
    super(message);
    this.name = 'WorkbenchInputError';
  }
}

function buildRuleSignals({ total, highRisk, hostRows, rule }) {
  const signals = [];
  if (total === 0) {
    signals.push({ level: 'info', code: 'NO_RECENT_HITS', message: 'No alert matched this rule in the selected window.' });
    return signals;
  }

  if (total >= 100 && highRisk / total < 0.1) {
    signals.push({
      level: 'review',
      code: 'HIGH_VOLUME_LOW_SEVERITY',
      message: 'High hit volume with a low high/critical ratio. Review thresholding and expected benign traffic before changing the rule.',
    });
  }

  if (hostRows.length === 1 && total >= 20) {
    signals.push({
      level: 'info',
      code: 'HOST_CONCENTRATION',
      message: 'Recent hits are concentrated on one host; validate whether this is asset-specific behavior.',
    });
  }

  if (!rule.mitre?.mapped) {
    signals.push({
      level: 'review',
      code: 'MITRE_UNMAPPED',
      message: 'This rule has no active deterministic MITRE mapping.',
    });
  }

  if (!signals.length) {
    signals.push({ level: 'ok', code: 'NO_OBVIOUS_QUALITY_SIGNAL', message: 'No obvious deterministic rule-quality issue was detected from the available telemetry.' });
  }
  return signals;
}

function percent(numerator, denominator) {
  if (!denominator) return 0;
  return Math.round((numerator / denominator) * 1000) / 10;
}

function clampInteger(value, min, max, fallback) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(Math.max(parsed, min), max);
}

module.exports = {
  WorkbenchAnalyticsService,
  WorkbenchInputError,
  buildRuleSignals,
  percent,
};
