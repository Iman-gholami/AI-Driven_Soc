const mongoose = require("mongoose");

const { Schema } = mongoose;

const alertAnalysisSchema = new Schema(
  {
    severity: { type: String, trim: true },
    summary: { type: String, trim: true },
    recommendations: [{ type: String, trim: true }],
    verdict: { type: String, trim: true },
    confidence: { type: Number, min: 0, max: 100 },
    action: { type: String, trim: true },
    analyzedAt: { type: Date, default: Date.now },
  },
  { _id: false, strict: false },
);

const futureSocFieldsSchema = new Schema(
  {
    mitreAttack: { type: Schema.Types.Mixed, default: undefined },
    iocs: { type: [Schema.Types.Mixed], default: undefined },
    correlation: { type: Schema.Types.Mixed, default: undefined },
    threatIntelligence: { type: Schema.Types.Mixed, default: undefined },
    networkIntelligence: { type: Schema.Types.Mixed, default: undefined },
    providerMetadata: { type: Schema.Types.Mixed, default: undefined },
  },
  { _id: false, strict: false },
);

const alertSchema = new Schema(
  {
    alertId: { type: String, required: true, trim: true },
    source: { type: String, default: "unknown", trim: true },
    signature: { type: String, default: undefined, trim: true },
    eventType: { type: String, default: undefined, trim: true },
    host: { type: String, default: undefined, trim: true },
    rawEvent: { type: Schema.Types.Mixed, required: true },
    ruleMatch: { type: Schema.Types.Mixed, default: undefined },
    aiStatus: {
      type: String,
      default: "not_analyzed",
      enum: ["not_analyzed", "analyzing", "analyzed", "failed"],
      trim: true,
    },
    analysis: { type: [alertAnalysisSchema], default: undefined },
    status: { type: String, default: "new", enum: ["new", "analyzed"], trim: true },
    severity: { type: String, default: "unknown", trim: true },
    llmProvider: { type: String, trim: true },
    model: { type: String, trim: true },
    processingTimeMs: { type: Number, min: 0 },
    eventHash: { type: String, required: true, trim: true },
    fullAnalysis: { type: Schema.Types.Mixed, default: undefined },
    soc: { type: futureSocFieldsSchema, default: () => ({}) },
    processing: {
      attempts: { type: Number, default: 0, min: 0 },
      lastIngestedAt: { type: Date, default: undefined },
      startedAt: { type: Date, default: undefined },
      completedAt: { type: Date, default: undefined },
      failedAt: { type: Date, default: undefined },
      lastError: { type: String, default: undefined, trim: true },
      errors: { type: [Schema.Types.Mixed], default: undefined },
    },
  },
  {
    timestamps: true,
    minimize: false,
  },
);

alertSchema.index({ alertId: 1 }, { unique: true });
alertSchema.index({ eventHash: 1 }, { unique: true });
alertSchema.index({ createdAt: -1 });
alertSchema.index({ createdAt: -1, signature: 1 });
alertSchema.index({ status: 1, createdAt: -1 });
alertSchema.index({ aiStatus: 1, createdAt: -1 });
alertSchema.index({ severity: 1, createdAt: -1 });
alertSchema.index({ source: 1, createdAt: -1 });
alertSchema.index({ "ruleMatch.status": 1, createdAt: -1 });
alertSchema.index({ "analysis.severity": 1 });

module.exports = mongoose.models.Alert || mongoose.model("Alert", alertSchema);
