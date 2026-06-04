const mongoose = require("mongoose");

const { Schema } = mongoose;

const analysisSummarySchema = new Schema(
  {
    severity: { type: String, trim: true },
    summary: { type: String, trim: true },
    recommendations: [{ type: String, trim: true }],
  },
  { _id: false, strict: false },
);

const socSchema = new Schema(
  {
    mitreAttack: { type: Schema.Types.Mixed, default: undefined },
    iocs: { type: [Schema.Types.Mixed], default: undefined },
    correlation: { type: Schema.Types.Mixed, default: undefined },
    threatIntelligence: { type: Schema.Types.Mixed, default: undefined },
    providerMetadata: { type: Schema.Types.Mixed, default: undefined },
  },
  { _id: false, strict: false },
);

const processingSchema = new Schema(
  {
    attemptNumber: { type: Number, min: 1 },
    completedAt: { type: Date, default: undefined },
    errors: { type: [Schema.Types.Mixed], default: undefined },
  },
  { _id: false, strict: false },
);

const alertAnalysisSchema = new Schema(
  {
    alert: { type: Schema.Types.ObjectId, ref: "Alert", required: true },
    alertId: { type: String, required: true, trim: true },
    analysis: { type: analysisSummarySchema, default: undefined },
    fullAnalysis: { type: Schema.Types.Mixed, default: undefined },
    llmProvider: { type: String, trim: true },
    model: { type: String, trim: true },
    processingTimeMs: { type: Number, min: 0 },
    soc: { type: socSchema, default: () => ({}) },
    processing: { type: processingSchema, default: () => ({}) },
  },
  {
    timestamps: true,
    minimize: false,
  },
);

alertAnalysisSchema.index({ alert: 1 });
alertAnalysisSchema.index({ alertId: 1 });
alertAnalysisSchema.index({ createdAt: -1 });
alertAnalysisSchema.index({ "analysis.severity": 1 });
alertAnalysisSchema.index({ llmProvider: 1 });
alertAnalysisSchema.index({ model: 1 });

module.exports = mongoose.models.AlertAnalysis || mongoose.model("AlertAnalysis", alertAnalysisSchema);
