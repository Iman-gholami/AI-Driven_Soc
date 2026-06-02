const mongoose = require("mongoose");

const { Schema } = mongoose;

const alertAnalysisSchema = new Schema(
  {
    severity: { type: String, trim: true },
    summary: { type: String, trim: true },
    recommendations: [{ type: String, trim: true }],
  },
  { _id: false, strict: false },
);

const futureSocFieldsSchema = new Schema(
  {
    mitreAttack: { type: Schema.Types.Mixed, default: undefined },
    iocs: { type: [Schema.Types.Mixed], default: undefined },
    correlation: { type: Schema.Types.Mixed, default: undefined },
    threatIntelligence: { type: Schema.Types.Mixed, default: undefined },
    providerMetadata: { type: Schema.Types.Mixed, default: undefined },
  },
  { _id: false, strict: false },
);

const alertSchema = new Schema(
  {
    alertId: { type: String, required: true, trim: true },
    source: { type: String, default: "unknown", trim: true },
    rawEvent: { type: Schema.Types.Mixed, required: true },
    analysis: { type: alertAnalysisSchema, default: undefined },
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
      completedAt: { type: Date, default: undefined },
      errors: { type: [Schema.Types.Mixed], default: undefined },
    },
  },
  {
    timestamps: true,
    minimize: false,
  },
);

alertSchema.index({ alertId: 1 }, { unique: true });
alertSchema.index({ status: 1 });
alertSchema.index({ createdAt: -1 });
alertSchema.index({ severity: 1 });
alertSchema.index({ "analysis.severity": 1 });
alertSchema.index({ eventHash: 1 }, { unique: true });

module.exports = mongoose.models.Alert || mongoose.model("Alert", alertSchema);
