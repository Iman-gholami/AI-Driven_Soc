const mongoose = require("mongoose");

const { Schema } = mongoose;

const alertProcessingSchema = new Schema(
  {
    attempts: { type: Number, default: 0, min: 0 },
    completedAt: { type: Date, default: undefined },
    errors: { type: [Schema.Types.Mixed], default: undefined },
  },
  { _id: false, strict: false },
);

const alertSchema = new Schema(
  {
    alertId: { type: String, required: true, trim: true },
    source: { type: String, default: "unknown", trim: true },
    rawEvent: { type: Schema.Types.Mixed, required: true },
    status: { type: String, default: "new", enum: ["new", "analyzed"], trim: true },
    severity: { type: String, default: "unknown", trim: true },
    eventHash: { type: String, required: true, trim: true },
    latestAnalysisId: { type: Schema.Types.ObjectId, ref: "AlertAnalysis", default: undefined },
    analysisCount: { type: Number, default: 0, min: 0 },
    lastAnalyzedAt: { type: Date, default: undefined },
    processing: { type: alertProcessingSchema, default: () => ({}) },
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
alertSchema.index({ eventHash: 1 }, { unique: true });
alertSchema.index({ latestAnalysisId: 1 });

module.exports = mongoose.models.Alert || mongoose.model("Alert", alertSchema);
