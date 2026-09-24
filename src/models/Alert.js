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

const analystActorSchema = new Schema(
  {
    id: { type: String, required: true, trim: true, maxlength: 200 },
    displayName: { type: String, required: true, trim: true, maxlength: 200 },
  },
  { _id: false },
);

const analystCaseSchema = new Schema(
  {
    actionsTaken: [{ type: String, trim: true, maxlength: 200 }],
    note: { type: String, default: undefined, trim: true, maxlength: 4000 },
    startedAt: { type: Date, default: undefined },
    startedBy: { type: analystActorSchema, default: undefined },
    updatedAt: { type: Date, default: undefined },
    updatedBy: { type: analystActorSchema, default: undefined },
    finalOutcome: {
      type: String,
      enum: ["true_positive", "false_positive"],
      default: undefined,
      trim: true,
    },
    falsePositiveReason: {
      type: String,
      enum: [
        "authorized_scanner",
        "authorized_testing",
        "known_benign_service",
        "rule_too_broad",
        "duplicate_alert",
        "expected_behavior",
        "other",
      ],
      default: undefined,
      trim: true,
    },
    falsePositiveDetails: { type: String, default: undefined, trim: true, maxlength: 2000 },
    ticketNumber: { type: String, default: undefined, trim: true, maxlength: 128 },
    closedAt: { type: Date, default: undefined },
    closedBy: { type: analystActorSchema, default: undefined },
  },
  { _id: false, minimize: false },
);

const futureSocFieldsSchema = new Schema(
  {
    mitreAttack: { type: Schema.Types.Mixed, default: undefined },
    iocs: { type: [Schema.Types.Mixed], default: undefined },
    correlation: { type: Schema.Types.Mixed, default: undefined },
    threatIntelligence: { type: Schema.Types.Mixed, default: undefined },
    networkIntelligence: { type: Schema.Types.Mixed, default: undefined },
    historicalReports: { type: Schema.Types.Mixed, default: undefined },
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
    eventTime: { type: Date, default: undefined },
    rawEvent: { type: Schema.Types.Mixed, required: true },
    ruleMatch: { type: Schema.Types.Mixed, default: undefined },
    aiStatus: {
      type: String,
      default: "not_analyzed",
      enum: ["not_analyzed", "analyzing", "analyzed", "failed"],
      trim: true,
    },
    analysis: { type: [alertAnalysisSchema], default: undefined },
    status: {
      type: String,
      default: "new",
      enum: ["new", "analyzed", "investigating", "closed"],
      trim: true,
    },
    analystCase: { type: analystCaseSchema, default: undefined },
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
alertSchema.index({ eventTime: -1 });
alertSchema.index({ eventTime: -1, signature: 1 });
alertSchema.index({ createdAt: -1, signature: 1 });
alertSchema.index({ status: 1, createdAt: -1 });
alertSchema.index({ aiStatus: 1, createdAt: -1 });
alertSchema.index({ severity: 1, createdAt: -1 });
alertSchema.index({ severity: 1, eventTime: -1 });
alertSchema.index({ source: 1, createdAt: -1 });
alertSchema.index({ "ruleMatch.status": 1, createdAt: -1 });
alertSchema.index({ "analysis.severity": 1 });

module.exports = mongoose.models.Alert || mongoose.model("Alert", alertSchema);