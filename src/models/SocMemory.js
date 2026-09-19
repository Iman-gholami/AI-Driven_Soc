const mongoose = require("mongoose");

const { Schema } = mongoose;

const fingerprintSchema = new Schema(
  {
    signature: { type: String, default: null, trim: true, index: true },
    ruleId: { type: String, default: null, trim: true, index: true },
    ruleTitle: { type: String, default: null, trim: true },
    protocol: { type: String, default: null, trim: true, lowercase: true },
    severity: { type: String, default: "unknown", trim: true },
    mitreTechniqueIds: { type: [String], default: [], index: true },
    ips: { type: [String], default: [], index: true },
    organizations: { type: [String], default: [], index: true },
    ports: { type: [Number], default: [] },
  },
  { _id: false },
);

const priorAssessmentSchema = new Schema(
  {
    verdict: { type: String, default: "UNKNOWN", trim: true },
    severity: { type: String, default: "unknown", trim: true },
    confidence: { type: Number, default: 0, min: 0, max: 100 },
    recommendedAction: { type: String, default: "UNKNOWN", trim: true },
    finalSocNote: { type: String, default: "", trim: true },
    investigationSteps: { type: [String], default: [] },
  },
  { _id: false },
);

const embeddingSchema = new Schema(
  {
    model: { type: String, default: null, trim: true },
    dimensions: { type: Number, default: 0, min: 0 },
    vector: { type: [Number], default: undefined },
    generatedAt: { type: Date, default: undefined },
  },
  { _id: false },
);

const socMemorySchema = new Schema(
  {
    memoryId: { type: String, required: true, unique: true, index: true, trim: true },
    kind: {
      type: String,
      enum: ["incident"],
      default: "incident",
      index: true,
    },
    source: {
      type: { type: String, enum: ["alert"], default: "alert" },
      id: { type: String, required: true, trim: true, index: true },
      eventHash: { type: String, default: null, trim: true },
      analysisCount: { type: Number, default: 1, min: 0 },
    },
    eventTime: { type: Date, default: undefined, index: true },
    summary: { type: String, default: "", trim: true },
    semanticText: { type: String, required: true },
    fingerprint: { type: fingerprintSchema, default: () => ({}) },
    priorAssessment: { type: priorAssessmentSchema, default: () => ({}) },
    embedding: { type: embeddingSchema, default: undefined },
  },
  { timestamps: true, minimize: false },
);

socMemorySchema.index({ kind: 1, eventTime: -1 });
socMemorySchema.index({ "fingerprint.ruleId": 1, eventTime: -1 });
socMemorySchema.index({ "fingerprint.signature": 1, eventTime: -1 });
socMemorySchema.index({ "fingerprint.ips": 1, eventTime: -1 });
socMemorySchema.index({ "fingerprint.organizations": 1, eventTime: -1 });
socMemorySchema.index({ "fingerprint.mitreTechniqueIds": 1, eventTime: -1 });

module.exports = mongoose.models.SocMemory || mongoose.model("SocMemory", socMemorySchema);
