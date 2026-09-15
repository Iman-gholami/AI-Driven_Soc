const mongoose = require("mongoose");

const affectedSystemSchema = new mongoose.Schema(
  {
    method: { type: String, default: null },
    parameter: { type: String, default: null },
    url: { type: String, default: null },
    domain: { type: String, default: null },
    organization: { type: String, default: null },
    ip: { type: String, default: null },
  },
  { _id: false },
);

const historicalReportSchema = new mongoose.Schema(
  {
    documentKey: { type: String, required: true, unique: true, index: true },
    reportNumber: { type: String, default: null, index: true },
    reportDateRaw: { type: String, default: null },
    year: { type: Number, required: true, index: true },
    month: { type: Number, default: null, index: true },
    day: { type: Number, default: null },

    title: { type: String, required: true },
    reportType: { type: String, default: "unknown", index: true },
    provider: { type: String, default: null },
    contact: { type: String, default: null },

    target: {
      organization: { type: String, default: null, index: true },
      ip: { type: String, default: null, index: true },
    },

    severity: {
      score: { type: Number, default: null },
      level: { type: String, default: "unknown", index: true },
    },

    urgency: {
      raw: { type: String, default: null },
      normalized: { type: String, default: "unknown", index: true },
    },

    vulnerability: {
      name: { type: String, default: null },
      normalizedName: { type: String, default: "unknown", index: true },
      category: { type: String, default: "unknown", index: true },
      cwe: { type: String, default: null },
    },

    description: { type: String, default: "" },
    recommendations: { type: [String], default: [] },
    affectedSystems: { type: [affectedSystemSchema], default: [] },
    fullText: { type: String, default: "" },

    source: {
      filename: { type: String, required: true },
      relativePath: { type: String, required: true },
      sha256: { type: String, required: true, index: true },
      sizeBytes: { type: Number, default: 0 },
      importedAt: { type: Date, default: Date.now },
    },

    extraction: {
      parserVersion: { type: String, default: "docx-v1" },
      paragraphCount: { type: Number, default: 0 },
      tableCount: { type: Number, default: 0 },
      warnings: { type: [String], default: [] },
      organizationMismatch: { type: Boolean, default: false, index: true },
      ipMismatch: { type: Boolean, default: false, index: true },
    },
  },
  { timestamps: true, minimize: false },
);

historicalReportSchema.index({ year: 1, month: 1 });
historicalReportSchema.index({ year: 1, "severity.level": 1 });
historicalReportSchema.index({ year: 1, "vulnerability.normalizedName": 1 });
historicalReportSchema.index({ year: 1, "target.organization": 1 });
historicalReportSchema.index({ "affectedSystems.ip": 1 });
historicalReportSchema.index({ "affectedSystems.domain": 1 });
historicalReportSchema.index({
  title: "text",
  description: "text",
  recommendations: "text",
  "target.organization": "text",
  "vulnerability.name": "text",
});

module.exports = mongoose.models.HistoricalReport
  || mongoose.model("HistoricalReport", historicalReportSchema);
