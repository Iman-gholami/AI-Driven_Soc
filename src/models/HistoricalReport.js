const mongoose = require("mongoose");

const affectedSystemSchema = new mongoose.Schema(
  {
    method: { type: String, default: null },
    parameter: { type: String, default: null },
    url: { type: String, default: null },
    additionalUrls: { type: [String], default: [] },
    domain: { type: String, default: null },
    organization: { type: String, default: null },
    ip: { type: String, default: null },
    rawIp: { type: String, default: null },
    port: { type: Number, default: null },
    service: { type: String, default: null },
    packetCount: { type: Number, default: null },
    participantIpCount: { type: Number, default: null },
    trafficVolumeRaw: { type: String, default: null },
    trafficVolumeBytes: { type: Number, default: null },
    eventDateRaw: { type: String, default: null },
    eventYear: { type: Number, default: null },
    eventMonth: { type: Number, default: null },
    eventDay: { type: Number, default: null },
    timeRange: { type: String, default: null },
    softwareVersion: { type: String, default: null },
    reportedFinding: { type: String, default: null },
    cves: { type: [String], default: [] },
  },
  { _id: false },
);

const phishingInfrastructureSchema = new mongoose.Schema(
  {
    url: { type: String, default: null },
    domain: { type: String, default: null },
    ip: { type: String, default: null },
    rawIp: { type: String, default: null },
    pageTitle: { type: String, default: null },
  },
  { _id: false },
);

const indicatorSchema = new mongoose.Schema(
  {
    type: { type: String, required: true },
    role: { type: String, default: null },
    value: { type: String, required: true },
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
    effect: { type: String, default: null },

    target: {
      organization: { type: String, default: null, index: true },
      ip: { type: String, default: null, index: true },
      rawIp: { type: String, default: null },
    },

    severity: {
      raw: { type: String, default: null },
      score: { type: Number, default: null },
      level: { type: String, default: "unknown", index: true },
    },

    urgency: {
      raw: { type: String, default: null },
      normalized: { type: String, default: "unknown", index: true },
    },

    finding: {
      type: { type: String, default: "unknown", index: true },
      name: { type: String, default: null },
      category: { type: String, default: "unknown", index: true },
      cwe: { type: String, default: null },
    },

    // Kept for compatibility with the first report-intelligence schema and
    // vulnerability-specific filtering. General analytics should prefer `finding`.
    vulnerability: {
      name: { type: String, default: null },
      normalizedName: { type: String, default: "unknown", index: true },
      category: { type: String, default: "unknown", index: true },
      cwe: { type: String, default: null },
    },

    cves: { type: [String], default: [], index: true },
    affectedCves: { type: [String], default: [], index: true },
    description: { type: String, default: "" },
    conclusion: { type: String, default: "" },
    recommendations: { type: [String], default: [] },
    affectedSystems: { type: [affectedSystemSchema], default: [] },
    phishingInfrastructure: { type: [phishingInfrastructureSchema], default: [] },
    indicators: { type: [indicatorSchema], default: [] },
    fullText: { type: String, default: "" },

    source: {
      filename: { type: String, required: true },
      relativePath: { type: String, required: true },
      sha256: { type: String, required: true, index: true },
      sizeBytes: { type: Number, default: 0 },
      importedAt: { type: Date, default: Date.now },
    },

    extraction: {
      parserVersion: { type: String, default: "docx-v4" },
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
historicalReportSchema.index({ year: 1, reportType: 1 });
historicalReportSchema.index({ year: 1, "severity.level": 1 });
historicalReportSchema.index({ year: 1, "finding.type": 1 });
historicalReportSchema.index({ year: 1, "vulnerability.normalizedName": 1 });
historicalReportSchema.index({ year: 1, "target.organization": 1 });
historicalReportSchema.index({ "affectedSystems.ip": 1 });
historicalReportSchema.index({ "affectedSystems.domain": 1 });
historicalReportSchema.index({ "affectedSystems.port": 1 });
historicalReportSchema.index({ "affectedSystems.eventYear": 1, "affectedSystems.eventMonth": 1 });
historicalReportSchema.index({ "phishingInfrastructure.ip": 1 });
historicalReportSchema.index({ "phishingInfrastructure.domain": 1 });
historicalReportSchema.index({ "indicators.value": 1 });
historicalReportSchema.index({
  title: "text",
  description: "text",
  conclusion: "text",
  recommendations: "text",
  "target.organization": "text",
  "finding.name": "text",
  "vulnerability.name": "text",
});

module.exports = mongoose.models.HistoricalReport
  || mongoose.model("HistoricalReport", historicalReportSchema);
