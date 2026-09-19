const v7 = require("./reportDocxParserV7");

const PARSER_VERSION = "docx-v8";

async function parseDocxReport(filePath, { yearHint } = {}) {
  const report = await v7.parseDocxReport(filePath, { yearHint });
  return enhanceReportRecordV8(report);
}

function enhanceReportRecordV8(report) {
  if (!report || typeof report !== "object") return report;

  // These reports can mention phishing infrastructure in the body, which made
  // older parsers choose the broad `phishing` finding. Prefer the explicit
  // malicious-code/APT report title when present.
  const titleFinding = classifyFindingV8(report.title);
  if (titleFinding.type !== "unknown") {
    report.finding = titleFinding;
    report.vulnerability = vulnerabilityFromFindingV8(titleFinding);
  }

  report.reportType = normalizeReportTypeV8(report.reportType, report.finding);

  const warnings = new Set(report.extraction?.warnings || []);
  if (report.finding?.type !== "unknown") warnings.delete("unknown_finding_type");

  report.extraction = {
    ...(report.extraction || {}),
    parserVersion: PARSER_VERSION,
    warnings: [...warnings],
  };

  return report;
}

function classifyFindingV8(value) {
  const text = normalize(value);
  const catalog = [
    {
      pattern: /(?:کد\s+مخرب.*(?:فعالیت\s+)?apt|(?:فعالیت\s+)?apt.*کد\s+مخرب|advanced\s+persistent\s+threat)/,
      type: "apt_malicious_code_activity",
      name: "APT Malicious Code Activity",
      category: "advanced_persistent_threat",
      cwe: null,
    },
  ];

  return catalog.find((item) => item.pattern.test(text)) || {
    type: "unknown",
    name: null,
    category: "unknown",
    cwe: null,
  };
}

function normalizeReportTypeV8(currentType, finding) {
  if (finding?.type === "apt_malicious_code_activity") return "malware";
  return v7.normalizeReportTypeV7(currentType, finding);
}

function vulnerabilityFromFindingV8(finding) {
  if (!finding || finding.type === "unknown") {
    return { name: null, normalizedName: "unknown", category: "unknown", cwe: null };
  }

  if (finding.type === "apt_malicious_code_activity") {
    return { name: null, normalizedName: "unknown", category: "unknown", cwe: null };
  }

  return v7.vulnerabilityFromFindingV7(finding);
}

function normalize(value) {
  return String(value || "")
    .replace(/ي/g, "ی")
    .replace(/ك/g, "ک")
    .replace(/[‌\u200c\u200f\u202a-\u202e]/g, " ")
    .replace(/[\u064b-\u065f\u0670]/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

module.exports = {
  PARSER_VERSION,
  parseDocxReport,
  enhanceReportRecordV8,
  classifyFindingV8,
  normalizeReportTypeV8,
  vulnerabilityFromFindingV8,
};
