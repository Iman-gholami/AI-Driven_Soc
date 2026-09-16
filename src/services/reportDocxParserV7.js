const v6 = require("./reportDocxParserV6");

const PARSER_VERSION = "docx-v7";

async function parseDocxReport(filePath, { yearHint } = {}) {
  const report = await v6.parseDocxReport(filePath, { yearHint });
  return enhanceReportRecordV7(report);
}

function enhanceReportRecordV7(report) {
  if (!report || typeof report !== "object") return report;

  // Prefer a highly specific title-based match even when an older parser
  // already produced a broader finding from the body text.
  const titleFinding = classifyFindingV7(report.title);
  if (titleFinding.type !== "unknown") {
    report.finding = titleFinding;
    report.vulnerability = vulnerabilityFromFindingV7(titleFinding);
  }

  report.reportType = normalizeReportTypeV7(report.reportType, report.finding);

  const warnings = new Set(report.extraction?.warnings || []);
  if (report.finding?.type !== "unknown") warnings.delete("unknown_finding_type");

  report.extraction = {
    ...(report.extraction || {}),
    parserVersion: PARSER_VERSION,
    warnings: [...warnings],
  };

  return report;
}

function classifyFindingV7(value) {
  const text = normalize(value);
  const catalog = [
    {
      pattern: /(?:api\s+swagger|swagger\s+(?:api|ui)|swagger.*(?:documentation|docs)|آسیب\s*پذیری\s+api\s+swagger)/,
      type: "swagger_api_exposure",
      name: "Swagger API Exposure",
      category: "api_security",
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

function normalizeReportTypeV7(currentType, finding) {
  const current = String(currentType || "other");
  if (current !== "other") return current;

  const type = String(finding?.type || "unknown");

  const incidentFindings = new Set([
    "malicious_indicator_communication",
    "suspicious_indicator_communication",
    "unusual_scanning",
  ]);
  if (incidentFindings.has(type)) return "incident";

  if (type === "malware_tunnel_communication") return "malware";

  const misconfigurationFindings = new Set([
    "password_policy_violation",
    "cleartext_communication",
    "default_credentials",
    "open_dns_resolver",
    "dns_zone_transfer_exposure",
    "insecure_tftp_service",
    "exposed_remote_desktop",
    "exposed_upnp_service",
    "swagger_api_exposure",
  ]);
  if (misconfigurationFindings.has(type)) return "misconfiguration";

  return current;
}

function vulnerabilityFromFindingV7(finding) {
  if (!finding || finding.type !== "swagger_api_exposure") {
    return finding && finding.type !== "unknown"
      ? v6.vulnerabilityFromFindingV6(finding)
      : { name: null, normalizedName: "unknown", category: "unknown", cwe: null };
  }

  return {
    name: finding.name,
    normalizedName: finding.type,
    category: finding.category,
    cwe: finding.cwe || null,
  };
}

function normalize(value) {
  return String(value || "")
    .replace(/ي/g, "ی")
    .replace(/ك/g, "ک")
    .replace(/[‌\u200c\u200f\u202a-\u202e]/g, " ")
    .replace(/[\u064b-\u065f\u0670]/g, "")
    .replace(/آسیب[\s-]*پذیری/g, "آسیب پذیری")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

module.exports = {
  PARSER_VERSION,
  parseDocxReport,
  enhanceReportRecordV7,
  classifyFindingV7,
  normalizeReportTypeV7,
  vulnerabilityFromFindingV7,
};
