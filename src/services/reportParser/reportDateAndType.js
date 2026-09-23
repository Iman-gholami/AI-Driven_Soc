const findingCatalog = require("./findingCatalog");

const STAGE_VERSION = "docx-v7";


function enhanceReportRecordV7(report, { yearHint } = {}) {
  if (!report || typeof report !== "object") return report;

  // Prefer a highly specific title-based match even when an older parser
  // already produced a broader finding from the body text.
  const titleFinding = classifyFindingV7(report.title);
  if (titleFinding.type !== "unknown") {
    report.finding = titleFinding;
    report.vulnerability = vulnerabilityFromFindingV7(titleFinding);
  }

  report.reportType = normalizeReportTypeV7(report.reportType, report.finding);

  const dateCorrection = reconcileReportDateYearV7(report, yearHint);
  const warnings = new Set(report.extraction?.warnings || []);
  if (report.finding?.type !== "unknown") warnings.delete("unknown_finding_type");

  if (dateCorrection) {
    warnings.delete(`report_year_mismatch:${dateCorrection.fromYear}:${dateCorrection.toYear}`);
    warnings.add(`report_date_year_corrected_from_report_number:${dateCorrection.fromYear}:${dateCorrection.toYear}`);
  }

  report.extraction = {
    ...(report.extraction || {}),
    parserVersion: STAGE_VERSION,
    warnings: [...warnings],
  };

  return report;
}

function reconcileReportDateYearV7(report, yearHint) {
  const expectedYear = Number(yearHint);
  const parsedYear = Number(report?.year);
  if (!Number.isInteger(expectedYear) || !Number.isInteger(parsedYear) || parsedYear === expectedYear) {
    return null;
  }

  const reportNumberDate = parseReportNumberDateV7(report?.reportNumber);
  if (!reportNumberDate || reportNumberDate.year !== expectedYear) return null;

  const parsedMonth = Number(report?.month);
  const parsedDay = Number(report?.day);
  const sameMonth = !Number.isInteger(parsedMonth) || parsedMonth === reportNumberDate.month;
  const sameDay = !Number.isInteger(parsedDay) || parsedDay === reportNumberDate.day;
  if (!sameMonth || !sameDay) return null;

  report.year = reportNumberDate.year;
  if (!Number.isInteger(parsedMonth)) report.month = reportNumberDate.month;
  if (!Number.isInteger(parsedDay)) report.day = reportNumberDate.day;

  return { fromYear: parsedYear, toYear: reportNumberDate.year };
}

function parseReportNumberDateV7(value) {
  const normalized = String(value || "")
    .replace(/[۰-۹]/g, (char) => String("۰۱۲۳۴۵۶۷۸۹".indexOf(char)))
    .replace(/[٠-٩]/g, (char) => String("٠١٢٣٤٥٦٧٨٩".indexOf(char)));
  const match = normalized.match(/(?:^|\D)(1[34]\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])(?:\D|$)/);
  if (!match) return null;
  return {
    year: Number(match[1]),
    month: Number(match[2]),
    day: Number(match[3]),
  };
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
      ? findingCatalog.vulnerabilityFromFindingV6(finding)
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
  STAGE_VERSION,
  enhanceReportRecordV7,
  reconcileReportDateYearV7,
  parseReportNumberDateV7,
  classifyFindingV7,
  normalizeReportTypeV7,
  vulnerabilityFromFindingV7,
};
