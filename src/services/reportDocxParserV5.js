const v4 = require("./reportDocxParserV4");

const PARSER_VERSION = "docx-v5";

async function parseDocxReport(filePath, { yearHint } = {}) {
  const report = await v4.parseDocxReport(filePath, { yearHint });
  return enhanceReportRecordV5(report);
}

function enhanceReportRecordV5(report) {
  if (!report || typeof report !== "object") return report;

  if (!report.finding || report.finding.type === "unknown") {
    const combinedText = [report.title, report.description, report.fullText]
      .filter(Boolean)
      .join("\n");
    const finding = classifyFindingV5(combinedText);
    if (finding.type !== "unknown") {
      report.finding = finding;
      report.vulnerability = vulnerabilityFromFindingV5(finding);
    }
  }

  const warnings = new Set(report.extraction?.warnings || []);
  if (report.finding?.type !== "unknown") warnings.delete("unknown_finding_type");

  report.extraction = {
    ...(report.extraction || {}),
    parserVersion: PARSER_VERSION,
    warnings: [...warnings],
  };

  return report;
}

function classifyFindingV5(value) {
  const text = normalize(value);
  const catalog = [
    {
      pattern: /دسترسی\s+(?:نامجاز\s+و\s+)?بدون\s+احراز\s+هویت|دسترسی\s+بدون\s+احراز\s+هویت.*(?:web\.config|فایل)|unauthenticated\s+(?:file\s+)?access/,
      type: "unauthenticated_file_access",
      name: "Unauthenticated File Access",
      category: "access_control",
      cwe: null,
    },
    {
      pattern: /slow\s*http\s*(?:dos|denial\s+of\s+service)|آسیب\s*پذیری\s+slow\s*http/,
      type: "slow_http_dos",
      name: "Slow HTTP DoS",
      category: "denial_of_service",
      cwe: null,
    },
    {
      pattern: /udp\s*flood(?:ing)?|منع\s+سرویس\s*udp\s*flood/,
      type: "udp_flood",
      name: "UDP Flood",
      category: "denial_of_service",
      cwe: null,
    },
    {
      pattern: /\bdefacement\b|دیفیس/,
      type: "defacement",
      name: "Website Defacement",
      category: "web_intrusion",
      cwe: null,
    },
    {
      pattern: /(?:سرویس|پروتکل).*ntlm|ntlm.*(?:آسیب\s*پذیر|vulnerable|احراز\s+هویت)/,
      type: "vulnerable_ntlm",
      name: "Vulnerable NTLM",
      category: "authentication_protocol",
      cwe: null,
    },
    {
      pattern: /(?:دسترسی\s+بدون\s+احراز\s+هویت|unauthenticated).*redis|redis.*(?:بدون\s+احراز\s+هویت|پیکربندی\s+نامناسب|6379|6380)/,
      type: "unauthenticated_redis",
      name: "Unauthenticated Redis",
      category: "exposed_service",
      cwe: null,
    },
    {
      pattern: /(?:سرویس\s+پرخطر|سرویس\s+آسیب\s*پذیر|عدم\s+مدیریت).*rpc|\brpc\b.*(?:در\s+معرض\s+اینترنت|exposed|پرخطر)/,
      type: "exposed_rpc",
      name: "Exposed RPC Service",
      category: "exposed_service",
      cwe: null,
    },
    {
      pattern: /apache\s+log4j2?|log4shell|cve-2021-44228|cve-2021-45046/,
      type: "vulnerable_log4j2",
      name: "Vulnerable Apache Log4j2 / Log4Shell",
      category: "vulnerable_software",
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

function vulnerabilityFromFindingV5(finding) {
  const vulnerabilityLike = new Set([
    "unauthenticated_file_access",
    "slow_http_dos",
    "vulnerable_ntlm",
    "unauthenticated_redis",
    "exposed_rpc",
    "vulnerable_log4j2",
  ]);

  if (!finding || !vulnerabilityLike.has(finding.type)) {
    return { name: null, normalizedName: "unknown", category: "unknown", cwe: null };
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
    .replace(/[‌\u200c]/g, " ")
    .replace(/آسیب[\s-]*پذیری/g, "آسیب پذیری")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

module.exports = {
  PARSER_VERSION,
  parseDocxReport,
  enhanceReportRecordV5,
  classifyFindingV5,
  vulnerabilityFromFindingV5,
};
