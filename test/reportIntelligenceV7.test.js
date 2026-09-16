const test = require("node:test");
const assert = require("node:assert/strict");

const {
  PARSER_VERSION,
  enhanceReportRecordV7,
  classifyFindingV7,
  normalizeReportTypeV7,
} = require("../src/services/reportDocxParserV7");

test("classifies Swagger API exposure from the report title", () => {
  const finding = classifyFindingV7("پیکربندی نامناسب – آسیب‌پذیری API Swagger");
  assert.equal(finding.type, "swagger_api_exposure");
  assert.equal(finding.category, "api_security");
});

test("specific Swagger title overrides an older broad unauthenticated access finding", () => {
  const report = {
    title: "پیکربندی نامناسب – آسیب‌پذیری API Swagger",
    reportType: "misconfiguration",
    finding: {
      type: "unauthenticated_file_access",
      name: "Unauthenticated File Access",
      category: "access_control",
      cwe: null,
    },
    vulnerability: {
      name: "Unauthenticated File Access",
      normalizedName: "unauthenticated_file_access",
      category: "access_control",
      cwe: null,
    },
    extraction: {
      parserVersion: "docx-v6",
      warnings: [],
    },
  };

  const result = enhanceReportRecordV7(report);
  assert.equal(result.finding.type, "swagger_api_exposure");
  assert.equal(result.vulnerability.normalizedName, "swagger_api_exposure");
  assert.equal(result.extraction.parserVersion, "docx-v7");
});

test("normalizes profiled other report families into meaningful report types", () => {
  assert.equal(normalizeReportTypeV7("other", { type: "password_policy_violation" }), "misconfiguration");
  assert.equal(normalizeReportTypeV7("other", { type: "cleartext_communication" }), "misconfiguration");
  assert.equal(normalizeReportTypeV7("other", { type: "malicious_indicator_communication" }), "incident");
  assert.equal(normalizeReportTypeV7("other", { type: "suspicious_indicator_communication" }), "incident");
  assert.equal(normalizeReportTypeV7("other", { type: "unusual_scanning" }), "incident");
  assert.equal(normalizeReportTypeV7("other", { type: "malware_tunnel_communication" }), "malware");
  assert.equal(normalizeReportTypeV7("vulnerability", { type: "vulnerable_nextjs" }), "vulnerability");
});

test("corrects a report-date year typo when report number and year hint agree", () => {
  const report = {
    reportNumber: "14040923_250093_35F",
    reportDateRaw: "23/09/1403",
    year: 1403,
    month: 9,
    day: 23,
    title: "گزارش حادثه سایبری - منع سرویس TCP Flood",
    reportType: "incident",
    finding: { type: "tcp_syn_flood", name: "TCP SYN Flood", category: "denial_of_service", cwe: null },
    vulnerability: { name: null, normalizedName: "unknown", category: "unknown", cwe: null },
    extraction: {
      parserVersion: "docx-v6",
      warnings: ["report_year_mismatch:1403:1404"],
    },
  };

  const result = enhanceReportRecordV7(report, { yearHint: 1404 });
  assert.equal(result.year, 1404);
  assert.equal(result.month, 9);
  assert.equal(result.day, 23);
  assert.equal(result.reportDateRaw, "23/09/1403");
  assert.ok(!result.extraction.warnings.includes("report_year_mismatch:1403:1404"));
  assert.ok(result.extraction.warnings.includes("report_date_year_corrected_from_report_number:1403:1404"));
});

test("does not override a genuine previous-year report number", () => {
  const report = {
    reportNumber: "14030307_225279_45F",
    reportDateRaw: "07/03/1403",
    year: 1403,
    month: 3,
    day: 7,
    title: "پیکربندی نامناسب – آسیب‌پذیری API Swagger",
    reportType: "misconfiguration",
    finding: { type: "unauthenticated_file_access", name: "Unauthenticated File Access", category: "access_control", cwe: null },
    vulnerability: { name: "Unauthenticated File Access", normalizedName: "unauthenticated_file_access", category: "access_control", cwe: null },
    extraction: {
      parserVersion: "docx-v6",
      warnings: ["report_year_mismatch:1403:1404"],
    },
  };

  const result = enhanceReportRecordV7(report, { yearHint: 1404 });
  assert.equal(result.year, 1403);
  assert.ok(result.extraction.warnings.includes("report_year_mismatch:1403:1404"));
});

test("exports the v7 parser version", () => {
  assert.equal(PARSER_VERSION, "docx-v7");
});
