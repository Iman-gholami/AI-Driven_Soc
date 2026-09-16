const test = require("node:test");
const assert = require("node:assert/strict");

const {
  PARSER_VERSION,
  enhanceReportRecordV9,
  extractTableReference,
  classifyScope,
} = require("../src/services/reportDocxParserV9");

function baseReport(overrides = {}) {
  return {
    title: "نمونه گزارش",
    target: {
      organization: "سازمان نمونه",
      ip: null,
      rawIp: null,
    },
    affectedSystems: [],
    extraction: {
      parserVersion: "docx-v8",
      warnings: [],
      organizationMismatch: false,
      ipMismatch: false,
    },
    ...overrides,
  };
}

test("v9 recognizes Persian and ASCII table references", () => {
  assert.equal(extractTableReference("جدول 2"), "جدول 2");
  assert.equal(extractTableReference("مطابق جدول شماره ۲"), "جدول شماره 2");
  assert.equal(extractTableReference("10.0.0.1"), null);
});

test("v9 classifies sector and organization-group scope labels conservatively", () => {
  assert.equal(classifyScope("حوزه اقتصادی").type, "sector");
  assert.equal(classifyScope("دستگاه های اجرایی تابعه").type, "organization_group");
  assert.equal(classifyScope("استان خوزستان").type, "geographic");
  assert.equal(classifyScope("شهرداری اهواز").type, null);
});

test("v9 keeps a scoped multi-target report at report level and assets in affectedSystems", () => {
  const report = enhanceReportRecordV9(baseReport({
    target: {
      organization: "حوزه اقتصادی",
      ip: null,
      rawIp: "جدول 2",
    },
    affectedSystems: [
      { organization: "سازمان الف", ip: "10.0.0.1" },
      { organization: "سازمان ب", ip: "10.0.0.2" },
    ],
    extraction: {
      parserVersion: "docx-v8",
      warnings: [
        "missing_target_ip",
        "target_ip_referenced_in_table",
        "target_organization_differs_from_affected_system",
      ],
      organizationMismatch: true,
      ipMismatch: false,
    },
  }));

  assert.equal(report.target.mode, "scope");
  assert.equal(report.target.scopeType, "sector");
  assert.equal(report.target.scopeName, "حوزه اقتصادی");
  assert.equal(report.target.organization, null);
  assert.equal(report.target.ip, null);
  assert.equal(report.target.rawOrganization, "حوزه اقتصادی");
  assert.equal(report.target.tableReference, "جدول 2");
  assert.equal(report.extraction.organizationMismatch, false);
  assert.equal(report.extraction.ipMismatch, false);
  assert.equal(report.extraction.warnings.includes("scope_target_detected"), true);
  assert.equal(report.extraction.warnings.includes("target_assets_resolved_from_table"), true);
  assert.equal(report.extraction.warnings.includes("missing_target_ip"), false);
  assert.equal(report.extraction.warnings.includes("target_organization_differs_from_affected_system"), false);
  assert.equal(report.extraction.parserVersion, PARSER_VERSION);
});

test("v9 derives a single target when a referenced table contains one organization/IP pair", () => {
  const report = enhanceReportRecordV9(baseReport({
    target: {
      organization: "حوزه اقتصادی",
      ip: "10.0.0.9",
      rawIp: "جدول شماره ۳",
    },
    affectedSystems: [
      { organization: "سازمان نهایی", ip: "10.0.0.9" },
    ],
    extraction: {
      parserVersion: "docx-v8",
      warnings: ["target_ip_referenced_in_table", "target_ip_derived_from_affected_system"],
      organizationMismatch: true,
      ipMismatch: false,
    },
  }));

  assert.equal(report.target.mode, "single");
  assert.equal(report.target.organization, "سازمان نهایی");
  assert.equal(report.target.ip, "10.0.0.9");
  assert.equal(report.target.scopeName, null);
  assert.equal(report.target.tableReference, "جدول شماره 3");
  assert.equal(report.extraction.warnings.includes("target_resolved_from_table"), true);
  assert.equal(report.extraction.warnings.includes("target_ip_referenced_in_table"), false);
});

test("v9 resolves a table reference supplied in the organization field", () => {
  const report = enhanceReportRecordV9(baseReport({
    target: {
      organization: "مطابق جدول 4",
      ip: null,
      rawIp: null,
    },
    affectedSystems: [
      { organization: "سازمان الف", ip: "10.0.0.1" },
      { organization: "سازمان ب", ip: "10.0.0.2" },
    ],
  }));

  assert.equal(report.target.mode, "multi_target");
  assert.equal(report.target.organization, null);
  assert.equal(report.target.ip, null);
  assert.equal(report.target.rawOrganization, "مطابق جدول 4");
  assert.equal(report.target.tableReference, "جدول 4");
  assert.equal(report.extraction.warnings.includes("multi_target_report"), true);
  assert.equal(report.extraction.warnings.includes("target_assets_resolved_from_table"), true);
});

test("v9 leaves ordinary single-target reports semantically unchanged", () => {
  const report = enhanceReportRecordV9(baseReport({
    target: {
      organization: "شهرداری اهواز",
      ip: "10.20.30.40",
      rawIp: "10.20.30.40",
    },
  }));

  assert.equal(report.target.mode, "single");
  assert.equal(report.target.organization, "شهرداری اهواز");
  assert.equal(report.target.ip, "10.20.30.40");
  assert.equal(report.target.scopeType, null);
  assert.equal(report.target.scopeName, null);
  assert.equal(report.target.tableReference, null);
});
