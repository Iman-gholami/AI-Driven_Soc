const test = require("node:test");
const assert = require("node:assert/strict");

const {
  STAGE_VERSION,
  enhanceReportRecordV8,
  classifyFindingV8,
  normalizeReportTypeV8,
} = require("../src/services/reportParser/aptTitleFinding");

test("classifies malicious-code APT reports from the explicit title", () => {
  const finding = classifyFindingV8("کد مخرب – فعالیت APT");
  assert.equal(finding.type, "apt_malicious_code_activity");
  assert.equal(finding.category, "advanced_persistent_threat");
});

test("APT title overrides an older broad phishing finding", () => {
  const report = {
    title: "کد مخرب – فعالیت APT",
    reportType: "other",
    finding: {
      type: "phishing",
      name: "Phishing",
      category: "social_engineering",
      cwe: null,
    },
    vulnerability: {
      name: null,
      normalizedName: "unknown",
      category: "unknown",
      cwe: null,
    },
    extraction: {
      parserVersion: "docx-v7",
      warnings: [],
    },
  };

  const result = enhanceReportRecordV8(report);
  assert.equal(result.finding.type, "apt_malicious_code_activity");
  assert.equal(result.finding.name, "APT Malicious Code Activity");
  assert.equal(result.reportType, "malware");
  assert.equal(result.vulnerability.normalizedName, "unknown");
  assert.equal(result.extraction.parserVersion, "docx-v8");
});

test("normalizes APT malicious-code reports to malware", () => {
  assert.equal(
    normalizeReportTypeV8("other", { type: "apt_malicious_code_activity" }),
    "malware",
  );
});

test("exports parser version v8", () => {
  assert.equal(STAGE_VERSION, "docx-v8");
});
