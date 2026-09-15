const test = require("node:test");
const assert = require("node:assert/strict");

const {
  enhanceReportRecordV5,
  classifyFindingV5,
  vulnerabilityFromFindingV5,
} = require("../src/services/reportDocxParserV5");

const observedFamilies = [
  ["پیکربندی نامناسب - دسترسی نامجاز و بدون احراز هویت", "unauthenticated_file_access"],
  ["پیکربندی نامناسب – آسیب‌پذیری Slow HTTP DoS", "slow_http_dos"],
  ["گزارش رخداد سایبری – منع سرویسUDP Flood", "udp_flood"],
  ["گزارش حادثه سایبری - حمله Defacement", "defacement"],
  ["پیکربندی نامناسب – استفاده از سرویس آسیب‌پذیر NTLM", "vulnerable_ntlm"],
  ["پیکربندی نامناسب – دسترسی بدون احراز هویت به سرویس Redis", "unauthenticated_redis"],
  ["پیکربندی نامناسب- عدم مدیریت سرویس پرخطر RPC", "exposed_rpc"],
  ["آسیب‌پذیری - استفاده از نسخه آسیب‌پذیر Apache Log4j2", "vulnerable_log4j2"],
];

test("classifies all remaining observed 1404 report families", () => {
  for (const [title, expected] of observedFamilies) {
    assert.equal(classifyFindingV5(title).type, expected, title);
  }
});

test("recognizes Log4Shell by CVE evidence even when title wording varies", () => {
  const finding = classifyFindingV5(
    "کتابخانه جاوا دارای CVE-2021-44228 و CVE-2021-45046 است و بهره‌برداری Log4Shell رخ می‌دهد.",
  );
  assert.equal(finding.type, "vulnerable_log4j2");
  assert.equal(finding.category, "vulnerable_software");
});

test("removes unknown finding warning after v5 classification", () => {
  const report = {
    title: "گزارش حادثه سایبری - حمله Defacement",
    description: "",
    fullText: "",
    finding: { type: "unknown", name: null, category: "unknown", cwe: null },
    vulnerability: { name: null, normalizedName: "unknown", category: "unknown", cwe: null },
    extraction: {
      parserVersion: "docx-v4",
      warnings: ["unknown_finding_type", "missing_target_ip"],
    },
  };

  const enhanced = enhanceReportRecordV5(report);
  assert.equal(enhanced.finding.type, "defacement");
  assert.equal(enhanced.extraction.parserVersion, "docx-v5");
  assert.ok(!enhanced.extraction.warnings.includes("unknown_finding_type"));
  assert.ok(enhanced.extraction.warnings.includes("missing_target_ip"));
});

test("maps vulnerability-like v5 findings while keeping incidents out of vulnerability stats", () => {
  const ntlm = vulnerabilityFromFindingV5(classifyFindingV5("استفاده از سرویس آسیب‌پذیر NTLM"));
  assert.equal(ntlm.normalizedName, "vulnerable_ntlm");

  const defacement = vulnerabilityFromFindingV5(classifyFindingV5("حمله Defacement"));
  assert.equal(defacement.normalizedName, "unknown");
});
