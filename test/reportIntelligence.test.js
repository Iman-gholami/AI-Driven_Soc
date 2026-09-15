const test = require("node:test");
const assert = require("node:assert/strict");

const {
  parseWordXml,
  extractReportRecord,
  parseJalaliDate,
  scoreToSeverity,
  classifyVulnerability,
} = require("../src/services/reportDocxParser");
const { planReportQuestion } = require("../src/services/reportCopilotService");

function p(text) {
  return `<w:p><w:r><w:t>${text}</w:t></w:r></w:p>`;
}

function cell(text) {
  return `<w:tc><w:p><w:r><w:t>${text}</w:t></w:r></w:p></w:tc>`;
}

function row(values) {
  return `<w:tr>${values.map(cell).join("")}</w:tr>`;
}

function table(rows) {
  return `<w:tbl>${rows.map(row).join("")}</w:tbl>`;
}

const sampleXml = `
<w:document xmlns:w="urn:test"><w:body>
  ${p("سوءاستفاده از آسیب‌پذیری - آسیب‌پذیری Cross-Site Scripting")}
  ${table([
    ["تاریخ ارائه گزارش:", "01/02/1404", "ارائه‌کننده گزارش:", "مرکز عملیات امنیت افتا"],
    ["شماره گزارش:", "14040201_21_6F", "اطلاعات تماس:", "+98 9"],
  ])}
  ${p("اطلاعات سازمان")}
  ${table([
    ["سازمان هدف:", "شرکت سهامی ابیاری گیاهان", "شدت رخداد:", "6.1"],
    ["آدرس IP:", "62.60.167.73", "فوریت اقدام:", "نیازمند اقدام فوری"],
  ])}
  ${p("شرح رخداد")}
  ${p("Cross-Site Scripting یکی از آسیب‌پذیری‌های مهم وب است.")}
  ${p("سیستم سازمانی جدول 1 به علت عدم کنترل ورودی‌ها، دارای آسیب‌پذیری XSS است.")}
  ${p("جدول 1- جزئیات سیستم سازمانی")}
  ${table([
    ["متد", "پارامتر", "مسیر قابل بهره‌برداری", "دامنه", "نام سازمان", "آدرس سازمان"],
    ["GET", "-", "https://sabir.ir/", "sabir.ir", "شرکت سهامی ساختمان سد و تاسیسات آبیاری (سابیر)", "62.60.167.73"],
  ])}
  ${p("شکل 1- شواهد آسیب‌پذیری XSS")}
  ${p("راهکار")}
  ${p("• بروز رسانی منظم سرویس و نرم‌افزارها تحت وب")}
  ${p("• استفاده از فایروال مختص برنامه‌های وب (WAF)")}
</w:body></w:document>`;

test("parses WordprocessingML into paragraphs and tables", () => {
  const parsed = parseWordXml(sampleXml);
  assert.ok(parsed.paragraphs.includes("شرح رخداد"));
  assert.equal(parsed.tables.length, 3);
  assert.equal(parsed.tables[2][1][2], "https://sabir.ir/");
});

test("extracts the known 1404 report template deterministically", () => {
  const parsed = parseWordXml(sampleXml);
  const report = extractReportRecord(parsed, { yearHint: 1404 });

  assert.equal(report.reportNumber, "14040201_21_6F");
  assert.equal(report.year, 1404);
  assert.equal(report.month, 2);
  assert.equal(report.day, 1);
  assert.equal(report.target.organization, "شرکت سهامی ابیاری گیاهان");
  assert.equal(report.target.ip, "62.60.167.73");
  assert.equal(report.severity.score, 6.1);
  assert.equal(report.severity.level, "medium");
  assert.equal(report.urgency.normalized, "immediate");
  assert.equal(report.vulnerability.normalizedName, "xss");
  assert.equal(report.vulnerability.cwe, "CWE-79");
  assert.equal(report.affectedSystems.length, 1);
  assert.equal(report.affectedSystems[0].method, "GET");
  assert.equal(report.affectedSystems[0].domain, "sabir.ir");
  assert.equal(report.affectedSystems[0].ip, "62.60.167.73");
  assert.equal(report.recommendations.length, 2);
  assert.equal(report.extraction.organizationMismatch, true);
  assert.equal(report.extraction.ipMismatch, false);
});

test("normalizes dates, severity and common vulnerability names", () => {
  assert.deepEqual(parseJalaliDate("۰۱/۰۲/۱۴۰۴"), { day: 1, month: 2, year: 1404 });
  assert.equal(scoreToSeverity(9.2), "critical");
  assert.equal(scoreToSeverity(7.4), "high");
  assert.equal(scoreToSeverity(6.1), "medium");
  assert.equal(classifyVulnerability("آسیب‌پذیری SQL Injection").normalizedName, "sql_injection");
});

test("plans deterministic report statistics questions", () => {
  assert.deepEqual(
    planReportQuestion("در سال ۱۴۰۴ چند گزارش XSS داشتیم؟"),
    { operation: "count", year: 1404, severity: null, vulnerability: "xss", urgency: null },
  );

  assert.equal(planReportQuestion("بیشترین آسیب‌پذیری سال 1404 چه بوده؟").operation, "top_vulnerabilities");
  assert.equal(planReportQuestion("کدام سازمان بیشترین گزارش High داشته؟").severity, "high");
  assert.equal(planReportQuestion("چند درصد گزارش‌های ۱۴۰۴ نیازمند اقدام فوری بوده‌اند؟").operation, "immediate_percentage");
  assert.equal(planReportQuestion("روند ماهانه گزارش‌های ۱۴۰۴ را نشان بده").operation, "monthly_trend");
  assert.equal(planReportQuestion("برای IP 62.60.167.73 چه گزارش‌هایی داریم؟").operation, "ip_reports");
});
