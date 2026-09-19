const test = require("node:test");
const assert = require("node:assert/strict");

const base = require("../src/services/reportDocxParser");
const {
  enhanceReportRecord,
  classifyFindingV4,
  extractAffectedSystemsV4,
  extractRecommendationsFromTables,
  extractPhishingInfrastructure,
} = require("../src/services/reportDocxParserV4");
const { updateQualitySummary } = require("../src/services/reportImportService");

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

function documentXml(parts) {
  return `<w:document xmlns:w="urn:test"><w:body>${parts.join("\n")}</w:body></w:document>`;
}

function enhanced(xml) {
  const parsed = base.parseWordXml(xml);
  return enhanceReportRecord(base.extractReportRecord(parsed, { yearHint: 1404 }), parsed);
}

test("classifies newly observed real 1404 finding families", () => {
  assert.equal(
    classifyFindingV4("گزارش حادثه سایبری – اخذ دسترسی و اجرای دستور از راه دور").type,
    "remote_access_command_execution",
  );
  assert.equal(
    classifyFindingV4("سوءاستفاده از آسیب‌پذیری- اخذ دسترسی غیرمجاز و بارگذاری وب‌شل").type,
    "webshell_compromise",
  );
  assert.equal(
    classifyFindingV4("کد مخرب – فعالیت بدافزار Zbot / Zeus").type,
    "malware_zeus",
  );
  assert.equal(
    classifyFindingV4("گزارش حادثه سایبری - حمله Phishing").type,
    "phishing",
  );
});

test("enhances a web-shell exploitation report without treating it as a generic RCE vulnerability", () => {
  const xml = documentXml([
    p("سوءاستفاده از آسیب‌پذیری- اخذ دسترسی غیرمجاز و بارگذاری وب‌شل"),
    table([
      ["تاریخ ارائه گزارش:", "02/01/1404", "شماره گزارش:", "14040102_211184_44F"],
      ["سازمان هدف:", "شرکت نمونه", "شدت رخداد:", "10"],
      ["آدرس IP:", "x.x.x.x", "فوریت اقدام:", "نیازمند اقدام فوری"],
    ]),
    p("شرح حادثه"),
    p("وب‌شل یک اسکریپت مخرب برای حفظ دسترسی راه دور است."),
    table([
      ["جدول 1- جزئیات ارتباطات"],
      ["زمان", "مسیر وب شل", "دامنه سازمانی", "نام سازمان", "IP سازمان"],
      ["1403/12/30", "/shell.php", "example.ir", "شرکت نمونه", "10.10.10.10"],
    ]),
  ]);

  const report = enhanced(xml);
  assert.equal(report.finding.type, "webshell_compromise");
  assert.equal(report.reportType, "vulnerability");
  assert.equal(report.target.ip, "10.10.10.10");
  assert.equal(report.affectedSystems.length, 1);
  assert.equal(report.affectedSystems[0].url, "/shell.php");
  assert.equal(report.affectedSystems[0].domain, "example.ir");
  assert.equal(report.affectedSystems[0].eventDateRaw, "1403/12/30");
  assert.ok(!report.extraction.warnings.includes("unknown_finding_type"));
});

test("classifies Zeus malware from the title", () => {
  const xml = documentXml([
    p("کد مخرب – فعالیت بدافزار Zbot / Zeus"),
    table([
      ["تاریخ ارائه گزارش:", "04/01/1404", "شماره گزارش:", "14040104_200877_27F"],
      ["سازمان هدف:", "دانشگاه نمونه", "شدت رخداد:", "8"],
      ["آدرس IP:", "x.x.x.x", "فوریت اقدام:", "نیازمند اقدام"],
    ]),
    p("شرح حادثه"),
    p("بدافزار Zbot که با نام Zeus نیز شناخته می‌شود با سرور C2 ارتباط برقرار می‌کند."),
  ]);

  const report = enhanced(xml);
  assert.equal(report.reportType, "malware");
  assert.equal(report.finding.type, "malware_zeus");
  assert.equal(report.finding.category, "malware");
  assert.equal(report.severity.level, "high");
});

test("extracts phishing infrastructure as indicators rather than affected organizational systems", () => {
  const xml = documentXml([
    p("گزارش حادثه سایبری - حمله Phishing"),
    table([
      ["تاریخ ارائه گزارش:", "15/01/1404", "شماره گزارش:", "14040115_212416_45F"],
      ["سازمان هدف:", "سازمان نمونه", "شدت رخداد:", "10"],
      ["آدرس IP:", "x.x.x.x", "فوریت اقدام:", "نیازمند اقدام فوری"],
    ]),
    p("شرح رخداد"),
    p("دامنه فیشینگ شناسایی شده است."),
    table([
      ["جدول 1- مشخصات دامنه فیشینگ شناسایی‌شده"],
      ["Domain/URL فیشینگ", "IP فیشینگ", "عنوان درگاه فیشینگ"],
      ["https://login-example.ir/auth", "1.2.3.4", "درگاه پرداخت"],
    ]),
  ]);

  const report = enhanced(xml);
  assert.equal(report.finding.type, "phishing");
  assert.equal(report.phishingInfrastructure.length, 1);
  assert.equal(report.phishingInfrastructure[0].domain, "login-example.ir");
  assert.equal(report.phishingInfrastructure[0].ip, "1.2.3.4");
  assert.equal(report.affectedSystems.length, 0);
  assert.ok(report.indicators.some((item) => item.type === "domain" && item.value === "login-example.ir"));
  assert.ok(report.indicators.some((item) => item.type === "ip" && item.value === "1.2.3.4"));
});

test("finds asset table headers below a caption row", () => {
  const tables = [[
    ["جدول 1- جزئیات رخداد"],
    ["IP سازمانی", "نام سازمان", "پورت", "مجموع بسته‌های ارسال‌شده"],
    ["10.0.0.1", "سازمان نمونه", "443", "3,503,201,704"],
  ]];

  const rows = extractAffectedSystemsV4(tables);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].ip, "10.0.0.1");
  assert.equal(rows[0].port, 443);
  assert.equal(rows[0].packetCount, 3503201704);
});

test("extracts recommendations embedded inside Word tables", () => {
  const tables = [[
    ["راهکارهای جامع مقابله با حملات منع سرویس"],
    ["o فعالسازی قابلیت Rate Limiting"],
    ["o استفاده از ACL برای محدودسازی دسترسی"],
    ["منابع"],
    ["https://example.invalid"],
  ]];

  assert.deepEqual(extractRecommendationsFromTables(tables), [
    "فعالسازی قابلیت Rate Limiting",
    "استفاده از ACL برای محدودسازی دسترسی",
  ]);
});

test("quality summary exposes all unknown findings instead of relying on the first 20 previews", () => {
  const quality = {
    unknownFindingCount: 0,
    unknownFindingFiles: [],
    findingCounts: {},
    reportTypeCounts: {},
    warningCounts: {},
  };

  updateQualitySummary(quality, {
    reportType: "incident",
    finding: { type: "unknown" },
    extraction: { warnings: ["unknown_finding_type"] },
  }, "1404/example.docx");

  assert.equal(quality.unknownFindingCount, 1);
  assert.deepEqual(quality.unknownFindingFiles, ["1404/example.docx"]);
  assert.equal(quality.findingCounts.unknown, 1);
  assert.equal(quality.reportTypeCounts.incident, 1);
  assert.equal(quality.warningCounts.unknown_finding_type, 1);
});

test("extractPhishingInfrastructure ignores non-phishing tables", () => {
  const rows = extractPhishingInfrastructure([[
    ["IP سازمانی", "نام سازمان"],
    ["10.0.0.1", "سازمان نمونه"],
  ]]);
  assert.deepEqual(rows, []);
});
