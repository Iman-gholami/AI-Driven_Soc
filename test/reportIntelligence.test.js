const test = require("node:test");
const assert = require("node:assert/strict");

const {
  parseWordXml,
  extractReportRecord,
  parseJalaliDate,
  scoreToSeverity,
  classifyFinding,
  classifyVulnerability,
  parseTrafficBytes,
  extractCves,
} = require("../src/services/reportDocxParser");
const { planReportQuestion } = require("../src/services/reportCopilotService");
const {
  UnifiedCopilotService,
  looksLikeHistoricalReportQuestion,
} = require("../src/services/unifiedCopilotService");

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

const sampleXml = documentXml([
  p("سوءاستفاده از آسیب‌پذیری - آسیب‌پذیری Cross-Site Scripting"),
  table([
    ["تاریخ ارائه گزارش:", "01/02/1404", "ارائه‌کننده گزارش:", "مرکز عملیات امنیت افتا"],
    ["شماره گزارش:", "14040201_21_6F", "اطلاعات تماس:", "+98 9"],
  ]),
  p("اطلاعات سازمان"),
  table([
    ["سازمان هدف:", "شرکت سهامی ابیاری گیاهان", "شدت رخداد:", "6.1"],
    ["آدرس IP:", "62.60.167.73", "فوریت اقدام:", "نیازمند اقدام فوری"],
  ]),
  p("شرح رخداد"),
  p("Cross-Site Scripting یکی از آسیب‌پذیری‌های مهم وب است."),
  p("سیستم سازمانی جدول 1 به علت عدم کنترل ورودی‌ها، دارای آسیب‌پذیری XSS است."),
  p("جدول 1- جزئیات سیستم سازمانی"),
  table([
    ["متد", "پارامتر", "مسیر قابل بهره‌برداری", "دامنه", "نام سازمان", "آدرس سازمان"],
    ["GET", "-", "https://sabir.ir/", "sabir.ir", "شرکت سهامی ساختمان سد و تاسیسات آبیاری (سابیر)", "62.60.167.73"],
  ]),
  p("شکل 1- شواهد آسیب‌پذیری XSS"),
  p("راهکار"),
  p("• بروز رسانی منظم سرویس و نرم‌افزارها تحت وب"),
  p("• استفاده از فایروال مختص برنامه‌های وب (WAF)"),
]);

const dependencyConfusionXml = documentXml([
  p("پیکربندی نامناسب – احتمال آسیب‌پذیری Dependency Confusion"),
  table([
    ["تاریخ ارائه گزارش:", "04/01/1404", "ارائه‌کننده گزارش:", "مرکز ابیاری ایران"],
    ["شماره گزارش:", "14040104_211298_45F", "اطلاعات تماس:", "02143439999"],
  ]),
  table([
    ["سازمان هدف:", "شرکت پشمک ایران", "شدت رخداد:", "7.8"],
    ["آدرس IP:", "x.x.x.x", "فوریت اقدام:", "نیازمند اقدام"],
  ]),
  p("شرح رخداد"),
  p("نمونه‌ای از این آسیب‌پذیری شناسه CVE-2018-20225 است و Dependency Confusion ممکن است رخ دهد."),
  table([
    ["آدرس سازمان", "نام سازمان", "مسیر دسترسی"],
    ["185.255.88.182", "شرکت پشمک ایران", "http://185.255.88.182/phpmyadmin/package.json"],
  ]),
  p("راهکار"),
  p("• اعمال سطح دسترسی امن برای فایل Dependency"),
  p("منابع"),
  p("https://example.invalid"),
]);

const udpAmplificationXml = documentXml([
  p("گزارش رخداد سایبری - منع سرویس UDP Amplification"),
  table([
    ["تاریخ ارائه گزارش:", "06/01/1404", "ارائه‌کننده گزارش:", "مرکز ابیاری"],
    ["شماره گزارش:", "14040106_211591_39F", "شماره تماس:", "9"],
  ]),
  table([
    ["سازمان هدف:", "پفک تهران", "اثر رخداد:", "عدم دسترسی به سرویس‌ها"],
    ["آدرس IP:", "x.x.x.x", "فوریت اقدام:", "جهت اطلاع"],
  ]),
  p("شرح رخداد"),
  p("سیستم تحت حمله منع سرویس توزیع‌شده از نوع UDP Amplification قرار گرفته است."),
  table([
    ["آدرس سازمان", "نام سازمان", "سرویس", "حجم ترافیک", "تعداد IP شرکت‌کننده", "تاریخ", "بازه زمانی"],
    ["10.30.89.17", "پفک تهران", "SSDP/UPnP (Port 1900)", "8.10 GB", "1669", "1404/01/05", "23:21 – 23:40"],
  ]),
  p("راهکارهای جامع مقابله با حملات منع سرویس"),
  p("o فعالسازی قابلیت Rate Limiting"),
]);

const tcpFloodXml = documentXml([
  p("گزارش حادثه سایبری - منع سرویس TCP Flood"),
  table([
    ["تاریخ ارائه گزارش:", "06/01/1404", "ارائه‌کننده گزارش:", "مرکز بیاری"],
    ["شماره گزارش:", "14040106_211828_46F", "شماره تماس:", "9"],
  ]),
  table([
    ["سازمان هدف:", "سازمان خرسازی", "اثر حادثه:", "عدم دسترسی به سرویس‌ها"],
    ["آدرس IP:", "x.x.x.x", "فوریت اقدام:", "جهت اطلاع"],
  ]),
  p("شرح حادثه"),
  p("در حمله Syn Flood تعداد زیادی بسته SYN به سمت سرویس سازمان ارسال شده است."),
  table([
    ["IP سازمانی", "نام سازمان", "دامنه", "پورت", "مجموع بسته‌های ارسال‌شده", "تعداد IPهای شرکت‌کننده در حمله", "تاریخ", "بازه زمانی"],
    ["10.1.2.3", "سازمان خرسازی", "example.ir", "80", "30,434,842", "6,255", "1404/01/06", "08:40 – 14:30"],
  ]),
  p("راهکارهای جامع مقابله با حملات منع سرویس"),
  p("o فعالسازی Syn Cookie"),
]);

const routerOsXml = documentXml([
  p("پیکربندی نامناسب - استفاده از نسخه آسیب‌پذیر Mikrotik RouterOS"),
  table([
    ["تاریخ ارائه گزارش:", "13/01/1404", "ارائه‌کننده گزارش:", "مرکزبیاری"],
    ["شماره گزارش:", "14040113_212081_45F", "اطلاعات تماس:", "9"],
  ]),
  table([
    ["سازمان هدف:", "سازمان نوشمک سازی", "شدت رخداد:", "7.5"],
    ["آدرس IP:", "X.X.X.X", "فوریت اقدام:", "نیازمند اقدام فوری"],
  ]),
  p("شرح رخداد"),
  p("MikroTik RouterOS در نسخه‌های قدیمی دارای چند آسیب‌پذیری است."),
  table([
    ["آسیب‌پذیری", "تشریح آسیب پذیری", "CVSS", "نسخه‌های آسیب پذیر"],
    ["CVE-2022-45315", "اجرای کد", "9.8", "x < 7.6"],
    ["CVE-2022-45313", "اجرای کد", "8.8", "x < 7.5"],
  ]),
  table([
    ["نوع آسیب پذیری", "نسخه RouterOS", "پورت", "نام سازمان", "آدرس سازمان"],
    ["CVE-2018-5951 CVE-2021-3014 CVE-2023-41570 Graphs_Access", "7.6", "8088", "سازمان نوشمک سازی", "10.20.30.40"],
  ]),
  p("راهکار"),
  p("• به‌روزرسانی RouterOS به آخرین نسخه"),
]);

test("parses WordprocessingML into paragraphs and tables", () => {
  const parsed = parseWordXml(sampleXml);
  assert.ok(parsed.paragraphs.includes("شرح رخداد"));
  assert.equal(parsed.tables.length, 3);
  assert.equal(parsed.tables[2][1][2], "https://sabir.ir/");
});

test("extracts the known 1404 XSS report template deterministically", () => {
  const report = extractReportRecord(parseWordXml(sampleXml), { yearHint: 1404 });

  assert.equal(report.reportNumber, "14040201_21_6F");
  assert.equal(report.year, 1404);
  assert.equal(report.month, 2);
  assert.equal(report.day, 1);
  assert.equal(report.target.organization, "شرکت سهامی ابیاری گیاهان");
  assert.equal(report.target.ip, "62.60.167.73");
  assert.equal(report.severity.score, 6.1);
  assert.equal(report.severity.level, "medium");
  assert.equal(report.urgency.normalized, "immediate");
  assert.equal(report.finding.type, "xss");
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

test("extracts dependency confusion and derives a real IP from the affected-system table", () => {
  const report = extractReportRecord(parseWordXml(dependencyConfusionXml), { yearHint: 1404 });
  assert.equal(report.reportType, "misconfiguration");
  assert.equal(report.finding.type, "dependency_confusion");
  assert.equal(report.severity.level, "high");
  assert.equal(report.urgency.normalized, "action_required");
  assert.equal(report.target.rawIp, "x.x.x.x");
  assert.equal(report.target.ip, "185.255.88.182");
  assert.equal(report.affectedSystems[0].url, "http://185.255.88.182/phpmyadmin/package.json");
  assert.ok(report.cves.includes("CVE-2018-20225"));
  assert.ok(report.extraction.warnings.includes("target_ip_derived_from_affected_system"));
  assert.equal(report.recommendations.length, 1);
});

test("extracts UDP amplification traffic metrics and informational urgency", () => {
  const report = extractReportRecord(parseWordXml(udpAmplificationXml), { yearHint: 1404 });
  assert.equal(report.reportType, "incident");
  assert.equal(report.finding.type, "udp_amplification");
  assert.equal(report.urgency.normalized, "informational");
  assert.equal(report.effect, "عدم دسترسی به سرویس‌ها");
  assert.equal(report.target.ip, "10.30.89.17");
  assert.equal(report.affectedSystems[0].port, 1900);
  assert.equal(report.affectedSystems[0].participantIpCount, 1669);
  assert.equal(report.affectedSystems[0].trafficVolumeRaw, "8.10 GB");
  assert.equal(report.affectedSystems[0].eventYear, 1404);
  assert.equal(report.affectedSystems[0].eventMonth, 1);
  assert.equal(report.recommendations[0], "فعالسازی قابلیت Rate Limiting");
});

test("extracts TCP SYN flood packet and participant counts from incident tables", () => {
  const report = extractReportRecord(parseWordXml(tcpFloodXml), { yearHint: 1404 });
  assert.equal(report.reportType, "incident");
  assert.equal(report.finding.type, "tcp_syn_flood");
  assert.equal(report.effect, "عدم دسترسی به سرویس‌ها");
  assert.equal(report.target.ip, "10.1.2.3");
  assert.equal(report.affectedSystems[0].port, 80);
  assert.equal(report.affectedSystems[0].packetCount, 30434842);
  assert.equal(report.affectedSystems[0].participantIpCount, 6255);
  assert.equal(report.affectedSystems[0].timeRange, "08:40 – 14:30");
});

test("keeps reference CVEs separate while extracting the affected RouterOS system", () => {
  const report = extractReportRecord(parseWordXml(routerOsXml), { yearHint: 1404 });
  assert.equal(report.reportType, "misconfiguration");
  assert.equal(report.finding.type, "vulnerable_routeros");
  assert.equal(report.severity.level, "high");
  assert.equal(report.affectedSystems.length, 1);
  assert.equal(report.affectedSystems[0].softwareVersion, "7.6");
  assert.equal(report.affectedSystems[0].port, 8088);
  assert.deepEqual(report.affectedSystems[0].cves, ["CVE-2018-5951", "CVE-2021-3014", "CVE-2023-41570"]);
  assert.ok(report.cves.includes("CVE-2022-45315"));
  assert.ok(report.cves.includes("CVE-2023-41570"));
});

test("normalizes dates, severity, traffic sizes and common findings", () => {
  assert.deepEqual(parseJalaliDate("۰۱/۰۲/۱۴۰۴"), { day: 1, month: 2, year: 1404 });
  assert.equal(scoreToSeverity(9.2), "critical");
  assert.equal(scoreToSeverity(7.4), "high");
  assert.equal(scoreToSeverity(6.1), "medium");
  assert.equal(classifyVulnerability("آسیب‌پذیری SQL Injection").normalizedName, "sql_injection");
  assert.equal(classifyFinding("گزارش منع سرویس UDP Amplification").type, "udp_amplification");
  assert.equal(parseTrafficBytes("8.10 GB"), Math.round(8.1 * (1024 ** 3)));
  assert.deepEqual(extractCves("CVE-2022-45315 و CVE-2022-45315 و CVE-2020-20231"), ["CVE-2022-45315", "CVE-2020-20231"]);
});

test("plans deterministic report statistics questions", () => {
  const xssPlan = planReportQuestion("در سال ۱۴۰۴ چند گزارش XSS داشتیم؟");
  assert.equal(xssPlan.operation, "count");
  assert.equal(xssPlan.year, 1404);
  assert.equal(xssPlan.finding, "xss");

  assert.equal(planReportQuestion("بیشترین آسیب‌پذیری سال 1404 چه بوده؟").operation, "top_vulnerabilities");
  assert.equal(planReportQuestion("بیشترین Finding سال 1404 چه بوده؟").operation, "top_findings");
  assert.equal(planReportQuestion("کدام سازمان بیشترین گزارش High داشته؟").severity, "high");
  assert.equal(planReportQuestion("کدام سازمان بیشترین گزارش UDP Amplification داشته؟").finding, "udp_amplification");
  assert.equal(planReportQuestion("در سال 1404 چند گزارش حادثه داشتیم؟").reportType, "incident");
  assert.equal(planReportQuestion("روی پورت 443 چند گزارش ثبت شده؟").port, 443);
  assert.equal(planReportQuestion("چند درصد گزارش‌های ۱۴۰۴ نیازمند اقدام فوری بوده‌اند؟").operation, "immediate_percentage");
  assert.equal(planReportQuestion("روند ماهانه گزارش‌های ۱۴۰۴ را نشان بده").operation, "monthly_trend");
  assert.equal(planReportQuestion("برای IP 62.60.167.73 چه گزارش‌هایی داریم؟").operation, "ip_reports");
});

test("recognizes historical report questions without hijacking normal SOC questions", () => {
  assert.equal(looksLikeHistoricalReportQuestion("در سال ۱۴۰۴ چند گزارش XSS داشتیم؟"), true);
  assert.equal(looksLikeHistoricalReportQuestion("بیشترین گزارش High برای کدام سازمان بوده؟"), true);
  assert.equal(looksLikeHistoricalReportQuestion("این alert چرا malicious شده؟"), false);
});

test("routes report questions through deterministic report data before the LLM planner", async () => {
  const service = new UnifiedCopilotService({
    reportCopilot: {
      async query() {
        return {
          supported: true,
          answer: "در سال 1404، 70 گزارش ثبت شده است.",
          plan: { operation: "count", year: 1404 },
          data: { count: 70 },
        };
      },
    },
    llm: {},
    mcpClient: {},
  });

  const result = await service.query("در سال 1404 چند گزارش داشتیم؟");
  assert.equal(result.tool, "query_historical_reports");
  assert.equal(result.result.count, 70);
  assert.equal(result.metadata.deterministic, true);
  assert.equal(result.metadata.readOnly, true);
});
