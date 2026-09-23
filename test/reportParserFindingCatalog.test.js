const test = require("node:test");
const assert = require("node:assert/strict");

const {
  enhanceReportRecordV6,
  classifyFindingV6,
  vulnerabilityFromFindingV6,
} = require("../src/services/reportParser/findingCatalog");

const profiledFamilies = [
  ["نقض سیاست امنیتی – عدم مدیریت رمز عبور", "password_policy_violation"],
  ["پیکربندی نامناسب – DNS سرور Open Resolver", "open_dns_resolver"],
  ["پیکربندی نامناسب – آسیب‌پذیری WordPress CMS", "vulnerable_wordpress"],
  ["ارتباط مخرب – ارتباط با IP/Domain آلوده", "malicious_indicator_communication"],
  ["پیکربندی نامناسب – استفاده از نسخه آسیب‌پذیر Xampp", "vulnerable_xampp"],
  ["پیکربندی نامناسب – اخذ دسترسی توسط بارگذاری فایل غیرمجاز", "unrestricted_file_upload"],
  ["پیکربندی نامناسب- استفاده از سرویس آسیب‌پذیر Remote Desktop", "exposed_remote_desktop"],
  ["پیکربندی نامناسب - استفاده از نام کاربری و کلمه عبور پیش‌فرض", "default_credentials"],
  ["پیکربندی نامناسب – استفاده از نسخه آسیب‌پذیر Allegro RomPager", "vulnerable_rompager"],
  ["پیکربندی نامناسب – استفاده از نسخه آسیب‌پذیر Liferay", "vulnerable_liferay"],
  ["سوءاستفاده از آسیب‌پذیری- دور‌زدن کنترل‌دسترسی دوربین هایک‌ویژن", "hikvision_access_control_bypass"],
  ["آسیب‌پذیری - نسخه آسیب‌پذیر Next.js", "vulnerable_nextjs"],
  ["نقض سیاست‌های امنیتی – ارتباط در بستر متن آشکار", "cleartext_communication"],
  ["آلودگی به بدافزار – ارتباط با IP/Domain آلوده در بستر Tunnel", "malware_tunnel_communication"],
  ["ارتباط مخرب – ارتباط با آدرس آلوده", "malicious_indicator_communication"],
  ["ارتباط مخرب – ارتباط با IP/Domain مشکوک", "suspicious_indicator_communication"],
  ["پیکربندی نامناسب - استفاده از سرویس آسیب‌پذیر UPnP", "exposed_upnp_service"],
  ["پیکربندی نامناسب - استفاده از نسخه آسیب‌پذیر Cisco ASA/FTD", "vulnerable_cisco_asa_ftd"],
  ["آسیب‌پذیری – استفاده از نسخه آسیب‌پذیر Next.js", "vulnerable_nextjs"],
  ["پیکربندی نامناسب – استفاده از نسخه آسیب‌پذیر Zimbra Collaboration", "vulnerable_zimbra"],
  ["پیکربندی نامناسب – افشای اطلاعات DNS توسط AXFR/IXFR", "dns_zone_transfer_exposure"],
  ["رفتار ناهنجار – پویش نامتعارف", "unusual_scanning"],
  ["پیکربندی نامناسب – عدم اعمال کنترل امنیتی سرویس TFTP", "insecure_tftp_service"],
  ["نقض سیاست‌های امنیتی – استفاده از بستر متن آشکار در پروتکل FTP", "cleartext_communication"],
  ["پیکربندی نامناسب – آسیب‌پذیری Host Header Injection در Plesk Obsidian", "host_header_injection"],
];

test("classifies every title family from the 352-report unknown profile", () => {
  for (const [title, expected] of profiledFamilies) {
    assert.equal(classifyFindingV6(title).type, expected, title);
  }
});

test("keeps malicious, suspicious and malware tunnel communication distinct", () => {
  assert.equal(
    classifyFindingV6("ارتباط مخرب – ارتباط با IP/Domain آلوده").type,
    "malicious_indicator_communication",
  );
  assert.equal(
    classifyFindingV6("ارتباط مخرب – ارتباط با IP/Domain مشکوک").type,
    "suspicious_indicator_communication",
  );
  assert.equal(
    classifyFindingV6("آلودگی به بدافزار – ارتباط با IP/Domain آلوده در بستر Tunnel").type,
    "malware_tunnel_communication",
  );
});

test("normalizes both Next.js title variants into one finding", () => {
  assert.equal(classifyFindingV6("آسیب‌پذیری - نسخه آسیب‌پذیر Next.js").type, "vulnerable_nextjs");
  assert.equal(classifyFindingV6("آسیب‌پذیری – استفاده از نسخه آسیب‌پذیر Next.js").type, "vulnerable_nextjs");
});

test("normalizes generic and FTP cleartext policy findings into one finding", () => {
  assert.equal(classifyFindingV6("نقض سیاست‌های امنیتی – ارتباط در بستر متن آشکار").type, "cleartext_communication");
  assert.equal(classifyFindingV6("نقض سیاست‌های امنیتی – استفاده از بستر متن آشکار در پروتکل FTP").type, "cleartext_communication");
});

test("removes the unknown warning and records parser v6", () => {
  const report = {
    title: "پیکربندی نامناسب – DNS سرور Open Resolver",
    description: "",
    fullText: "",
    finding: { type: "unknown", name: null, category: "unknown", cwe: null },
    vulnerability: { name: null, normalizedName: "unknown", category: "unknown", cwe: null },
    extraction: { parserVersion: "docx-v5", warnings: ["unknown_finding_type", "missing_target_ip"] },
  };

  const enhanced = enhanceReportRecordV6(report);
  assert.equal(enhanced.finding.type, "open_dns_resolver");
  assert.equal(enhanced.extraction.parserVersion, "docx-v6");
  assert.ok(!enhanced.extraction.warnings.includes("unknown_finding_type"));
  assert.ok(enhanced.extraction.warnings.includes("missing_target_ip"));
});

test("maps weakness-like findings while keeping threat communication out of vulnerability stats", () => {
  const next = vulnerabilityFromFindingV6(classifyFindingV6("آسیب‌پذیری - نسخه آسیب‌پذیر Next.js"));
  assert.equal(next.normalizedName, "vulnerable_nextjs");

  const malicious = vulnerabilityFromFindingV6(classifyFindingV6("ارتباط مخرب – ارتباط با IP/Domain آلوده"));
  assert.equal(malicious.normalizedName, "unknown");
});

// Earlier 1404 profiling cases, originally covered through the docx-v5 compatibility exports.

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
    assert.equal(classifyFindingV6(title).type, expected, title);
  }
});

test("prefers exposed RPC when an RPC report body also mentions NTLM", () => {
  const finding = classifyFindingV6([
    "پیکربندی نامناسب- عدم مدیریت سرویس پرخطر RPC",
    "سرویس RPC جهت احراز هویت کاربران خود بطور پیش‌فرض از پروتکل NTLM استفاده می‌کند.",
    "RPC هرگز نباید مستقیماً در معرض اینترنت قرار گیرد.",
  ].join("\n"));
  assert.equal(finding.type, "exposed_rpc");
});

test("recognizes Log4Shell by CVE evidence even when title wording varies", () => {
  const finding = classifyFindingV6(
    "کتابخانه جاوا دارای CVE-2021-44228 و CVE-2021-45046 است و بهره‌برداری Log4Shell رخ می‌دهد.",
  );
  assert.equal(finding.type, "vulnerable_log4j2");
  assert.equal(finding.category, "vulnerable_software");
});

test("removes unknown finding warning after compatibility classification", () => {
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

  const enhanced = enhanceReportRecordV6(report);
  assert.equal(enhanced.finding.type, "defacement");
  assert.equal(enhanced.extraction.parserVersion, "docx-v6");
  assert.ok(!enhanced.extraction.warnings.includes("unknown_finding_type"));
  assert.ok(enhanced.extraction.warnings.includes("missing_target_ip"));
});

test("maps vulnerability-like compatibility findings while keeping incidents out of vulnerability stats", () => {
  const ntlm = vulnerabilityFromFindingV6(classifyFindingV6("استفاده از سرویس آسیب‌پذیر NTLM"));
  assert.equal(ntlm.normalizedName, "vulnerable_ntlm");

  const defacement = vulnerabilityFromFindingV6(classifyFindingV6("حمله Defacement"));
  assert.equal(defacement.normalizedName, "unknown");
});
