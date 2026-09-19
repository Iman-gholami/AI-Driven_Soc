const test = require("node:test");
const assert = require("node:assert/strict");

const {
  PARSER_VERSION,
  classifyFindingV11,
  extractStructuredAssetSystemsV11,
  recoverUnresolvedTargetV11,
} = require("../src/services/reportDocxParserV11");

const cases = [
  ["آلودگی به بدافزار – ارتباط با دامنه بدافزار", "malware_domain_communication"],
  ["نقض سیاست های امنیتی - ارسال اطلاعات به dailyhealthcheck", "unauthorized_external_data_transfer"],
  ["نقض سیاست های امنیتی - ارسال اطلاعات توسط سرویس ابری dubox", "unauthorized_external_data_transfer"],
  ["آلودگی به بدافزار – فعالیت Golang Backdoor", "malware_backdoor_activity"],
  ["سوءاستفاده از آسیب پذیری- آسیب پذیری Clickjack(UI Redress)", "clickjacking"],
  ["مدیریت نادرست خطاها در Laravel", "improper_error_handling"],
  ["ناهنجاری ترافیک – تبادل اطلاعات در بستر DNS Tunnel", "dns_tunneling"],
  ["آلودگی به بدافزار – فعالیت باج افزار Expiro.NDO", "ransomware_activity"],
  ["استفاده از نسخه آسیب پذیر ایمیل سرور IceWarp", "vulnerable_icewarp"],
  ["استفاده از نسخه آسیب پذیر AngularJS", "vulnerable_angularjs"],
  ["کد مخرب – فعالیت بدافزار Bancos", "malware_activity"],
  ["کد مخرب – فعالیت بدافزار Dapato", "malware_activity"],
  ["کد مخرب – فعالیت بدافزار Floxif", "malware_activity"],
  ["کد مخرب – فعالیت بدافزار NSPPS", "malware_activity"],
  ["کد مخرب – فعالیت بدافزار SocGholish", "malware_activity"],
];

for (const [title, expected] of cases) {
  test(`v11 classifies ${expected}`, () => {
    assert.equal(classifyFindingV11(title).type, expected);
  });
}

test("v11 recovers asset IP when the mixed table header is not normalized by v4", () => {
  const tables = [[
    ["جدول 5"],
    ["Domain/URL فیشینگ", "نام سازمان", "IP دارایی", "شرح"],
    ["https://phish.example", "سازمان نمونه", "10.20.30.40", "نمونه"],
  ]];

  const rows = extractStructuredAssetSystemsV11(tables);

  assert.equal(rows.length, 1);
  assert.equal(rows[0].organization, "سازمان نمونه");
  assert.equal(rows[0].ip, "10.20.30.40");
});

test("v11 resolves an otherwise unresolved table target", () => {
  const report = {
    target: {
      mode: "multi_target",
      scopeType: null,
      scopeName: null,
      organization: null,
      ip: null,
      rawOrganization: null,
      rawIp: "جدول 1",
      tableReference: "جدول 1",
    },
    affectedSystems: [],
    affectedCves: [],
    extraction: {
      parserVersion: "docx-v10",
      warnings: [
        "missing_target_ip",
        "multi_target_report",
        "target_table_reference_unresolved",
      ],
      organizationMismatch: false,
      ipMismatch: false,
    },
  };

  const tables = [[
    ["جدول 5"],
    ["Domain/URL فیشینگ", "نام سازمان", "IP دارایی", "شرح"],
    ["https://phish.example", "سازمان نمونه", "10.20.30.40", "نمونه"],
  ]];

  const recovered = recoverUnresolvedTargetV11(report, tables);

  assert.equal(recovered.affectedSystems.length, 1);
  assert.equal(
    recovered.extraction.warnings.includes("target_table_reference_unresolved"),
    false,
  );
  assert.equal(
    recovered.extraction.warnings.includes("structured_asset_table_recovered"),
    true,
  );
});

test("v11 exports parser version", () => {
  assert.equal(PARSER_VERSION, "docx-v11");
});

test("v11 infers an asset IP column when organization header exists but IP header is ambiguous", () => {
  const tables = [[
    ["جدول 5"],
    [
      "Domain/URL فیشینگ",
      "نام سازمان",
      "مقدار مقصد",
      "شرح",
    ],
    [
      "198.51.100.10",
      "سازمان نمونه",
      "10.20.30.40",
      "نمونه",
    ],
  ]];

  const rows = extractStructuredAssetSystemsV11(tables);

  assert.equal(rows.length, 1);
  assert.equal(rows[0].organization, "سازمان نمونه");
  assert.equal(rows[0].ip, "10.20.30.40");
});

test("v11 never infers an affected asset from a phishing-only table", () => {
  const tables = [[
    ["جدول فیشینگ"],
    [
      "Domain/URL فیشینگ",
      "IP فیشینگ",
      "عنوان درگاه فیشینگ",
    ],
    [
      "phish.example",
      "198.51.100.10",
      "نمونه",
    ],
  ]];

  assert.deepEqual(
    extractStructuredAssetSystemsV11(tables),
    [],
  );
});


test("v11 removes stale multi-target warning after resolving to a single asset", () => {
  const report = {
    target: {
      mode: "multi_target",
      scopeType: null,
      scopeName: null,
      organization: null,
      ip: null,
      rawOrganization: null,
      rawIp: "جدول 1",
      tableReference: "جدول 1",
    },
    affectedSystems: [],
    affectedCves: [],
    extraction: {
      parserVersion: "docx-v10",
      warnings: [
        "missing_target_ip",
        "multi_target_report",
        "target_table_reference_unresolved",
      ],
      organizationMismatch: false,
      ipMismatch: false,
    },
  };

  const tables = [[
    ["جدول 1"],
    ["نام سازمان", "مقدار مقصد"],
    ["سازمان نمونه", "10.20.30.40"],
  ]];

  const recovered = recoverUnresolvedTargetV11(report, tables);

  assert.equal(recovered.target.mode, "single");
  assert.equal(
    recovered.extraction.warnings.includes("multi_target_report"),
    false,
  );
  assert.equal(
    recovered.extraction.warnings.includes("target_table_reference_unresolved"),
    false,
  );
});

test("v11 removes stale multi-target warning from final single mode", () => {
  const {
    normalizeTargetModeWarningsV11,
  } = require("../src/services/reportDocxParserV11");

  const report = {
    target: { mode: "single" },
    extraction: {
      warnings: [
        "multi_target_report",
        "target_resolved_from_table",
      ],
    },
  };

  normalizeTargetModeWarningsV11(report);

  assert.equal(
    report.extraction.warnings.includes("multi_target_report"),
    false,
  );
  assert.equal(
    report.extraction.warnings.includes("target_resolved_from_table"),
    true,
  );
});
