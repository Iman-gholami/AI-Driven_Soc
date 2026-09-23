const test = require("node:test");
const assert = require("node:assert/strict");

const {
  STAGE_VERSION,
  extractMixedAssetSystemsV10,
  recoverUnresolvedTargetV10,
} = require("../src/services/reportParser/mixedAssetRecovery");

test("v10 recovers asset rows from a mixed phishing-and-asset header", () => {
  const tables = [[
    ["جدول 1- دارایی های متاثر"],
    ["Domain/URL فیشینگ", "نام سازمان", "IP سازمان", "دامنه", "پورت"],
    ["phish-a.example", "سازمان الف", "10.0.0.1", "a.example.ir", "443"],
    ["phish-b.example", "سازمان ب", "10.0.0.2", "b.example.ir", "80"],
  ]];

  const rows = extractMixedAssetSystemsV10(tables);
  assert.equal(rows.length, 2);
  assert.equal(rows[0].organization, "سازمان الف");
  assert.equal(rows[0].ip, "10.0.0.1");
  assert.equal(rows[1].organization, "سازمان ب");
  assert.equal(rows[1].ip, "10.0.0.2");
});

test("v10 does not convert a phishing-only infrastructure table into affected systems", () => {
  const rows = extractMixedAssetSystemsV10([[
    ["جدول 1- فیشینگ"],
    ["Domain/URL فیشینگ", "IP فیشینگ", "عنوان درگاه فیشینگ"],
    ["https://login.example", "1.2.3.4", "درگاه نمونه"],
  ]]);

  assert.deepEqual(rows, []);
});

test("v10 resolves an unresolved scoped table reference with recovered assets", () => {
  const report = {
    target: {
      mode: "scope",
      scopeType: "sector",
      scopeName: "حوزه اقتصادی",
      organization: null,
      ip: null,
      rawOrganization: "حوزه اقتصادی",
      rawIp: "جدول 1",
      tableReference: "جدول 1",
    },
    affectedSystems: [],
    affectedCves: [],
    extraction: {
      parserVersion: "docx-v9",
      warnings: ["scope_target_detected", "target_table_reference_unresolved"],
      organizationMismatch: false,
      ipMismatch: false,
    },
  };

  const tables = [[
    ["جدول 1- دارایی های متاثر"],
    ["Domain/URL فیشینگ", "نام سازمان", "IP سازمان", "دامنه", "پورت"],
    ["phish-a.example", "سازمان الف", "10.0.0.1", "a.example.ir", "443"],
    ["phish-b.example", "سازمان ب", "10.0.0.2", "b.example.ir", "80"],
  ]];

  const recovered = recoverUnresolvedTargetV10(report, tables);
  assert.equal(recovered.affectedSystems.length, 2);
  assert.equal(recovered.target.mode, "scope");
  assert.equal(recovered.target.scopeType, "sector");
  assert.equal(recovered.target.scopeName, "حوزه اقتصادی");
  assert.equal(recovered.target.organization, null);
  assert.equal(recovered.target.ip, null);
  assert.equal(recovered.extraction.warnings.includes("target_table_reference_unresolved"), false);
  assert.equal(recovered.extraction.warnings.includes("target_assets_resolved_from_table"), true);
  assert.equal(recovered.extraction.warnings.includes("mixed_asset_table_recovered"), true);
  assert.equal(recovered.extraction.parserVersion, STAGE_VERSION);
});

test("v10 exports parser version", () => {
  assert.equal(STAGE_VERSION, "docx-v10");
});
