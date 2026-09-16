const test = require("node:test");
const assert = require("node:assert/strict");

const {
  classifyReconcileStatus,
  comparableRecord,
} = require("../src/services/reportReconcileService");

function record(overrides = {}) {
  return {
    documentKey: "R-1",
    reportNumber: "R-1",
    reportDateRaw: "01/02/1404",
    year: 1404,
    month: 2,
    day: 1,
    title: "Sample report",
    reportType: "vulnerability",
    provider: "SOC",
    contact: null,
    effect: "test",
    target: { organization: "دانشگاه علوم", ip: "10.0.0.1", rawIp: "10.0.0.1" },
    severity: { raw: "8", score: 8, level: "high" },
    urgency: { raw: "نیازمند اقدام", normalized: "action_required" },
    finding: { type: "xss", name: "Cross-Site Scripting", category: "web_vulnerability", cwe: "CWE-79" },
    vulnerability: { name: "Cross-Site Scripting", normalizedName: "xss", category: "web_vulnerability", cwe: "CWE-79" },
    cves: [],
    affectedCves: [],
    description: "description",
    conclusion: "conclusion",
    recommendations: ["fix it"],
    affectedSystems: [{ ip: "10.0.0.1", port: 443 }],
    phishingInfrastructure: [],
    indicators: [],
    fullText: "full text",
    source: {
      filename: "r1.docx",
      relativePath: "1404/r1.docx",
      sha256: "abc",
      sizeBytes: 100,
      importedAt: new Date("2026-01-01T00:00:00Z"),
    },
    extraction: {
      parserVersion: "docx-v5",
      paragraphCount: 10,
      tableCount: 2,
      warnings: [],
      organizationMismatch: false,
      ipMismatch: false,
    },
    createdAt: new Date("2026-01-01T00:00:00Z"),
    updatedAt: new Date("2026-01-01T00:00:00Z"),
    ...overrides,
  };
}

test("reconciliation ignores database timestamps and detects unchanged records", () => {
  const existing = record();
  const parsed = record({
    source: { ...record().source, importedAt: new Date("2026-09-01T00:00:00Z") },
    updatedAt: new Date("2026-09-01T00:00:00Z"),
  });

  assert.equal(classifyReconcileStatus(existing, parsed), "unchanged");
  assert.deepEqual(comparableRecord(existing), comparableRecord(parsed));
});

test("reconciliation detects source, parser and metadata drift independently", () => {
  assert.equal(
    classifyReconcileStatus(record(), record({ source: { ...record().source, sha256: "changed" } })),
    "changed_source",
  );

  assert.equal(
    classifyReconcileStatus(record(), record({ extraction: { ...record().extraction, parserVersion: "docx-v6" } })),
    "stale_parser",
  );

  assert.equal(
    classifyReconcileStatus(record(), record({ title: "Changed title" })),
    "metadata_drift",
  );
});
