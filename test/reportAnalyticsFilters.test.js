const test = require("node:test");
const assert = require("node:assert/strict");

const {
  ReportAnalyticsService,
  buildReportFilter,
} = require("../src/services/reportAnalyticsService");

test("report filters support Jalali month/day and multidimensional analytics scope", () => {
  const filter = buildReportFilter({
    year: "1404",
    month: "2",
    day: "7",
    reportType: "VULNERABILITY",
    severity: "HIGH",
    urgency: "IMMEDIATE",
    finding: "XSS",
    findingCategory: "web_vulnerability",
    provider: "SOC",
    organization: "تامین اجتماعی",
    ip: "10.20.30.40",
    port: "443",
    service: "https",
    domain: "example.ir",
    cve: "cve-2025-1234",
    minScore: "7",
    maxScore: "10",
    search: "remote",
  });

  assert.equal(filter.year, 1404);
  assert.equal(filter.month, 2);
  assert.equal(filter.day, 7);
  assert.equal(filter.reportType, "vulnerability");
  assert.equal(filter["severity.level"], "high");
  assert.equal(filter["urgency.normalized"], "immediate");
  assert.equal(filter["finding.type"], "xss");
  assert.equal(filter["finding.category"], "web_vulnerability");
  assert.equal(filter["affectedSystems.port"], 443);
  assert.equal(filter.cves, "CVE-2025-1234");
  assert.deepEqual(filter["severity.score"], { $gte: 7, $lte: 10 });
  assert.equal(Array.isArray(filter.$and), true);
  assert.equal(filter.$and.length, 2);
});

test("filtered stats use the same Mongo match scope as the report list", async () => {
  let pipeline;
  const model = {
    aggregate(value) {
      pipeline = value;
      return { exec: async () => [{}] };
    },
  };

  const service = new ReportAnalyticsService({ model });
  const result = await service.getStats({
    year: 1404,
    month: 2,
    reportType: "incident",
    organization: "تامین اجتماعی",
    severity: "critical",
  });

  assert.equal(pipeline[0].$match.year, 1404);
  assert.equal(pipeline[0].$match.month, 2);
  assert.equal(pipeline[0].$match.reportType, "incident");
  assert.equal(pipeline[0].$match["severity.level"], "critical");
  assert.deepEqual(result.scope, {
    month: 2,
    reportType: "incident",
    severity: "critical",
    organization: "تامین اجتماعی",
  });
  assert.equal(result.summary.total, 0);
});
