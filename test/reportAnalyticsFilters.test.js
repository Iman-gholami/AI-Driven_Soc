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
    targetMode: "SCOPE",
    scopeType: "SECTOR",
    scopeName: "حوزه اقتصادی",
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
  assert.equal(filter["target.mode"], "scope");
  assert.equal(filter["target.scopeType"], "sector");
  assert.deepEqual(filter["target.scopeName"], { $regex: "حوزه اقتصادی", $options: "i" });
  assert.equal(filter["severity.level"], "high");
  assert.equal(filter["urgency.normalized"], "immediate");
  assert.equal(filter["finding.type"], "xss");
  assert.equal(filter["finding.category"], "web_vulnerability");
  assert.equal(filter["affectedSystems.port"], 443);
  assert.equal(filter.cves, "CVE-2025-1234");
  assert.deepEqual(filter["severity.score"], { $gte: 7, $lte: 10 });
  assert.equal(Array.isArray(filter.$and), true);
  assert.equal(filter.$and.length, 3);

  const disjunctions = filter.$and.map((item) => item.$or || []);
  assert.equal(
    disjunctions.some((rows) => rows.some((row) => Object.prototype.hasOwnProperty.call(row, "affectedSystems.organization"))),
    true,
  );
  assert.equal(
    disjunctions.some((rows) => rows.some((row) => Object.prototype.hasOwnProperty.call(row, "target.scopeName"))),
    true,
  );
  assert.equal(
    disjunctions.some((rows) => rows.some((row) => Object.prototype.hasOwnProperty.call(row, "affectedSystems.ip"))),
    true,
  );
});

test("report enum filters support comma separated faceted selections", () => {
  const filter = buildReportFilter({
    year: 1404,
    reportType: "incident,vulnerability",
    targetMode: "scope,multi_target",
    severity: "critical,high",
    finding: "xss,phishing",
  });

  assert.deepEqual(filter.reportType, { $in: ["incident", "vulnerability"] });
  assert.deepEqual(filter["target.mode"], { $in: ["scope", "multi_target"] });
  assert.deepEqual(filter["severity.level"], { $in: ["critical", "high"] });
  assert.deepEqual(filter["finding.type"], { $in: ["xss", "phishing"] });
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
    targetMode: "scope",
    scopeType: "sector",
    organization: "تامین اجتماعی",
    severity: "critical",
  });

  assert.equal(pipeline[0].$match.year, 1404);
  assert.equal(pipeline[0].$match.month, 2);
  assert.equal(pipeline[0].$match.reportType, "incident");
  assert.equal(pipeline[0].$match["target.mode"], "scope");
  assert.equal(pipeline[0].$match["target.scopeType"], "sector");
  assert.equal(pipeline[0].$match["severity.level"], "critical");
  assert.equal(Array.isArray(pipeline[0].$match.$or), true);
  assert.equal(
    pipeline[0].$match.$or.some((row) => Object.prototype.hasOwnProperty.call(row, "affectedSystems.organization")),
    true,
  );
  assert.deepEqual(result.scope, {
    month: 2,
    reportType: "incident",
    targetMode: "scope",
    scopeType: "sector",
    severity: "critical",
    organization: "تامین اجتماعی",
  });
  assert.equal(result.summary.total, 0);
  assert.deepEqual(result.byTargetMode, []);
  assert.deepEqual(result.topScopes, []);
  assert.deepEqual(result.findingMonthHeatmap, []);
  assert.deepEqual(result.repeatedPatterns, []);
});

test("facets reuse the same Mongo filter scope", async () => {
  let pipeline;
  const model = {
    aggregate(value) {
      pipeline = value;
      return { exec: async () => [{}] };
    },
  };

  const service = new ReportAnalyticsService({ model });
  const result = await service.getFacets({ year: 1404, month: 3 });

  assert.equal(pipeline[0].$match.year, 1404);
  assert.equal(pipeline[0].$match.month, 3);
  assert.ok(pipeline[1].$facet.targetModes);
  assert.ok(pipeline[1].$facet.organizations);
  assert.deepEqual(result.reportTypes, []);
  assert.deepEqual(result.organizations, []);
});


test("all-years report analytics omit the Mongo year constraint", async () => {
  let pipeline;

  const model = {
    aggregate(value) {
      pipeline = value;
      return { exec: async () => [{}] };
    },
  };

  const service = new ReportAnalyticsService({ model });
  const result = await service.getStats({});

  assert.deepEqual(pipeline[0].$match, {});
  assert.equal(
    Object.prototype.hasOwnProperty.call(pipeline[0].$match, "year"),
    false,
  );
  assert.equal(result.year, null);
  assert.equal(result.summary.total, 0);
});

test("all-years stats preserve non-year filters", async () => {
  let pipeline;

  const model = {
    aggregate(value) {
      pipeline = value;
      return { exec: async () => [{}] };
    },
  };

  const service = new ReportAnalyticsService({ model });

  const result = await service.getStats({
    month: 3,
    reportType: "incident",
    severity: "high",
  });

  assert.equal(
    Object.prototype.hasOwnProperty.call(pipeline[0].$match, "year"),
    false,
  );
  assert.equal(pipeline[0].$match.month, 3);
  assert.equal(pipeline[0].$match.reportType, "incident");
  assert.equal(pipeline[0].$match["severity.level"], "high");
  assert.equal(result.year, null);
});

test("all-years facets omit year while preserving date filters", async () => {
  let pipeline;

  const model = {
    aggregate(value) {
      pipeline = value;
      return { exec: async () => [{}] };
    },
  };

  const service = new ReportAnalyticsService({ model });
  await service.getFacets({ month: 4, day: 9 });

  assert.equal(
    Object.prototype.hasOwnProperty.call(pipeline[0].$match, "year"),
    false,
  );
  assert.equal(pipeline[0].$match.month, 4);
  assert.equal(pipeline[0].$match.day, 9);
});

test("buildReportFilter treats an omitted year as all years", () => {
  const filter = buildReportFilter({
    month: 7,
    finding: "phishing",
  });

  assert.equal(
    Object.prototype.hasOwnProperty.call(filter, "year"),
    false,
  );
  assert.equal(filter.month, 7);
  assert.equal(filter["finding.type"], "phishing");
});
