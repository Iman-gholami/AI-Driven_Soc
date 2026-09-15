const test = require("node:test");
const assert = require("node:assert/strict");

const {
  HistoricalReportContextService,
  organizationEquivalent,
} = require("../src/services/historicalReportContextService");
const {
  groundHistoricalReportAnalysis,
} = require("../src/services/analyzer");
const {
  UnifiedCopilotService,
} = require("../src/services/unifiedCopilotService");

function modelWithReports(reports) {
  return {
    db: { readyState: 1 },
    find() {
      const query = {
        select() { return query; },
        sort() { return query; },
        limit() { return query; },
        lean() { return query; },
        async exec() { return reports; },
      };
      return query;
    },
  };
}

function historicalContext() {
  return {
    status: "matched",
    reason: null,
    matchedBy: ["organization", "ip"],
    query: {
      organizations: ["سازمان تامین اجتماعی"],
      ips: ["10.10.10.10"],
    },
    matchedOrganizations: ["سازمان تامین اجتماعی"],
    totalReports: 4,
    organizationReportCount: 4,
    sameIpReportCount: 1,
    vulnerabilityReports: 2,
    misconfigurationReports: 1,
    incidentReports: 1,
    malwareReports: 0,
    highCriticalCount: 3,
    immediateCount: 2,
    reportTypeCounts: {
      vulnerability: 2,
      misconfiguration: 1,
      incident: 1,
    },
    findingCounts: [
      { type: "dependency_confusion", name: "Dependency Confusion", category: "software_supply_chain", count: 2 },
      { type: "xss", name: "Cross-Site Scripting (XSS)", category: "web", count: 1 },
    ],
    years: [1404],
    exposure: {
      level: "high",
      factors: ["4 prior reports", "3 high/critical reports", "2 immediate-action reports", "1 reports matched the current IP context"],
      interpretation: "prior_exposure_context_only",
    },
    latestReport: {
      reportNumber: "14040120_TEST",
      reportDateRaw: "20/01/1404",
      title: "گزارش آسیب پذیری نمونه",
      reportType: "vulnerability",
      organization: "سازمان تامین اجتماعی",
      ip: "10.10.10.10",
      finding: { type: "dependency_confusion", name: "Dependency Confusion", category: "software_supply_chain" },
      severity: { level: "critical", score: 9.8 },
      urgency: "immediate",
      cves: [],
    },
    recentReports: [],
    evidencePolicy: {
      localHistoricalReports: true,
      priorExposureContextOnly: true,
      provesCurrentCompromise: false,
      provesCurrentCausation: false,
    },
  };
}

test("organization matching tolerates common Persian organization prefixes", () => {
  assert.equal(organizationEquivalent("سازمان تامین اجتماعی", "تامین اجتماعی"), true);
  assert.equal(organizationEquivalent("دانشگاه علوم پزشکی تهران", "علوم پزشکی تهران"), true);
  assert.equal(organizationEquivalent("شرکت نمونه الف", "شرکت کاملاً متفاوت"), false);
});

test("historical context summarizes matching organization and IP reports", async () => {
  const reports = [
    {
      reportNumber: "R4",
      reportDateRaw: "20/01/1404",
      year: 1404,
      month: 1,
      day: 20,
      title: "R4",
      reportType: "vulnerability",
      target: { organization: "سازمان تامین اجتماعی", ip: "10.10.10.10" },
      severity: { level: "critical", score: 9.8 },
      urgency: { normalized: "immediate" },
      finding: { type: "dependency_confusion", name: "Dependency Confusion", category: "software_supply_chain" },
      cves: [],
      affectedSystems: [],
    },
    {
      reportNumber: "R3",
      reportDateRaw: "18/01/1404",
      year: 1404,
      month: 1,
      day: 18,
      title: "R3",
      reportType: "vulnerability",
      target: { organization: "تامین اجتماعی", ip: "10.10.10.11" },
      severity: { level: "high", score: 8.1 },
      urgency: { normalized: "immediate" },
      finding: { type: "dependency_confusion", name: "Dependency Confusion", category: "software_supply_chain" },
      cves: [],
      affectedSystems: [],
    },
    {
      reportNumber: "R2",
      reportDateRaw: "15/01/1404",
      year: 1404,
      month: 1,
      day: 15,
      title: "R2",
      reportType: "misconfiguration",
      target: { organization: "سازمان تامین اجتماعی", ip: "10.10.10.12" },
      severity: { level: "high", score: 7.8 },
      urgency: { normalized: "action_required" },
      finding: { type: "xss", name: "Cross-Site Scripting (XSS)", category: "web" },
      cves: [],
      affectedSystems: [],
    },
    {
      reportNumber: "R1",
      reportDateRaw: "10/01/1404",
      year: 1404,
      month: 1,
      day: 10,
      title: "R1",
      reportType: "incident",
      target: { organization: "سازمان تامین اجتماعی", ip: "10.10.10.13" },
      severity: { level: "medium", score: 5 },
      urgency: { normalized: "informational" },
      finding: { type: "phishing", name: "Phishing", category: "social_engineering" },
      cves: [],
      affectedSystems: [],
    },
    {
      reportNumber: "OTHER",
      reportDateRaw: "21/01/1404",
      year: 1404,
      month: 1,
      day: 21,
      title: "Other organization",
      reportType: "incident",
      target: { organization: "سازمان دیگری", ip: "10.20.20.20" },
      severity: { level: "critical", score: 10 },
      urgency: { normalized: "immediate" },
      finding: { type: "defacement", name: "Website Defacement", category: "web_intrusion" },
      cves: [],
      affectedSystems: [],
    },
  ];

  const service = new HistoricalReportContextService({ model: modelWithReports(reports) });
  const result = await service.getContext({
    organizations: ["تامین اجتماعی"],
    ips: ["10.10.10.10"],
  });

  assert.equal(result.status, "matched");
  assert.equal(result.totalReports, 4);
  assert.equal(result.vulnerabilityReports, 2);
  assert.equal(result.misconfigurationReports, 1);
  assert.equal(result.incidentReports, 1);
  assert.equal(result.highCriticalCount, 3);
  assert.equal(result.immediateCount, 2);
  assert.equal(result.sameIpReportCount, 1);
  assert.equal(result.findingCounts[0].type, "dependency_confusion");
  assert.equal(result.findingCounts[0].count, 2);
  assert.ok(result.matchedBy.includes("organization"));
  assert.ok(result.matchedBy.includes("ip"));
  assert.equal(result.exposure.level, "high");
});

test("historical grounding adds prioritization context without changing verdict or severity", () => {
  const analysis = {
    verdict: "SUSPICIOUS",
    observed_evidence: ["Current alert evidence"],
    risk_assessment: {
      severity: "medium",
      confidence: 72,
      reasoning: "Current evidence requires investigation.",
    },
    analyst_decision: {
      action: "INVESTIGATE",
      reason: "Validate the current alert.",
    },
    recommended_investigation_steps: ["Review current host telemetry."],
    final_soc_note: "Investigate current activity.",
  };

  const result = groundHistoricalReportAnalysis(analysis, historicalContext());

  assert.equal(result.verdict, "SUSPICIOUS");
  assert.equal(result.risk_assessment.severity, "medium");
  assert.equal(result.risk_assessment.confidence, 72);
  assert.match(result.risk_assessment.reasoning, /Historical exposure context/);
  assert.ok(result.observed_evidence.some((item) => item.includes("4 prior local security report")));
  assert.ok(result.recommended_investigation_steps.some((item) => /remediation status/i.test(item)));
  assert.match(result.final_soc_note, /does not prove the cause or compromise status/i);
});

test("SOC Copilot answers focused prior-history questions deterministically", async () => {
  let receivedHints = null;
  const service = new UnifiedCopilotService({
    historicalReportContext: {
      async getContext(hints) {
        receivedHints = hints;
        return historicalContext();
      },
    },
  });

  const result = await service.query("این سازمان قبلاً چه سابقه امنیتی داشته؟", {
    state: {
      focus: { entityType: "alert", id: "alert-1" },
      relatedEntities: {
        organization: "سازمان تامین اجتماعی",
        destinationIp: "10.10.10.10",
      },
    },
  });

  assert.equal(result.supported, true);
  assert.equal(result.tool, "historical_report_context");
  assert.deepEqual(receivedHints.organizations, ["سازمان تامین اجتماعی"]);
  assert.deepEqual(receivedHints.ips, ["10.10.10.10"]);
  assert.match(result.answer, /4 گزارش امنیتی تاریخی/);
  assert.match(result.answer, /2 گزارش آسیب/);
  assert.match(result.answer, /به‌تنهایی اثبات نمی‌کند|به تنهایی اثبات نمی‌کند/);
});

test("IncidentAnalyzer supplies historical report context to analysis and grounds the result", async () => {
  const { IncidentAnalyzer } = require("../src/services/analyzer");
  let capturedContext = null;
  const history = historicalContext();

  const analyzer = new IncidentAnalyzer({
    llm: {
      getMetadata: () => ({ provider: "test", model: "test-model" }),
      async analyze(context) {
        capturedContext = context;
        return {
          verdict: "SUSPICIOUS",
          one_line_summary: "Current alert needs investigation.",
          risk_assessment: { severity: "medium", confidence: 70, reasoning: "Current telemetry is suspicious." },
          analyst_decision: { action: "INVESTIGATE", reason: "Validate current activity." },
          recommended_investigation_steps: ["Review current endpoint telemetry."],
          final_soc_note: "Investigate current activity.",
        };
      },
    },
    networkIntelligence: {
      async enrich() {
        return {
          status: "complete",
          tuple: { sourceIp: "5.5.5.5", destinationIp: "10.10.10.10" },
          ips: [{
            ip: "10.10.10.10",
            roles: ["destination"],
            asset: { owned: true, organization: "سازمان تامین اجتماعی" },
            threat: {},
          }],
          correlations: [],
        };
      },
    },
    historicalReportContext: {
      async resolveForAlert() { return history; },
    },
    alertRepository: {},
    ruleResolver: {},
    logger: { info() {}, warn() {}, error() {} },
  });

  const result = await analyzer.analyzePayload(
    { dst_ip: "10.10.10.10", signature: "Example Rule" },
    {
      ruleResolution: {
        status: "matched",
        matchType: "exact_signature",
        candidateCount: 1,
        rule: {
          ruleId: "1",
          revision: 1,
          title: "Example Rule",
          protocol: "tcp",
          parsedRule: { flow: [], contents: [], pcre: [], references: [] },
          rawRule: "alert tcp any any -> any any",
        },
      },
    },
  );

  assert.equal(capturedContext.historical_report_context, history);
  assert.equal(result.historicalReportContext, history);
  assert.equal(result.metadata.historicalReportStatus, "matched");
  assert.equal(result.metadata.historicalReportCount, 4);
  assert.equal(result.analysis.verdict, "SUSPICIOUS");
  assert.equal(result.analysis.risk_assessment.severity, "medium");
  assert.ok(result.analysis.observed_evidence.some((item) => item.includes("Historical report context")));
});
