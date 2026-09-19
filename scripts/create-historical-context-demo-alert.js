#!/usr/bin/env node

require("dotenv").config();

const mongoose = require("mongoose");
const { settings } = require("../src/core/config");
const HistoricalReport = require("../src/models/HistoricalReport");
const Alert = require("../src/models/Alert");
const { AlertRepository } = require("../src/repositories/AlertRepository");
const { createEventHash } = require("../src/services/eventHash");
const {
  HistoricalReportContextService,
  normalizeOrganization,
} = require("../src/services/historicalReportContextService");

const DEMO_ALERT_ID = process.env.DEMO_HISTORICAL_ALERT_ID || "DEMO-HISTORICAL-CONTEXT-001";
const DOCUMENTATION_SOURCE_IP = "198.51.100.77";

async function main() {
  if (!settings.mongodbUri) {
    throw new Error("MONGODB_URI is required. Point it at the local SOC MongoDB instance before running this script.");
  }

  await mongoose.connect(settings.mongodbUri, {
    serverSelectionTimeoutMS: settings.mongodbServerSelectionTimeoutMs,
  });

  if (process.argv.includes("--delete")) {
    const result = await Alert.deleteMany({ alertId: DEMO_ALERT_ID }).exec();
    console.log(JSON.stringify({
      phase: "deleted",
      alertId: DEMO_ALERT_ID,
      deletedCount: Number(result.deletedCount || 0),
    }, null, 2));
    return;
  }

  const reports = await HistoricalReport.find({
    "target.organization": { $nin: [null, ""] },
  })
    .sort({ year: -1, month: -1, day: -1, _id: -1 })
    .select("reportNumber reportDateRaw year month day title reportType target severity urgency finding affectedSystems.organization affectedSystems.ip affectedSystems.port")
    .lean()
    .exec();

  if (!reports.length) {
    throw new Error("No historical reports are available. Import the DOCX report dataset first.");
  }

  const candidate = selectBestCandidate(reports);
  if (!candidate) {
    throw new Error("Could not find a historical-report organization with a usable IPv4 address.");
  }

  const historicalService = new HistoricalReportContextService();
  const historicalContext = await historicalService.getContext({
    organizations: [candidate.organization],
    ips: [candidate.ip],
  });

  if (historicalContext.status !== "matched" || !historicalContext.totalReports) {
    throw new Error("Historical report context did not match the selected local report candidate.");
  }

  const now = new Date();
  const destinationPort = candidate.port || 443;
  const rawEvent = {
    alertId: DEMO_ALERT_ID,
    event_id: DEMO_ALERT_ID,
    source: "historical-context-demo",
    sourcetype: "soc:demo:historical-context",
    eventtype: "historical_report_context_validation",
    host: "soc-demo-sensor",
    signature: "DEMO Historical Exposure Correlation",
    category: "validation",
    severity: "high",
    timestamp: now.toISOString(),
    _time: now.toISOString(),
    src_ip: DOCUMENTATION_SOURCE_IP,
    src_port: 51515,
    dst_ip: candidate.ip,
    dst_port: destinationPort,
    protocol: "tcp",
    organization: candidate.organization,
    target_organization: candidate.organization,
    destination_organization: candidate.organization,
    demo: true,
    demo_purpose: "Validate historical report enrichment in alert analysis and SOC Copilot.",
    raw_log: `DEMO historical-context validation: ${DOCUMENTATION_SOURCE_IP}:51515 -> ${candidate.ip}:${destinationPort}`,
  };

  const networkIntelligence = buildDemoNetworkIntelligence({
    organization: candidate.organization,
    destinationIp: candidate.ip,
    destinationPort,
    generatedAt: now,
  });
  const fullAnalysis = buildDemoAnalysis({
    organization: candidate.organization,
    destinationIp: candidate.ip,
    destinationPort,
    historicalContext,
  });

  const repository = new AlertRepository();
  const eventHash = createEventHash(rawEvent);
  const analysisSummary = {
    severity: fullAnalysis.risk_assessment.severity,
    summary: fullAnalysis.one_line_summary,
    recommendations: fullAnalysis.recommended_investigation_steps,
    verdict: fullAnalysis.verdict,
    confidence: fullAnalysis.risk_assessment.confidence,
    action: fullAnalysis.analyst_decision.action,
    analyzedAt: now,
  };

  await repository.upsertAnalyzedAlert({
    alertId: DEMO_ALERT_ID,
    source: "historical-context-demo",
    severity: analysisSummary.severity,
    rawEvent,
    eventHash,
    analysis: analysisSummary,
    fullAnalysis,
    ruleMatch: {
      status: "unavailable",
      matchType: "synthetic_validation",
      signature: rawEvent.signature,
      candidateCount: 0,
      reason: "synthetic_demo_alert",
      resolutionEvidence: [],
    },
    soc: {
      mitreAttack: [],
      iocs: [
        {
          type: "ip",
          value: candidate.ip,
          roles: ["destination"],
          organizationalAsset: true,
          organization: candidate.organization,
          directThreatMatch: false,
          relationshipThreatMatch: false,
        },
      ],
      correlation: [
        {
          type: "historical_report_context_demo",
          strength: historicalContext.sameIpReportCount > 0 ? "high" : "moderate",
          matchedFields: historicalContext.sameIpReportCount > 0
            ? ["organization", "destination_ip"]
            : ["organization"],
        },
      ],
      threatIntelligence: {
        status: "not_applicable",
        indicators: [],
      },
      networkIntelligence,
      historicalReports: historicalContext,
      providerMetadata: {
        provider: "deterministic-demo",
        model: "none",
      },
    },
    llmProvider: "deterministic-demo",
    model: "none",
    processingTimeMs: 0,
  });

  console.log(JSON.stringify({
    phase: "created",
    alertId: DEMO_ALERT_ID,
    source: "historical-context-demo",
    destination: {
      organization: candidate.organization,
      ip: candidate.ip,
      port: destinationPort,
    },
    historicalContext: {
      totalReports: historicalContext.totalReports,
      vulnerabilityReports: historicalContext.vulnerabilityReports,
      misconfigurationReports: historicalContext.misconfigurationReports,
      incidentReports: historicalContext.incidentReports,
      malwareReports: historicalContext.malwareReports,
      highCriticalCount: historicalContext.highCriticalCount,
      immediateCount: historicalContext.immediateCount,
      sameIpReportCount: historicalContext.sameIpReportCount,
      topFindings: (historicalContext.findingCounts || []).slice(0, 5),
      exposure: historicalContext.exposure,
    },
    next: [
      "Open Alerts and search for DEMO-HISTORICAL-CONTEXT-001.",
      "Open the SOC Investigation Workspace to inspect Historical Report Context.",
      "In Ask SOC Copilot ask: این سازمان قبلاً چه سابقه امنیتی داشته؟",
      "Then ask: آیا برای IP مقصد قبلاً گزارش امنیتی داشتیم؟",
    ],
  }, null, 2));
}

function selectBestCandidate(reports) {
  const groups = new Map();

  for (const report of reports) {
    const organization = String(report.target?.organization || "").trim();
    if (!organization) continue;
    const key = normalizeOrganization(organization);
    if (!key) continue;

    const group = groups.get(key) || {
      organization,
      reports: [],
      ipCounts: new Map(),
      highCriticalCount: 0,
      immediateCount: 0,
    };

    group.reports.push(report);
    if (["high", "critical"].includes(String(report.severity?.level || "").toLowerCase())) {
      group.highCriticalCount += 1;
    }
    if (String(report.urgency?.normalized || "").toLowerCase() === "immediate") {
      group.immediateCount += 1;
    }

    for (const ip of reportIps(report)) {
      const current = group.ipCounts.get(ip) || { count: 0, port: null };
      current.count += 1;
      if (!current.port) current.port = findPortForIp(report, ip);
      group.ipCounts.set(ip, current);
    }

    groups.set(key, group);
  }

  const ranked = [...groups.values()]
    .filter((group) => group.ipCounts.size > 0)
    .map((group) => {
      const [bestIp, bestIpInfo] = [...group.ipCounts.entries()]
        .sort((left, right) => right[1].count - left[1].count || left[0].localeCompare(right[0]))[0];
      return {
        ...group,
        ip: bestIp,
        ipMatchCount: bestIpInfo.count,
        port: bestIpInfo.port,
      };
    })
    .sort((a, b) =>
      b.reports.length - a.reports.length ||
      b.ipMatchCount - a.ipMatchCount ||
      b.highCriticalCount - a.highCriticalCount ||
      b.immediateCount - a.immediateCount ||
      a.organization.localeCompare(b.organization),
    );

  return ranked[0] || null;
}

function reportIps(report) {
  const values = [
    report.target?.ip,
    ...(Array.isArray(report.affectedSystems) ? report.affectedSystems.map((item) => item?.ip) : []),
  ];
  return [...new Set(values.map((value) => String(value || "").trim()).filter(isIpv4))];
}

function findPortForIp(report, ip) {
  const systems = Array.isArray(report.affectedSystems) ? report.affectedSystems : [];
  const matching = systems.find((item) => String(item?.ip || "").trim() === ip && validPort(item?.port));
  return matching ? Number(matching.port) : null;
}

function buildDemoNetworkIntelligence({ organization, destinationIp, destinationPort, generatedAt }) {
  return {
    status: "complete",
    generatedAt: generatedAt.toISOString(),
    reason: "synthetic_validation_context",
    tuple: {
      sourceIp: DOCUMENTATION_SOURCE_IP,
      sourcePort: 51515,
      destinationIp,
      destinationPort,
      protocol: "tcp",
    },
    ips: [
      {
        ip: DOCUMENTATION_SOURCE_IP,
        roles: ["source"],
        scope: "documentation",
        nationalNetwork: false,
        asset: { owned: false, organization: null },
        threat: { directMatch: false, relationshipMatch: false },
      },
      {
        ip: destinationIp,
        roles: ["destination"],
        scope: "organizational_asset",
        asset: {
          owned: true,
          organization,
          category: "Historical report target",
        },
        threat: { directMatch: false, relationshipMatch: false },
      },
    ],
    correlations: [],
    sources: {
      assetDataset: { source: "historical_reports_demo" },
      threatDataset: null,
    },
  };
}

function buildDemoAnalysis({ organization, destinationIp, destinationPort, historicalContext }) {
  const topFindings = (historicalContext.findingCounts || [])
    .slice(0, 3)
    .map((item) => `${item.name || item.type} (${item.count})`);
  const reportBreakdown = [
    historicalContext.vulnerabilityReports ? `${historicalContext.vulnerabilityReports} vulnerability` : null,
    historicalContext.misconfigurationReports ? `${historicalContext.misconfigurationReports} misconfiguration` : null,
    historicalContext.incidentReports ? `${historicalContext.incidentReports} incident` : null,
    historicalContext.malwareReports ? `${historicalContext.malwareReports} malware` : null,
  ].filter(Boolean).join(", ");

  return {
    verdict: "SUSPICIOUS",
    one_line_summary: `Synthetic validation alert for ${organization}; local historical intelligence found ${historicalContext.totalReports} prior matching security reports.`,
    attack_story: [
      `A synthetic TCP alert was generated from ${DOCUMENTATION_SOURCE_IP} to ${destinationIp}:${destinationPort}.`,
      `The local historical-report dataset matched ${historicalContext.totalReports} prior reports for the organization/IP context.`,
    ],
    why_alert_triggered: {
      rule: "DEMO Historical Exposure Correlation",
      evidence: [
        `Synthetic validation traffic targeted ${destinationIp}:${destinationPort}.`,
        `Destination organization resolved to ${organization}.`,
      ],
    },
    observed_evidence: [
      `Destination asset: ${destinationIp}:${destinationPort} (${organization}).`,
      `Historical report matches: ${historicalContext.totalReports}.`,
      reportBreakdown ? `Prior report types: ${reportBreakdown}.` : null,
      `${historicalContext.highCriticalCount || 0} prior reports were high/critical and ${historicalContext.immediateCount || 0} required immediate action.`,
      historicalContext.sameIpReportCount
        ? `${historicalContext.sameIpReportCount} prior reports matched the destination IP.`
        : null,
      topFindings.length ? `Top prior findings: ${topFindings.join(", ")}.` : null,
    ].filter(Boolean),
    network_relationship_analysis: {
      assessment: "SUSPICIOUS",
      summary: `Synthetic validation connection from ${DOCUMENTATION_SOURCE_IP} to organizational asset ${destinationIp}:${destinationPort} owned by ${organization}. Historical security-report exposure raises investigation priority but does not prove current compromise or causation.`,
      source: {
        ip: DOCUMENTATION_SOURCE_IP,
        organization: "",
        context: "RFC 5737 documentation-range source used only for local validation.",
      },
      destination: {
        ip: destinationIp,
        organization,
        context: `Organizational asset with ${historicalContext.totalReports} matching prior local security reports.`,
      },
      why_suspicious: [
        `The destination organization has ${historicalContext.totalReports} prior matching security reports.`,
        historicalContext.highCriticalCount
          ? `${historicalContext.highCriticalCount} prior reports were high/critical.`
          : null,
        historicalContext.sameIpReportCount
          ? `${historicalContext.sameIpReportCount} prior reports matched this exact destination IP.`
          : null,
      ].filter(Boolean),
      current_alert_domains: [],
      current_alert_packet_evidence: [],
      threat_feed_context: [],
      limitations: "This alert is synthetic. Historical reports provide prior-exposure and remediation context only and do not prove that the current synthetic event exploited a prior weakness.",
    },
    detection_analysis: {
      rule_logic: "Synthetic validation rule used to exercise historical-report enrichment and SOC Copilot correlation.",
      limitations: "Not a production detection and not evidence of a real attack.",
    },
    behavior_analysis: "The event is intentionally synthetic; the useful signal is the deterministic correlation to local historical report history for the same organization/IP context.",
    attack_mapping: [],
    risk_assessment: {
      severity: "high",
      confidence: 100,
      reasoning: `High is assigned only to make the demo visible in the analyst workflow. The historical dataset contains ${historicalContext.totalReports} prior matches, including ${historicalContext.highCriticalCount || 0} high/critical reports; this history should influence triage priority, not be treated as proof of current compromise.`,
    },
    analyst_decision: {
      action: "INVESTIGATE",
      reason: "Validate that prior findings were remediated and compare the current alert asset/port against the historical report record before escalation.",
    },
    false_positive_analysis: [
      "This record is explicitly a synthetic validation alert and must not be treated as a real security incident.",
    ],
    recommended_investigation_steps: [
      `Review the ${historicalContext.totalReports} matching historical reports for ${organization}.`,
      historicalContext.sameIpReportCount
        ? `Prioritize the ${historicalContext.sameIpReportCount} reports that reference ${destinationIp}.`
        : "Confirm whether the current destination IP belongs to the same organizational scope as the historical reports.",
      "Verify remediation status for the most recent high/critical and immediate-action findings.",
      "Use current telemetry to determine whether any present-day evidence independently supports exploitation or compromise.",
    ],
    final_soc_note: `DEMO ONLY — historical context matched ${historicalContext.totalReports} prior reports for ${organization}. Use the history to prioritize remediation verification; do not infer current compromise from history alone.`,
  };
}

function isIpv4(value) {
  const parts = String(value || "").trim().split(".");
  if (parts.length !== 4) return false;
  return parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

function validPort(value) {
  const port = Number(value);
  return Number.isInteger(port) && port > 0 && port <= 65535;
}

main()
  .catch((error) => {
    console.error(error?.stack || error?.message || String(error));
    process.exitCode = 1;
  })
  .finally(async () => {
    if (mongoose.connection.readyState !== 0) await mongoose.disconnect();
  });
