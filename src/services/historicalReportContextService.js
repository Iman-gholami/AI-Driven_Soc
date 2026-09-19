const HistoricalReport = require("../models/HistoricalReport");

const MAX_CANDIDATES = 250;
const GENERIC_ORG_PREFIX = /^(?:سازمان|شرکت|اداره\s*کل|اداره|وزارت|دانشگاه|مرکز|موسسه|مؤسسه|بانک|گروه|هلدینگ|organization|company|department|ministry|university|center)\s+/i;

class HistoricalReportContextService {
  constructor({ model = HistoricalReport } = {}) {
    this.model = model;
  }

  async resolveForAlert(payload = {}, networkIntelligence = {}) {
    const endpoints = Array.isArray(networkIntelligence?.ips) ? networkIntelligence.ips : [];
    const tuple = networkIntelligence?.tuple || {};

    const organizations = uniqueStrings([
      payload.organization,
      payload.organization_name,
      payload.organizationName,
      payload.org,
      payload.bunit,
      payload.business_unit,
      payload.businessUnit,
      payload.target_organization,
      payload.targetOrganization,
      payload.destination_organization,
      payload.destinationOrganization,
      payload.source_organization,
      payload.sourceOrganization,
      ...endpoints.map((item) => item?.asset?.organization),
    ]);

    const ips = uniqueStrings([
      payload.src_ip,
      payload.source_ip,
      payload.srcIp,
      payload.sourceIp,
      payload.dst_ip,
      payload.dest_ip,
      payload.destination_ip,
      payload.dstIp,
      payload.destinationIp,
      tuple.sourceIp,
      tuple.destinationIp,
      ...endpoints.map((item) => item?.ip),
    ]).filter(isIpv4);

    return this.getContext({ organizations, ips });
  }

  async getContext({ organizations = [], ips = [] } = {}) {
    const organizationHints = uniqueStrings(organizations).map(cleanOrganization).filter(Boolean);
    const ipHints = uniqueStrings(ips).filter(isIpv4);

    if (!organizationHints.length && !ipHints.length) {
      return emptyContext("no_entity_hints", organizationHints, ipHints);
    }

    if (this.model?.db && Number(this.model.db.readyState) !== 1) {
      return emptyContext("historical_report_database_not_connected", organizationHints, ipHints, "unavailable");
    }

    const clauses = [];
    for (const ip of ipHints) {
      clauses.push({ "target.ip": ip }, { "affectedSystems.ip": ip });
    }

    for (const organization of organizationHints) {
      for (const pattern of organizationSearchPatterns(organization)) {
        clauses.push({ "target.organization": { $regex: pattern, $options: "i" } });
        clauses.push({ "affectedSystems.organization": { $regex: pattern, $options: "i" } });
      }
    }

    if (!clauses.length) {
      return emptyContext("no_queryable_entity_hints", organizationHints, ipHints);
    }

    const candidates = await this.model
      .find({ $or: clauses })
      .select([
        "reportNumber",
        "reportDateRaw",
        "year",
        "month",
        "day",
        "title",
        "reportType",
        "target",
        "severity",
        "urgency",
        "finding",
        "vulnerability",
        "cves",
        "affectedSystems.organization",
        "affectedSystems.ip",
      ].join(" "))
      .sort({ year: -1, month: -1, day: -1, _id: -1 })
      .limit(MAX_CANDIDATES)
      .lean()
      .exec();

    const matched = (candidates || []).filter((report) => reportMatches(report, organizationHints, ipHints));
    if (!matched.length) {
      return emptyContext("no_matching_reports", organizationHints, ipHints);
    }

    return summarizeReports(matched, organizationHints, ipHints);
  }
}

function summarizeReports(reports, organizationHints, ipHints) {
  const findingMap = new Map();
  const reportTypeCounts = {};
  const organizationMatches = new Set();
  const years = new Set();
  let highCriticalCount = 0;
  let immediateCount = 0;
  let sameIpReportCount = 0;
  let organizationReportCount = 0;

  for (const report of reports) {
    years.add(report.year);
    const reportType = String(report.reportType || "unknown");
    reportTypeCounts[reportType] = (reportTypeCounts[reportType] || 0) + 1;

    if (["high", "critical"].includes(String(report.severity?.level || "").toLowerCase())) highCriticalCount += 1;
    if (String(report.urgency?.normalized || "").toLowerCase() === "immediate") immediateCount += 1;

    const findingType = String(report.finding?.type || "unknown");
    if (findingType && findingType !== "unknown") {
      const existing = findingMap.get(findingType) || {
        type: findingType,
        name: report.finding?.name || findingType,
        category: report.finding?.category || "unknown",
        count: 0,
      };
      existing.count += 1;
      findingMap.set(findingType, existing);
    }

    const reportOrganizations = collectReportOrganizations(report);
    const reportIps = collectReportIps(report);
    for (const organization of reportOrganizations) organizationMatches.add(organization);
    if (organizationHints.some((hint) => reportOrganizations.some((value) => organizationEquivalent(hint, value)))) {
      organizationReportCount += 1;
    }
    if (ipHints.some((ip) => reportIps.includes(ip))) sameIpReportCount += 1;
  }

  const findingCounts = [...findingMap.values()]
    .sort((a, b) => b.count - a.count || a.type.localeCompare(b.type))
    .slice(0, 10);

  const matchedBy = [];
  if (organizationReportCount > 0) matchedBy.push("organization");
  if (sameIpReportCount > 0) matchedBy.push("ip");

  const exposure = deriveExposureLevel({
    totalReports: reports.length,
    highCriticalCount,
    immediateCount,
    sameIpReportCount,
  });

  return {
    status: "matched",
    reason: null,
    matchedBy,
    query: {
      organizations: organizationHints,
      ips: ipHints,
    },
    matchedOrganizations: [...organizationMatches].filter(Boolean).slice(0, 20),
    totalReports: reports.length,
    organizationReportCount,
    sameIpReportCount,
    vulnerabilityReports: Number(reportTypeCounts.vulnerability || 0),
    misconfigurationReports: Number(reportTypeCounts.misconfiguration || 0),
    incidentReports: Number(reportTypeCounts.incident || 0),
    malwareReports: Number(reportTypeCounts.malware || 0),
    highCriticalCount,
    immediateCount,
    reportTypeCounts,
    findingCounts,
    years: [...years].filter((value) => value !== null && value !== undefined).sort((a, b) => b - a),
    exposure,
    latestReport: summarizeReportReference(reports[0]),
    recentReports: reports.slice(0, 5).map(summarizeReportReference),
    evidencePolicy: {
      localHistoricalReports: true,
      priorExposureContextOnly: true,
      provesCurrentCompromise: false,
      provesCurrentCausation: false,
    },
  };
}

function summarizeReportReference(report = {}) {
  return {
    reportNumber: report.reportNumber || null,
    reportDateRaw: report.reportDateRaw || null,
    year: report.year ?? null,
    month: report.month ?? null,
    day: report.day ?? null,
    title: report.title || null,
    reportType: report.reportType || "unknown",
    organization: report.target?.organization || null,
    ip: report.target?.ip || null,
    finding: report.finding
      ? {
          type: report.finding.type || "unknown",
          name: report.finding.name || report.finding.type || null,
          category: report.finding.category || "unknown",
        }
      : null,
    severity: report.severity
      ? { level: report.severity.level || "unknown", score: report.severity.score ?? null }
      : null,
    urgency: report.urgency?.normalized || null,
    cves: Array.isArray(report.cves) ? report.cves.slice(0, 10) : [],
  };
}

function deriveExposureLevel({ totalReports, highCriticalCount, immediateCount, sameIpReportCount }) {
  const factors = [];
  if (totalReports >= 4) factors.push(`${totalReports} prior reports`);
  if (highCriticalCount > 0) factors.push(`${highCriticalCount} high/critical reports`);
  if (immediateCount > 0) factors.push(`${immediateCount} immediate-action reports`);
  if (sameIpReportCount > 0) factors.push(`${sameIpReportCount} reports matched the current IP context`);

  let level = "limited";
  if (totalReports >= 4 && (highCriticalCount >= 2 || immediateCount >= 2 || sameIpReportCount >= 2)) level = "high";
  else if (totalReports >= 2 || highCriticalCount >= 1 || immediateCount >= 1 || sameIpReportCount >= 1) level = "elevated";

  return {
    level,
    factors,
    interpretation: "prior_exposure_context_only",
  };
}

function reportMatches(report, organizationHints, ipHints) {
  const reportOrganizations = collectReportOrganizations(report);
  const reportIps = collectReportIps(report);
  const organizationMatch = organizationHints.some((hint) =>
    reportOrganizations.some((organization) => organizationEquivalent(hint, organization)),
  );
  const ipMatch = ipHints.some((ip) => reportIps.includes(ip));
  return organizationMatch || ipMatch;
}

function collectReportOrganizations(report = {}) {
  return uniqueStrings([
    report.target?.organization,
    ...(Array.isArray(report.affectedSystems) ? report.affectedSystems.map((item) => item?.organization) : []),
  ]).map(cleanOrganization).filter(Boolean);
}

function collectReportIps(report = {}) {
  return uniqueStrings([
    report.target?.ip,
    ...(Array.isArray(report.affectedSystems) ? report.affectedSystems.map((item) => item?.ip) : []),
  ]).filter(isIpv4);
}

function organizationSearchPatterns(value) {
  const normalized = normalizeOrganization(value);
  const core = organizationCore(normalized);
  const candidates = uniqueStrings([normalized, core]).filter((item) => item.length >= 4);
  return candidates.map((item) => item.split(/\s+/).filter(Boolean).map(flexibleToken).join("[\\s‌]+"));
}

function flexibleToken(value) {
  return escapeRegex(value)
    .replace(/ی/g, "[یي]")
    .replace(/ک/g, "[کك]");
}

function organizationEquivalent(left, right) {
  const a = organizationCore(normalizeOrganization(left));
  const b = organizationCore(normalizeOrganization(right));
  if (!a || !b) return false;
  if (a === b) return true;

  const shorter = a.length <= b.length ? a : b;
  const longer = a.length > b.length ? a : b;
  const tokenCount = shorter.split(/\s+/).filter(Boolean).length;
  return shorter.length >= 8 && tokenCount >= 2 && longer.includes(shorter);
}

function organizationCore(value) {
  let text = normalizeOrganization(value);
  for (let index = 0; index < 2; index += 1) text = text.replace(GENERIC_ORG_PREFIX, "").trim();
  return text;
}

function cleanOrganization(value) {
  return String(value || "").replace(/\s+/g, " ").trim();
}

function normalizeOrganization(value) {
  return cleanOrganization(value)
    .replace(/ي/g, "ی")
    .replace(/ك/g, "ک")
    .replace(/[‌\u200c]/g, " ")
    .replace(/[()\[\]{}،,؛;:|/\\_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

function emptyContext(reason, organizations = [], ips = [], status = "none") {
  return {
    status,
    reason,
    matchedBy: [],
    query: { organizations, ips },
    matchedOrganizations: [],
    totalReports: 0,
    organizationReportCount: 0,
    sameIpReportCount: 0,
    vulnerabilityReports: 0,
    misconfigurationReports: 0,
    incidentReports: 0,
    malwareReports: 0,
    highCriticalCount: 0,
    immediateCount: 0,
    reportTypeCounts: {},
    findingCounts: [],
    years: [],
    exposure: {
      level: "none",
      factors: [],
      interpretation: "prior_exposure_context_only",
    },
    latestReport: null,
    recentReports: [],
    evidencePolicy: {
      localHistoricalReports: true,
      priorExposureContextOnly: true,
      provesCurrentCompromise: false,
      provesCurrentCausation: false,
    },
  };
}

function uniqueStrings(values) {
  return [...new Set((values || [])
    .filter((value) => value !== undefined && value !== null)
    .map((value) => String(value).trim())
    .filter(Boolean))];
}

function isIpv4(value) {
  const text = String(value || "").trim();
  const parts = text.split(".");
  if (parts.length !== 4) return false;
  return parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

function escapeRegex(value) {
  return String(value || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

module.exports = {
  HistoricalReportContextService,
  summarizeReports,
  normalizeOrganization,
  organizationEquivalent,
  deriveExposureLevel,
  emptyContext,
};
