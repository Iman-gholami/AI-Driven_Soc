const base = require("./reportDocxParser");
const v4 = require("./reportDocxParserV4");
const v9 = require("./reportDocxParserV9");
const v10 = require("./reportDocxParserV10");

const PARSER_VERSION = "docx-v11";

async function parseDocxReport(filePath, { yearHint } = {}) {
  let report = await v10.parseDocxReport(filePath, { yearHint });

  report = enhanceFindingV11(report);

  if (needsStructuredAssetRecoveryV11(report)) {
    const xml = await base.extractDocumentXml(filePath);
    const parsed = base.parseWordXml(xml);
    report = recoverUnresolvedTargetV11(report, parsed.tables);
  }

  report = normalizeTargetModeWarningsV11(report);

  report.extraction = {
    ...(report.extraction || {}),
    parserVersion: PARSER_VERSION,
  };

  return report;
}

function enhanceFindingV11(report) {
  if (!report || typeof report !== "object") return report;
  if (report.finding?.type && report.finding.type !== "unknown") return report;

  const titleFinding = classifyFindingV11(report.title);
  const finding = titleFinding.type !== "unknown"
    ? titleFinding
    : classifyFindingV11(
        [report.title, report.description, report.fullText]
          .filter(Boolean)
          .join("\n"),
      );

  if (finding.type === "unknown") return report;

  report.finding = finding;
  report.vulnerability = vulnerabilityFromFindingV11(finding);

  const warnings = new Set(report.extraction?.warnings || []);
  warnings.delete("unknown_finding_type");

  report.extraction = {
    ...(report.extraction || {}),
    parserVersion: PARSER_VERSION,
    warnings: [...warnings],
  };

  return report;
}

function classifyFindingV11(value) {
  const text = normalize(value);

  const catalog = [
    {
      pattern: /آلودگی\s+به\s+بدافزار.*ارتباط.*دامنه\s+بدافزار/,
      type: "malware_domain_communication",
      name: "Malware Domain Communication",
      category: "malware_network_activity",
      cwe: null,
    },
    {
      pattern: /نقض\s+سیاست(?:\s*های)?\s+امنیتی.*ارسال\s+اطلاعات.*(?:dailyhealthcheck|dubox|سرویس\s+ابری)/,
      type: "unauthorized_external_data_transfer",
      name: "Unauthorized External Data Transfer",
      category: "data_loss_prevention",
      cwe: null,
    },
    {
      pattern: /(?:golang|go\s*lang).*backdoor|backdoor.*(?:golang|go\s*lang)/,
      type: "malware_backdoor_activity",
      name: "Malware Backdoor Activity",
      category: "malware",
      cwe: null,
    },
    {
      pattern: /click\s*jack(?:ing)?|clickjack(?:ing)?|ui\s*redress/,
      type: "clickjacking",
      name: "Clickjacking / UI Redress",
      category: "web_vulnerability",
      cwe: "CWE-1021",
    },
    {
      pattern: /مدیریت\s+نادرست\s+خطا/,
      type: "improper_error_handling",
      name: "Improper Error Handling",
      category: "application_misconfiguration",
      cwe: "CWE-755",
    },
    {
      pattern: /dns\s*tunnel|تونل.*dns|dns.*تونل/,
      type: "dns_tunneling",
      name: "DNS Tunneling",
      category: "network_anomaly",
      cwe: null,
    },
    {
      pattern: /باج\s*افزار|ransomware/,
      type: "ransomware_activity",
      name: "Ransomware Activity",
      category: "malware",
      cwe: null,
    },
    {
      pattern: /ice\s*warp|icewarp/,
      type: "vulnerable_icewarp",
      name: "Vulnerable IceWarp",
      category: "vulnerable_software",
      cwe: null,
    },
    {
      pattern: /angular\s*\.?\s*js|angularjs/,
      type: "vulnerable_angularjs",
      name: "Vulnerable AngularJS",
      category: "vulnerable_software",
      cwe: null,
    },
    {
      pattern: /(?:bancos|dapato|floxif|nspps|socgholish)/,
      type: "malware_activity",
      name: "Known Malware Activity",
      category: "malware",
      cwe: null,
    },
  ];

  return catalog.find((item) => item.pattern.test(text)) || {
    type: "unknown",
    name: null,
    category: "unknown",
    cwe: null,
  };
}

function vulnerabilityFromFindingV11(finding) {
  const vulnerabilityLike = new Set([
    "clickjacking",
    "improper_error_handling",
    "vulnerable_icewarp",
    "vulnerable_angularjs",
  ]);

  if (!finding || !vulnerabilityLike.has(finding.type)) {
    return {
      name: null,
      normalizedName: "unknown",
      category: "unknown",
      cwe: null,
    };
  }

  return {
    name: finding.name,
    normalizedName: finding.type,
    category: finding.category,
    cwe: finding.cwe || null,
  };
}

function needsStructuredAssetRecoveryV11(report) {
  const warnings = report?.extraction?.warnings || [];
  return warnings.includes("target_table_reference_unresolved");
}

function recoverUnresolvedTargetV11(report, tables) {
  if (!needsStructuredAssetRecoveryV11(report)) return report;

  const recovered = extractStructuredAssetSystemsV11(tables);
  const currentCount = Array.isArray(report.affectedSystems)
    ? report.affectedSystems.length
    : 0;

  if (recovered.length <= currentCount) return report;

  report.affectedSystems = recovered;
  report.affectedCves = [
    ...new Set(
      recovered.flatMap((item) =>
        Array.isArray(item.cves) ? item.cves : [],
      ),
    ),
  ];

  report = v9.enhanceReportRecordV9(report);

  const warnings = new Set(report.extraction?.warnings || []);

  warnings.delete("target_table_reference_unresolved");

  if (report.target?.mode === "single") {
    warnings.delete("multi_target_report");
    warnings.delete("scope_target_detected");
  } else if (report.target?.mode === "multi_target") {
    warnings.delete("scope_target_detected");
    warnings.delete("target_resolved_from_table");
  } else if (report.target?.mode === "scope") {
    warnings.delete("multi_target_report");
    warnings.delete("target_resolved_from_table");
  }

  warnings.add("structured_asset_table_recovered");

  report.extraction = {
    ...(report.extraction || {}),
    parserVersion: PARSER_VERSION,
    warnings: [...warnings],
  };

  return report;
}

function extractStructuredAssetSystemsV11(tables) {
  let bestRows = [];

  for (const table of Array.isArray(tables) ? tables : []) {
    if (!Array.isArray(table) || table.length < 2) continue;

    const header = findStructuredAssetHeaderV11(table);
    if (!header) continue;

    const rows = [];

    for (const row of table.slice(header.index + 1)) {
      if (!Array.isArray(row) || !row.some(Boolean)) continue;

      const repeatedHeaders = row
        .map(v4.normalizeHeaderV4)
        .filter(Boolean);

      if (repeatedHeaders.length >= 2) continue;

      const organization = clean(row[header.organizationIndex]);
      const rawIp = clean(row[header.ipIndex]);
      const ip = base.normalizeFirstIp(rawIp);

      if (!ip) continue;

      rows.push({
        method: null,
        parameter: null,
        url: null,
        additionalUrls: [],
        domain: null,
        organization,
        ip,
        rawIp,
        port: null,
        service: null,
        packetCount: null,
        participantIpCount: null,
        trafficVolumeRaw: null,
        trafficVolumeBytes: null,
        eventDateRaw: null,
        eventYear: null,
        eventMonth: null,
        eventDay: null,
        timeRange: null,
        softwareVersion: null,
        reportedFinding: null,
        cves: [],
      });
    }

    const uniqueRows = dedupeAssets(rows);
    if (uniqueRows.length > bestRows.length) bestRows = uniqueRows;
  }

  return bestRows;
}

function findStructuredAssetHeaderV11(table) {
  let best = null;
  const limit = Math.min(table.length, 8);

  for (let index = 0; index < limit; index += 1) {
    const row = table[index];
    if (!Array.isArray(row)) continue;

    const keys = row.map(v4.normalizeHeaderV4);

    let organizationIndex = keys.findIndex(
      (key) => key === "organization",
    );

    if (organizationIndex < 0) {
      organizationIndex = row.findIndex(isOrganizationHeader);
    }

    if (organizationIndex < 0) continue;

    let ipIndex = keys.findIndex((key) => key === "ip");
    let inferredIp = false;
    let ipEvidence = 0;

    if (ipIndex < 0) {
      const inferred = inferAssetIpColumnV11(
        table,
        index,
        organizationIndex,
        keys,
      );

      if (inferred) {
        ipIndex = inferred.columnIndex;
        ipEvidence = inferred.pairedIpRows;
        inferredIp = true;
      }
    } else {
      ipEvidence = countPairedIpRowsV11(
        table,
        index,
        organizationIndex,
        ipIndex,
      );
    }

    if (ipIndex < 0 || organizationIndex === ipIndex) continue;

    const explicitIp =
      keys[ipIndex] === "ip" ||
      isAssetIpHeader(row[ipIndex]);

    const score =
      keys.filter(Boolean).length * 10 +
      row.filter((cell) => clean(cell)).length +
      ipEvidence * 20 +
      (explicitIp ? 30 : 0) +
      (ipIndex > organizationIndex ? 3 : 0);

    if (!best || score > best.score) {
      best = {
        index,
        organizationIndex,
        ipIndex,
        inferredIp,
        ipEvidence,
        score,
      };
    }
  }

  return best;
}

function inferAssetIpColumnV11(
  table,
  headerIndex,
  organizationIndex,
  headerKeys,
) {
  const dataRows = table.slice(headerIndex + 1);

  const width = Math.max(
    0,
    ...table.map((row) =>
      Array.isArray(row) ? row.length : 0
    ),
  );

  const candidates = [];

  for (let columnIndex = 0; columnIndex < width; columnIndex += 1) {
    if (columnIndex === organizationIndex) continue;

    const headerKey = headerKeys[columnIndex] || null;

    // Do not treat a phishing IP/URL column as an affected asset.
    if (
      typeof headerKey === "string" &&
      headerKey.startsWith("phishing_")
    ) {
      continue;
    }

    let ipRows = 0;
    let pairedIpRows = 0;

    for (const row of dataRows) {
      if (!Array.isArray(row)) continue;

      const rawIp = clean(row[columnIndex]);
      if (!rawIp) continue;

      const ip = base.normalizeFirstIp(rawIp);
      if (!ip) continue;

      ipRows += 1;

      const organization = clean(row[organizationIndex]);
      if (organization) pairedIpRows += 1;
    }

    if (!pairedIpRows) continue;

    candidates.push({
      columnIndex,
      ipRows,
      pairedIpRows,
      rightOfOrganization: columnIndex > organizationIndex,
      distance: Math.abs(columnIndex - organizationIndex),
    });
  }

  candidates.sort((a, b) =>
    b.pairedIpRows - a.pairedIpRows ||
    b.ipRows - a.ipRows ||
    Number(b.rightOfOrganization) -
      Number(a.rightOfOrganization) ||
    a.distance - b.distance ||
    a.columnIndex - b.columnIndex
  );

  return candidates[0] || null;
}

function countPairedIpRowsV11(
  table,
  headerIndex,
  organizationIndex,
  ipIndex,
) {
  let count = 0;

  for (const row of table.slice(headerIndex + 1)) {
    if (!Array.isArray(row)) continue;

    const organization = clean(row[organizationIndex]);
    const ip = base.normalizeFirstIp(
      clean(row[ipIndex]),
    );

    if (organization && ip) count += 1;
  }

  return count;
}

function isOrganizationHeader(value) {
  const text = normalizeHeaderText(value);
  return /نام.*سازمان|سازمان|organization/.test(text);
}

function isAssetIpHeader(value) {
  const text = normalizeHeaderText(value);

  if (/فیشینگ|phish/.test(text)) return false;

  return (
    /(?:^|\s)ip(?:\s|$)/.test(text) ||
    /آی\s*پی/.test(text) ||
    /آدرس.*(?:ip|آی|سازمان|دارایی)/.test(text) ||
    /(?:ip|آی\s*پی).*(?:سازمان|دارایی|میزبان|سامانه)/.test(text)
  );
}

function normalizeHeaderText(value) {
  const normalized =
    typeof base.normalizeLabel === "function"
      ? base.normalizeLabel(value)
      : value;

  return normalize(normalized);
}

function dedupeAssets(rows) {
  const seen = new Set();

  return rows.filter((row) => {
    const key = `${row.organization || ""}|${row.ip || ""}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function normalizeTargetModeWarningsV11(report) {
  if (!report || typeof report !== "object") return report;

  const warnings = new Set(report.extraction?.warnings || []);
  const mode = report.target?.mode || "unknown";

  if (mode === "single") {
    warnings.delete("multi_target_report");
    warnings.delete("scope_target_detected");
  } else if (mode === "multi_target") {
    warnings.delete("scope_target_detected");
    warnings.delete("target_resolved_from_table");
  } else if (mode === "scope") {
    warnings.delete("multi_target_report");
    warnings.delete("target_resolved_from_table");
  }

  report.extraction = {
    ...(report.extraction || {}),
    warnings: [...warnings],
  };

  return report;
}

function clean(value) {
  const text = String(value || "").replace(/\s+/g, " ").trim();
  return text || null;
}

function normalize(value) {
  return String(value || "")
    .replace(/[۰-۹]/g, (digit) =>
      String("۰۱۲۳۴۵۶۷۸۹".indexOf(digit)),
    )
    .replace(/ي/g, "ی")
    .replace(/ك/g, "ک")
    .replace(/[\u200c\u200f\u202a-\u202e]/g, " ")
    .replace(/[–—]/g, "-")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

module.exports = {
  PARSER_VERSION,
  parseDocxReport,
  enhanceFindingV11,
  classifyFindingV11,
  vulnerabilityFromFindingV11,
  needsStructuredAssetRecoveryV11,
  recoverUnresolvedTargetV11,
  extractStructuredAssetSystemsV11,
  findStructuredAssetHeaderV11,
  normalizeTargetModeWarningsV11,
};
