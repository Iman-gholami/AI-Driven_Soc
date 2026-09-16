const base = require("./reportDocxParser");
const v4 = require("./reportDocxParserV4");
const v9 = require("./reportDocxParserV9");

const PARSER_VERSION = "docx-v10";

async function parseDocxReport(filePath, { yearHint } = {}) {
  let report = await v9.parseDocxReport(filePath, { yearHint });

  if (needsMixedAssetRecovery(report)) {
    const xml = await base.extractDocumentXml(filePath);
    const parsed = base.parseWordXml(xml);
    report = recoverUnresolvedTargetV10(report, parsed.tables);
  }

  report.extraction = {
    ...(report.extraction || {}),
    parserVersion: PARSER_VERSION,
  };

  return report;
}

function needsMixedAssetRecovery(report) {
  if (!report || typeof report !== "object") return false;
  const warnings = report.extraction?.warnings || [];
  const hasTableReference = Boolean(report.target?.tableReference);
  const affectedCount = Array.isArray(report.affectedSystems) ? report.affectedSystems.length : 0;
  return warnings.includes("target_table_reference_unresolved") || (hasTableReference && affectedCount === 0);
}

function recoverUnresolvedTargetV10(report, tables) {
  if (!needsMixedAssetRecovery(report)) return report;

  const recovered = extractMixedAssetSystemsV10(tables);
  const currentCount = Array.isArray(report.affectedSystems) ? report.affectedSystems.length : 0;
  if (recovered.length <= currentCount) return report;

  report.affectedSystems = recovered;
  report.affectedCves = [...new Set(
    recovered.flatMap((item) => Array.isArray(item.cves) ? item.cves : []),
  )];

  report = v9.enhanceReportRecordV9(report);

  const warnings = new Set(report.extraction?.warnings || []);
  warnings.delete("target_table_reference_unresolved");
  warnings.add("mixed_asset_table_recovered");

  report.extraction = {
    ...(report.extraction || {}),
    parserVersion: PARSER_VERSION,
    warnings: [...warnings],
  };

  return report;
}

function extractMixedAssetSystemsV10(tables) {
  const sanitizedTables = [];

  for (const table of Array.isArray(tables) ? tables : []) {
    if (!Array.isArray(table) || table.length < 2) continue;
    const headerIndex = findMixedAssetHeaderIndexV10(table);
    if (headerIndex < 0) continue;

    const sanitized = table.map((row) => Array.isArray(row) ? [...row] : row);
    sanitized[headerIndex] = sanitized[headerIndex].map((cell) => {
      const key = v4.normalizeHeaderV4(cell);
      return key && key.startsWith("phishing_") ? "" : cell;
    });
    sanitizedTables.push(sanitized);
  }

  return v4.extractAffectedSystemsV4(sanitizedTables)
    .filter((item) => item && item.ip);
}

function findMixedAssetHeaderIndexV10(table) {
  let bestIndex = -1;
  let bestScore = -1;
  const limit = Math.min(table.length, 8);

  for (let index = 0; index < limit; index += 1) {
    const row = table[index];
    if (!Array.isArray(row)) continue;
    const keys = row.map(v4.normalizeHeaderV4).filter(Boolean);
    const hasPhishingField = keys.some((key) => key.startsWith("phishing_"));
    const hasAssetIdentity = keys.some((key) => ["ip", "organization", "domain", "url"].includes(key));
    const score = keys.length;

    if (!hasPhishingField || !hasAssetIdentity || score < 2) continue;
    if (score > bestScore) {
      bestIndex = index;
      bestScore = score;
    }
  }

  return bestIndex;
}

module.exports = {
  PARSER_VERSION,
  parseDocxReport,
  needsMixedAssetRecovery,
  recoverUnresolvedTargetV10,
  extractMixedAssetSystemsV10,
  findMixedAssetHeaderIndexV10,
};
