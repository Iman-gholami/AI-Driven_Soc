const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const path = require("node:path");
const base = require("./docxBase");
const tableEnrichment = require("./tableEnrichment");
const findingCatalog = require("./findingCatalog");
const reportDateAndType = require("./reportDateAndType");
const aptTitleFinding = require("./aptTitleFinding");
const targetScope = require("./targetScope");
const mixedAssetRecovery = require("./mixedAssetRecovery");
const structuredAssetRecovery = require("./structuredAssetRecovery");

// Stored on every imported report. Bump it whenever a stage changes extraction output so
// `npm run reconcile:reports` can detect records parsed by an older pipeline.
const PARSER_VERSION = "docx-v11";

// Historical DOCX report parser. Each stage refines the record produced by the previous one;
// stage modules stamp their own STAGE_VERSION, and the final stamp is PARSER_VERSION.
//
//   docxBase                 read word/document.xml, extract labelled fields and base classification
//   tableEnrichment          affected systems, recommendations and phishing indicators from tables
//   findingCatalog           finding taxonomy for reports the base classifier left unknown
//   reportDateAndType        report-number date reconciliation and report type normalization
//   aptTitleFinding          prefer explicit APT / malicious-code titles over body mentions
//   targetScope              single / multi-target / scope resolution from table references
//   mixedAssetRecovery       recover targets from mixed organization+IP asset tables
//   structuredAssetRecovery  refined finding rules and structured asset-table recovery
async function parseDocxReport(filePath, { yearHint } = {}) {
  const absolutePath = path.resolve(filePath);
  if (path.extname(absolutePath).toLowerCase() !== ".docx") {
    throw new Error("Only .docx files are supported");
  }

  const [stat, buffer, xml] = await Promise.all([
    fs.stat(absolutePath),
    fs.readFile(absolutePath),
    base.extractDocumentXml(absolutePath),
  ]);
  const parsed = base.parseWordXml(xml);

  let report = base.extractReportRecord(parsed, { yearHint });
  report = tableEnrichment.enhanceReportRecord(report, parsed);
  report = findingCatalog.enhanceReportRecordV6(report);
  report = reportDateAndType.enhanceReportRecordV7(report, { yearHint });
  report = aptTitleFinding.enhanceReportRecordV8(report);
  report = targetScope.enhanceReportRecordV9(report);

  if (mixedAssetRecovery.needsMixedAssetRecovery(report)) {
    report = mixedAssetRecovery.recoverUnresolvedTargetV10(report, parsed.tables);
  }

  report = structuredAssetRecovery.enhanceFindingV11(report);
  if (structuredAssetRecovery.needsStructuredAssetRecoveryV11(report)) {
    report = structuredAssetRecovery.recoverUnresolvedTargetV11(report, parsed.tables);
  }
  report = structuredAssetRecovery.normalizeTargetModeWarningsV11(report);

  return {
    ...report,
    extraction: {
      ...(report.extraction || {}),
      parserVersion: PARSER_VERSION,
    },
    source: {
      filename: path.basename(absolutePath),
      relativePath: path.basename(absolutePath),
      sha256: crypto.createHash("sha256").update(buffer).digest("hex"),
      sizeBytes: stat.size,
      importedAt: new Date(),
    },
  };
}

module.exports = { PARSER_VERSION, parseDocxReport };
