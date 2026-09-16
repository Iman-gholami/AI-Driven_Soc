const path = require("node:path");
const HistoricalReport = require("../models/HistoricalReport");
const {
  ReportImportService,
  updateQualitySummary,
} = require("./reportImportService");

class ReportReconcileService {
  constructor({ model = HistoricalReport, importer = new ReportImportService({ model }) } = {}) {
    this.model = model;
    this.importer = importer;
  }

  async reconcileYear(year, { apply = false, pruneOrphans = false, detailLimit = 80 } = {}) {
    const scan = await this.importer.scanYear(year);
    const dbRows = await this.model.find({ year: scan.year }).lean().exec();
    const dbByDocumentKey = new Map(dbRows.map((row) => [String(row.documentKey || ""), row]));
    const dbByRelativePath = new Map(dbRows
      .filter((row) => row.source?.relativePath)
      .map((row) => [String(row.source.relativePath), row]));

    const result = {
      year: scan.year,
      apply: Boolean(apply),
      pruneOrphans: Boolean(pruneOrphans),
      local: {
        discovered: scan.count,
        eligible: scan.eligibleCount,
        oversized: scan.oversizedCount,
      },
      database: {
        existing: dbRows.length,
      },
      actions: {
        new: 0,
        changedSource: 0,
        staleParser: 0,
        metadataDrift: 0,
        identityChanged: 0,
        unchanged: 0,
        conflicts: 0,
        failed: 0,
        orphans: 0,
        inserted: 0,
        updated: 0,
        deleted: 0,
      },
      integrity: {
        duplicateDocumentKeys: [],
        duplicateSourceHashes: [],
        orphanDocuments: [],
        identityChanges: [],
      },
      quality: {
        unknownFindingCount: 0,
        unknownFindingFiles: [],
        findingCounts: {},
        reportTypeCounts: {},
        warningCounts: {},
      },
      changes: [],
      errors: [],
    };

    const parsedRows = [];
    const seenDocumentKeys = new Map();
    const seenHashes = new Map();

    for (const file of scan.files) {
      if (!file.eligible) {
        result.actions.failed += 1;
        result.errors.push({ file: file.relativePath, error: "file_too_large" });
        continue;
      }

      const absolutePath = path.resolve(this.importer.root, file.relativePath);
      try {
        const parsed = await this.importer.parser(absolutePath, { yearHint: scan.year });
        parsed.source.relativePath = file.relativePath;
        parsed.documentKey = String(parsed.reportNumber || parsed.source.sha256);
        updateQualitySummary(result.quality, parsed, file.relativePath);

        parsedRows.push({ file, parsed });
        pushMapArray(seenDocumentKeys, parsed.documentKey, file.relativePath);
        pushMapArray(seenHashes, parsed.source.sha256, file.relativePath);
      } catch (error) {
        result.actions.failed += 1;
        result.errors.push({ file: file.relativePath, error: safeError(error) });
      }
    }

    result.integrity.duplicateDocumentKeys = duplicateEntries(seenDocumentKeys, "documentKey");
    result.integrity.duplicateSourceHashes = duplicateEntries(seenHashes, "sha256");
    const conflictedKeys = new Set(result.integrity.duplicateDocumentKeys.map((item) => item.value));

    const matchedDbIds = new Set();

    for (const { file, parsed } of parsedRows) {
      if (conflictedKeys.has(parsed.documentKey)) {
        result.actions.conflicts += 1;
        addChange(result, detailLimit, {
          file: file.relativePath,
          documentKey: parsed.documentKey,
          status: "conflict_duplicate_document_key",
          after: summarizeRecord(parsed),
        });
        continue;
      }

      const byKey = dbByDocumentKey.get(parsed.documentKey);
      const byPath = dbByRelativePath.get(file.relativePath);
      const existing = byKey || byPath || null;
      if (existing?._id) matchedDbIds.add(String(existing._id));

      let status;
      if (!existing) status = "new";
      else if (String(existing.documentKey || "") !== parsed.documentKey) status = "identity_changed";
      else status = classifyReconcileStatus(existing, parsed);

      incrementStatus(result.actions, status);
      if (status !== "unchanged") {
        addChange(result, detailLimit, {
          file: file.relativePath,
          documentKey: parsed.documentKey,
          status,
          before: existing ? summarizeRecord(existing) : null,
          after: summarizeRecord(parsed),
        });
      }

      if (status === "identity_changed") {
        result.integrity.identityChanges.push({
          file: file.relativePath,
          databaseDocumentKey: existing?.documentKey || null,
          parsedDocumentKey: parsed.documentKey,
          reportNumber: parsed.reportNumber || null,
        });
        continue;
      }

      if (!apply || status === "unchanged") continue;

      if (status === "new") {
        await this.model.findOneAndUpdate(
          { documentKey: parsed.documentKey },
          { $set: parsed },
          { upsert: true, new: true, setDefaultsOnInsert: true },
        ).exec();
        result.actions.inserted += 1;
      } else {
        await this.model.findOneAndUpdate(
          { _id: existing._id },
          { $set: parsed },
          { new: true },
        ).exec();
        result.actions.updated += 1;
      }
    }

    const localPaths = new Set(scan.files.map((item) => item.relativePath));
    const orphans = dbRows.filter((row) => {
      const id = row._id ? String(row._id) : null;
      if (id && matchedDbIds.has(id)) return false;
      const relativePath = String(row.source?.relativePath || "");
      return !relativePath || !localPaths.has(relativePath);
    });

    result.actions.orphans = orphans.length;
    result.integrity.orphanDocuments = orphans.slice(0, detailLimit).map((row) => ({
      id: String(row._id || ""),
      documentKey: row.documentKey || null,
      reportNumber: row.reportNumber || null,
      file: row.source?.relativePath || null,
      parserVersion: row.extraction?.parserVersion || null,
    }));

    if (apply && pruneOrphans && orphans.length) {
      const ids = orphans.map((row) => row._id).filter(Boolean);
      if (ids.length) {
        const deleted = await this.model.deleteMany({ _id: { $in: ids } }).exec();
        result.actions.deleted = Number(deleted?.deletedCount || 0);
      }
    }

    return result;
  }
}

function classifyReconcileStatus(existing, parsed) {
  if (!existing) return "new";
  if (String(existing?.source?.sha256 || "") !== String(parsed?.source?.sha256 || "")) return "changed_source";
  if (String(existing?.extraction?.parserVersion || "") !== String(parsed?.extraction?.parserVersion || "")) return "stale_parser";
  if (stableJson(comparableRecord(existing)) !== stableJson(comparableRecord(parsed))) return "metadata_drift";
  return "unchanged";
}

function comparableRecord(record) {
  return {
    documentKey: record.documentKey || null,
    reportNumber: record.reportNumber || null,
    reportDateRaw: record.reportDateRaw || null,
    year: record.year ?? null,
    month: record.month ?? null,
    day: record.day ?? null,
    title: record.title || null,
    reportType: record.reportType || "unknown",
    provider: record.provider || null,
    contact: record.contact || null,
    effect: record.effect || null,
    target: plain(record.target),
    severity: plain(record.severity),
    urgency: plain(record.urgency),
    finding: plain(record.finding),
    vulnerability: plain(record.vulnerability),
    cves: array(record.cves),
    affectedCves: array(record.affectedCves),
    description: record.description || "",
    conclusion: record.conclusion || "",
    recommendations: array(record.recommendations),
    affectedSystems: array(record.affectedSystems).map(plain),
    phishingInfrastructure: array(record.phishingInfrastructure).map(plain),
    indicators: array(record.indicators).map(plain),
    fullText: record.fullText || "",
    source: {
      filename: record.source?.filename || null,
      relativePath: record.source?.relativePath || null,
      sha256: record.source?.sha256 || null,
      sizeBytes: record.source?.sizeBytes ?? 0,
    },
    extraction: {
      parserVersion: record.extraction?.parserVersion || null,
      paragraphCount: record.extraction?.paragraphCount ?? 0,
      tableCount: record.extraction?.tableCount ?? 0,
      warnings: array(record.extraction?.warnings),
      organizationMismatch: Boolean(record.extraction?.organizationMismatch),
      ipMismatch: Boolean(record.extraction?.ipMismatch),
    },
  };
}

function summarizeRecord(record) {
  return {
    reportNumber: record.reportNumber || null,
    date: record.reportDateRaw || null,
    title: record.title || null,
    reportType: record.reportType || "unknown",
    organization: record.target?.organization || null,
    ip: record.target?.ip || record.target?.rawIp || null,
    finding: record.finding?.type || "unknown",
    severity: record.severity?.level || "unknown",
    urgency: record.urgency?.normalized || "unknown",
    affectedSystems: array(record.affectedSystems).length,
    recommendations: array(record.recommendations).length,
    parserVersion: record.extraction?.parserVersion || null,
    warnings: array(record.extraction?.warnings),
    sha256: record.source?.sha256 || null,
  };
}

function incrementStatus(actions, status) {
  const map = {
    new: "new",
    changed_source: "changedSource",
    stale_parser: "staleParser",
    metadata_drift: "metadataDrift",
    identity_changed: "identityChanged",
    unchanged: "unchanged",
  };
  const key = map[status];
  if (key) actions[key] += 1;
}

function pushMapArray(map, key, value) {
  const normalized = String(key || "");
  if (!normalized) return;
  const list = map.get(normalized) || [];
  list.push(value);
  map.set(normalized, list);
}

function duplicateEntries(map, field) {
  return [...map.entries()]
    .filter(([, files]) => files.length > 1)
    .map(([value, files]) => ({ field, value, count: files.length, files }));
}

function addChange(result, limit, change) {
  if (result.changes.length < limit) result.changes.push(change);
}

function array(value) {
  return Array.isArray(value) ? value : [];
}

function plain(value) {
  if (!value) return value ?? null;
  if (typeof value.toObject === "function") return value.toObject({ depopulate: true, flattenMaps: true });
  return JSON.parse(JSON.stringify(value));
}

function stableJson(value) {
  return JSON.stringify(sortObject(value));
}

function sortObject(value) {
  if (Array.isArray(value)) return value.map(sortObject);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortObject(value[key])]));
}

function safeError(error) {
  return String(error?.message || error || "Unknown reconciliation error").slice(0, 500);
}

module.exports = {
  ReportReconcileService,
  classifyReconcileStatus,
  comparableRecord,
  summarizeRecord,
};
