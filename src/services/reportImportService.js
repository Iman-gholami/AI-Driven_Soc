const fs = require("node:fs/promises");
const path = require("node:path");
const { settings } = require("../core/config");
const HistoricalReport = require("../models/HistoricalReport");
const { parseDocxReport } = require("./reportDocxParserV5");

class ReportImportService {
  constructor({
    model = HistoricalReport,
    root = settings.reportsRoot,
    maxFileBytes = settings.reportImportMaxFileBytes,
    parser = parseDocxReport,
  } = {}) {
    this.model = model;
    this.root = path.resolve(root || "reports");
    this.maxFileBytes = Number(maxFileBytes || 25 * 1024 * 1024);
    this.parser = parser;
  }

  async scanYear(year) {
    const normalizedYear = normalizeYear(year);
    const directory = this.resolveYearDirectory(normalizedYear);
    const files = await walkDocxFiles(directory);
    const rows = [];

    for (const filePath of files) {
      const stat = await fs.stat(filePath);
      rows.push({
        filename: path.basename(filePath),
        relativePath: toPortablePath(path.relative(this.root, filePath)),
        sizeBytes: stat.size,
        eligible: stat.size <= this.maxFileBytes,
      });
    }

    return {
      year: normalizedYear,
      root: this.root,
      directory,
      count: rows.length,
      eligibleCount: rows.filter((item) => item.eligible).length,
      oversizedCount: rows.filter((item) => !item.eligible).length,
      files: rows,
    };
  }

  async importYear(year, { dryRun = false } = {}) {
    const scan = await this.scanYear(year);
    const result = {
      year: scan.year,
      discovered: scan.count,
      eligible: scan.eligibleCount,
      imported: 0,
      updated: 0,
      skipped: 0,
      failed: 0,
      dryRun: Boolean(dryRun),
      previews: [],
      errors: [],
      quality: {
        unknownFindingCount: 0,
        unknownFindingFiles: [],
        findingCounts: {},
        reportTypeCounts: {},
        warningCounts: {},
      },
    };

    for (const file of scan.files) {
      if (!file.eligible) {
        result.failed += 1;
        result.errors.push({ file: file.relativePath, error: "file_too_large" });
        continue;
      }

      const absolutePath = path.resolve(this.root, file.relativePath);
      try {
        const parsed = await this.parser(absolutePath, { yearHint: scan.year });
        parsed.source.relativePath = file.relativePath;
        parsed.documentKey = String(parsed.reportNumber || parsed.source.sha256);
        updateQualitySummary(result.quality, parsed, file.relativePath);

        if (dryRun && result.previews.length < 20) {
          result.previews.push(toPreview(parsed, file.relativePath));
        }

        const existing = await this.model.findOne({ documentKey: parsed.documentKey }).lean().exec();
        if (existing?.source?.sha256 === parsed.source.sha256) {
          result.skipped += 1;
          continue;
        }

        if (dryRun) {
          if (existing) result.updated += 1;
          else result.imported += 1;
          continue;
        }

        await this.model.findOneAndUpdate(
          { documentKey: parsed.documentKey },
          { $set: parsed },
          { upsert: true, new: true, setDefaultsOnInsert: true },
        ).exec();

        if (existing) result.updated += 1;
        else result.imported += 1;
      } catch (error) {
        result.failed += 1;
        result.errors.push({
          file: file.relativePath,
          error: safeError(error),
        });
      }
    }

    return result;
  }

  resolveYearDirectory(year) {
    const candidate = path.resolve(this.root, String(year));
    const relative = path.relative(this.root, candidate);
    if (relative.startsWith("..") || path.isAbsolute(relative)) {
      throw new Error("Invalid reports directory");
    }
    return candidate;
  }
}

function updateQualitySummary(quality, parsed, relativePath) {
  const finding = parsed.finding?.type || "unknown";
  const reportType = parsed.reportType || "other";
  quality.findingCounts[finding] = (quality.findingCounts[finding] || 0) + 1;
  quality.reportTypeCounts[reportType] = (quality.reportTypeCounts[reportType] || 0) + 1;

  if (finding === "unknown") {
    quality.unknownFindingCount += 1;
    quality.unknownFindingFiles.push(relativePath);
  }

  for (const warning of parsed.extraction?.warnings || []) {
    quality.warningCounts[warning] = (quality.warningCounts[warning] || 0) + 1;
  }
}

function toPreview(parsed, relativePath) {
  return {
    file: relativePath,
    title: parsed.title || null,
    reportNumber: parsed.reportNumber || null,
    date: parsed.reportDateRaw || null,
    reportType: parsed.reportType || "other",
    provider: parsed.provider || null,
    organization: parsed.target?.organization || null,
    ip: parsed.target?.ip || null,
    rawIp: parsed.target?.rawIp || null,
    severityScore: parsed.severity?.score ?? null,
    severityLevel: parsed.severity?.level || "unknown",
    urgency: parsed.urgency?.normalized || "unknown",
    effect: parsed.effect || null,
    finding: parsed.finding?.type || "unknown",
    findingName: parsed.finding?.name || null,
    vulnerability: parsed.vulnerability?.normalizedName || "unknown",
    cves: Array.isArray(parsed.cves) ? parsed.cves : [],
    affectedSystems: Array.isArray(parsed.affectedSystems) ? parsed.affectedSystems.length : 0,
    affectedSystemPreview: Array.isArray(parsed.affectedSystems)
      ? parsed.affectedSystems.slice(0, 5).map((item) => ({
        organization: item.organization || null,
        ip: item.ip || null,
        domain: item.domain || null,
        url: item.url || null,
        service: item.service || null,
        port: item.port ?? null,
        packetCount: item.packetCount ?? null,
        participantIpCount: item.participantIpCount ?? null,
        trafficVolume: item.trafficVolumeRaw || null,
        eventDate: item.eventDateRaw || null,
        timeRange: item.timeRange || null,
        softwareVersion: item.softwareVersion || null,
        cves: Array.isArray(item.cves) ? item.cves : [],
      }))
      : [],
    phishingInfrastructure: Array.isArray(parsed.phishingInfrastructure)
      ? parsed.phishingInfrastructure.slice(0, 5)
      : [],
    recommendations: Array.isArray(parsed.recommendations) ? parsed.recommendations.length : 0,
    recommendationPreview: Array.isArray(parsed.recommendations) ? parsed.recommendations.slice(0, 5) : [],
    descriptionPreview: compactPreviewText(parsed.description, 900),
    conclusionPreview: compactPreviewText(parsed.conclusion, 500),
    warnings: parsed.extraction?.warnings || [],
  };
}

function compactPreviewText(value, maxChars) {
  const text = String(value || "").replace(/\s+/g, " ").trim();
  if (!text) return null;
  if (text.length <= maxChars) return text;
  return `${text.slice(0, maxChars - 1).trimEnd()}…`;
}

async function walkDocxFiles(directory) {
  let entries;
  try {
    entries = await fs.readdir(directory, { withFileTypes: true });
  } catch (error) {
    if (error?.code === "ENOENT") return [];
    throw error;
  }

  const files = [];
  for (const entry of entries) {
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await walkDocxFiles(fullPath));
    else if (entry.isFile() && path.extname(entry.name).toLowerCase() === ".docx" && !entry.name.startsWith("~$")) {
      files.push(fullPath);
    }
  }
  return files.sort((left, right) => left.localeCompare(right));
}

function normalizeYear(value) {
  const year = Number(String(value ?? "").replace(/[۰-۹]/g, (char) => String("۰۱۲۳۴۵۶۷۸۹".indexOf(char))));
  if (!Number.isInteger(year) || year < 1300 || year > 1600) {
    throw new ReportImportInputError("A valid Jalali report year is required");
  }
  return year;
}

function toPortablePath(value) {
  return String(value || "").split(path.sep).join("/");
}

function safeError(error) {
  const message = String(error?.message || error || "Unknown import error");
  return message.replace(/\/[^\s:]+/g, "<path>").slice(0, 500);
}

class ReportImportInputError extends Error {
  constructor(message) {
    super(message);
    this.name = "ReportImportInputError";
  }
}

module.exports = {
  ReportImportService,
  ReportImportInputError,
  walkDocxFiles,
  normalizeYear,
  toPortablePath,
  toPreview,
  updateQualitySummary,
};
