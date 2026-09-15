const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { settings } = require("../core/config");
const HistoricalReport = require("../models/HistoricalReport");
const { parseDocxReport } = require("./reportDocxParserV5");
const {
  ReportImportInputError,
  normalizeYear,
  toPortablePath,
  toPreview,
  updateQualitySummary,
} = require("./reportImportService");

const SESSION_VERSION = 1;
const DEFAULT_TTL_MS = 30 * 60 * 1000;
const MAX_FILES_PER_SESSION = 100;
const TOKEN_PATTERN = /^[a-f0-9]{48}$/;

class ReportUploadReviewService {
  constructor({
    model = HistoricalReport,
    root = settings.reportsRoot,
    maxFileBytes = settings.reportImportMaxFileBytes,
    parser = parseDocxReport,
    stagingRoot = path.join(os.tmpdir(), "ai-driven-soc-report-staging"),
    ttlMs = DEFAULT_TTL_MS,
  } = {}) {
    this.model = model;
    this.root = path.resolve(root || "reports");
    this.maxFileBytes = Number(maxFileBytes || 25 * 1024 * 1024);
    this.parser = parser;
    this.stagingRoot = path.resolve(stagingRoot);
    this.ttlMs = Math.max(Number(ttlMs) || DEFAULT_TTL_MS, 60 * 1000);
  }

  async previewUpload(year, files = []) {
    const normalizedYear = normalizeYear(year);
    const uploads = Array.isArray(files) ? files : [];
    if (!uploads.length) throw new ReportImportInputError("At least one DOCX file is required");
    if (uploads.length > MAX_FILES_PER_SESSION) {
      throw new ReportImportInputError(`A maximum of ${MAX_FILES_PER_SESSION} DOCX files can be reviewed at once`);
    }

    await this.cleanupExpiredSessions();
    await fs.mkdir(this.stagingRoot, { recursive: true, mode: 0o700 });

    const token = crypto.randomBytes(24).toString("hex");
    const sessionDirectory = this.resolveSessionDirectory(token);
    await fs.mkdir(sessionDirectory, { recursive: true, mode: 0o700 });

    const createdAt = new Date();
    const expiresAt = new Date(createdAt.getTime() + this.ttlMs);
    const quality = createQualitySummary();
    const errors = [];
    const items = [];
    const previews = [];
    const pendingTempPaths = new Set(uploads.map((file) => file?.path).filter(Boolean));

    try {
      for (let index = 0; index < uploads.length; index += 1) {
        const upload = uploads[index] || {};
        const rawName = path.basename(String(upload.originalname || upload.filename || `report-${index + 1}.docx`));

        if (path.extname(rawName).toLowerCase() !== ".docx") {
          errors.push({ file: rawName || `report-${index + 1}`, error: "only_docx_files_are_supported" });
          await safeUnlink(upload.path);
          pendingTempPaths.delete(upload.path);
          continue;
        }

        const originalName = safeDocxFilename(rawName);
        const sizeBytes = Number(upload.size || 0);
        if (sizeBytes > this.maxFileBytes) {
          errors.push({ file: originalName, error: "file_too_large" });
          await safeUnlink(upload.path);
          pendingTempPaths.delete(upload.path);
          continue;
        }

        const stagedFilename = `${String(index + 1).padStart(3, "0")}-${crypto.randomBytes(6).toString("hex")}.docx`;
        const stagedPath = path.join(sessionDirectory, stagedFilename);

        try {
          await moveFile(upload.path, stagedPath);
          pendingTempPaths.delete(upload.path);

          const parsed = await this.parser(stagedPath, { yearHint: normalizedYear });
          parsed.source = {
            ...(parsed.source || {}),
            filename: originalName,
            relativePath: originalName,
            sizeBytes: sizeBytes || parsed.source?.sizeBytes || 0,
          };
          parsed.documentKey = String(parsed.reportNumber || parsed.source.sha256);

          const existing = await this.model.findOne({ documentKey: parsed.documentKey }).lean().exec();
          const action = existing?.source?.sha256 === parsed.source.sha256
            ? "unchanged"
            : existing
              ? "update"
              : "new";
          const id = buildItemId(parsed, index);

          updateQualitySummary(quality, parsed, originalName);
          previews.push({ id, action, ...toPreview(parsed, originalName) });
          items.push({ id, action, originalName, stagedFilename, parsed });
        } catch (error) {
          errors.push({ file: originalName, error: safeError(error) });
          await safeUnlink(stagedPath);
        }
      }

      const manifest = {
        version: SESSION_VERSION,
        token,
        year: normalizedYear,
        createdAt: createdAt.toISOString(),
        expiresAt: expiresAt.toISOString(),
        items,
        errors,
        quality,
      };
      await fs.writeFile(
        path.join(sessionDirectory, "manifest.json"),
        JSON.stringify(manifest),
        { encoding: "utf8", mode: 0o600 },
      );

      return {
        sessionToken: token,
        year: normalizedYear,
        createdAt: manifest.createdAt,
        expiresAt: manifest.expiresAt,
        discovered: uploads.length,
        ready: items.length,
        failed: errors.length,
        previews,
        errors,
        quality,
        storagePolicy: {
          databaseChanged: false,
          stagedLocally: true,
          stagedFilesExpireMinutes: Math.round(this.ttlMs / 60000),
        },
      };
    } catch (error) {
      await fs.rm(sessionDirectory, { recursive: true, force: true });
      throw error;
    } finally {
      await Promise.all([...pendingTempPaths].map(safeUnlink));
    }
  }

  async commitUpload(token, { selectedIds } = {}) {
    const manifest = await this.readManifest(token);
    const selected = Array.isArray(selectedIds)
      ? new Set(selectedIds.map(String))
      : null;
    const items = manifest.items.filter((item) => !selected || selected.has(String(item.id)));
    if (!items.length) throw new ReportImportInputError("Select at least one reviewed report to save");

    const result = {
      sessionToken: token,
      year: manifest.year,
      selected: items.length,
      imported: 0,
      updated: 0,
      skipped: 0,
      failed: 0,
      errors: [],
    };

    await fs.mkdir(path.join(this.root, String(manifest.year)), { recursive: true, mode: 0o700 });
    const sessionDirectory = this.resolveSessionDirectory(token);

    for (const item of items) {
      try {
        const stagedPath = path.join(sessionDirectory, path.basename(item.stagedFilename));
        const parsed = item.parsed;
        const existing = await this.model.findOne({ documentKey: parsed.documentKey }).lean().exec();

        if (existing?.source?.sha256 === parsed.source?.sha256) {
          result.skipped += 1;
          continue;
        }

        const stored = await this.placeOriginalFile({
          stagedPath,
          filename: item.originalName,
          year: manifest.year,
          sha256: parsed.source?.sha256,
        });

        parsed.source = {
          ...(parsed.source || {}),
          filename: stored.filename,
          relativePath: stored.relativePath,
        };

        await this.model.findOneAndUpdate(
          { documentKey: parsed.documentKey },
          { $set: parsed },
          { upsert: true, new: true, setDefaultsOnInsert: true },
        ).exec();

        if (existing) result.updated += 1;
        else result.imported += 1;
      } catch (error) {
        result.failed += 1;
        result.errors.push({ file: item.originalName, error: safeError(error) });
      }
    }

    if (result.failed === 0) {
      await this.cancelUpload(token);
      result.sessionRetained = false;
    } else {
      result.sessionRetained = true;
    }

    return result;
  }

  async cancelUpload(token) {
    const sessionDirectory = this.resolveSessionDirectory(token);
    await fs.rm(sessionDirectory, { recursive: true, force: true });
    return { cancelled: true, sessionToken: token };
  }

  async readManifest(token) {
    const sessionDirectory = this.resolveSessionDirectory(token);
    let manifest;
    try {
      manifest = JSON.parse(await fs.readFile(path.join(sessionDirectory, "manifest.json"), "utf8"));
    } catch (error) {
      if (error?.code === "ENOENT") throw new ReportImportInputError("Upload preview session was not found or has expired");
      throw error;
    }

    if (manifest.version !== SESSION_VERSION || manifest.token !== token) {
      throw new ReportImportInputError("Invalid upload preview session");
    }

    if (!manifest.expiresAt || Date.parse(manifest.expiresAt) <= Date.now()) {
      await this.cancelUpload(token);
      throw new ReportImportInputError("Upload preview session has expired; upload the files again");
    }

    return manifest;
  }

  resolveSessionDirectory(token) {
    const normalized = String(token || "").trim().toLowerCase();
    if (!TOKEN_PATTERN.test(normalized)) throw new ReportImportInputError("Invalid upload preview token");
    const candidate = path.resolve(this.stagingRoot, normalized);
    const relative = path.relative(this.stagingRoot, candidate);
    if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {
      throw new ReportImportInputError("Invalid upload preview token");
    }
    return candidate;
  }

  async cleanupExpiredSessions() {
    let entries = [];
    try {
      entries = await fs.readdir(this.stagingRoot, { withFileTypes: true });
    } catch (error) {
      if (error?.code === "ENOENT") return;
      throw error;
    }

    const now = Date.now();
    await Promise.all(entries
      .filter((entry) => entry.isDirectory() && TOKEN_PATTERN.test(entry.name))
      .map(async (entry) => {
        const directory = path.join(this.stagingRoot, entry.name);
        try {
          const raw = await fs.readFile(path.join(directory, "manifest.json"), "utf8");
          const expiresAt = Date.parse(JSON.parse(raw).expiresAt || "");
          if (!Number.isFinite(expiresAt) || expiresAt <= now) {
            await fs.rm(directory, { recursive: true, force: true });
          }
        } catch (_) {
          const stat = await fs.stat(directory).catch(() => null);
          if (stat && now - stat.mtimeMs > this.ttlMs) {
            await fs.rm(directory, { recursive: true, force: true });
          }
        }
      }));
  }

  async placeOriginalFile({ stagedPath, filename, year, sha256 }) {
    const yearDirectory = path.join(this.root, String(year));
    const safeName = safeDocxFilename(filename);
    const extension = path.extname(safeName) || ".docx";
    const stem = path.basename(safeName, extension);
    let candidate = path.join(yearDirectory, safeName);

    let existingHash = await fileSha256(candidate);
    if (existingHash && sha256 && existingHash === sha256) {
      return storedFileReference(this.root, candidate);
    }

    if (existingHash) {
      const suffix = String(sha256 || crypto.randomBytes(4).toString("hex")).slice(0, 8);
      candidate = path.join(yearDirectory, `${stem}-${suffix}${extension}`);
      existingHash = await fileSha256(candidate);
      if (existingHash && sha256 && existingHash === sha256) {
        return storedFileReference(this.root, candidate);
      }
      if (existingHash) {
        candidate = path.join(yearDirectory, `${stem}-${suffix}-${crypto.randomBytes(3).toString("hex")}${extension}`);
      }
    }

    await fs.copyFile(stagedPath, candidate);
    await fs.chmod(candidate, 0o600).catch(() => {});
    return storedFileReference(this.root, candidate);
  }
}

function createQualitySummary() {
  return {
    unknownFindingCount: 0,
    unknownFindingFiles: [],
    findingCounts: {},
    reportTypeCounts: {},
    warningCounts: {},
  };
}

function buildItemId(parsed, index) {
  const seed = `${parsed.documentKey || ""}|${parsed.source?.sha256 || ""}|${index}`;
  return crypto.createHash("sha256").update(seed).digest("hex").slice(0, 24);
}

function safeDocxFilename(value) {
  let filename = path.basename(String(value || "report.docx"))
    .replace(/[\x00-\x1f<>:"/\\|?*]+/g, "_")
    .replace(/\s+/g, " ")
    .trim();
  if (!filename) filename = "report.docx";
  if (path.extname(filename).toLowerCase() !== ".docx") filename += ".docx";
  return filename.slice(0, 220);
}

function storedFileReference(root, candidate) {
  return {
    filename: path.basename(candidate),
    relativePath: toPortablePath(path.relative(root, candidate)),
  };
}

async function moveFile(source, destination) {
  if (!source) throw new ReportImportInputError("Uploaded file was not staged correctly");
  try {
    await fs.rename(source, destination);
  } catch (error) {
    if (error?.code !== "EXDEV") throw error;
    await fs.copyFile(source, destination);
    await safeUnlink(source);
  }
  await fs.chmod(destination, 0o600).catch(() => {});
}

async function safeUnlink(filePath) {
  if (!filePath) return;
  await fs.unlink(filePath).catch(() => {});
}

async function fileSha256(filePath) {
  try {
    const data = await fs.readFile(filePath);
    return crypto.createHash("sha256").update(data).digest("hex");
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

function safeError(error) {
  return String(error?.message || error || "Unknown upload error").replace(/\/[^\s:]+/g, "<path>").slice(0, 500);
}

module.exports = {
  ReportUploadReviewService,
  DEFAULT_TTL_MS,
  MAX_FILES_PER_SESSION,
  safeDocxFilename,
  createQualitySummary,
};
