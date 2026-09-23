require("dotenv").config();

const path = require("node:path");
const { ReportImportService, normalizeYear } = require("../src/services/reportImportService");
const { parseDocxReport } = require("../src/services/reportParser");

async function main() {
  const args = process.argv.slice(2);
  const yearArg = args.find((value) => /^--year=/.test(value));
  const positionalYear = args.find((value) => /^\d{4}$/.test(value));
  const year = normalizeYear(yearArg ? yearArg.split("=")[1] : positionalYear);
  const includeAllFiles = args.includes("--all-files");

  const importer = new ReportImportService({ parser: parseDocxReport });
  const scan = await importer.scanYear(year);
  const groups = new Map();
  const failures = [];
  let unknownCount = 0;
  let parsedCount = 0;

  for (const file of scan.files) {
    if (!file.eligible) {
      failures.push({ file: file.relativePath, error: "file_too_large" });
      continue;
    }

    try {
      const absolutePath = path.resolve(importer.root, file.relativePath);
      const parsed = await parseDocxReport(absolutePath, { yearHint: year });
      parsedCount += 1;
      if (parsed.finding?.type !== "unknown") continue;
      unknownCount += 1;

      const key = buildGroupKey(parsed);
      if (!groups.has(key)) {
        groups.set(key, {
          key,
          count: 0,
          titles: new Map(),
          reportTypes: new Map(),
          effects: new Map(),
          files: [],
          descriptionSample: null,
        });
      }

      const group = groups.get(key);
      group.count += 1;
      increment(group.titles, compact(parsed.title));
      increment(group.reportTypes, parsed.reportType || "unknown");
      increment(group.effects, compact(parsed.effect));
      if (includeAllFiles || group.files.length < 8) group.files.push(file.relativePath);
      if (!group.descriptionSample && parsed.description) {
        group.descriptionSample = preview(parsed.description, 420);
      }
    } catch (error) {
      failures.push({
        file: file.relativePath,
        error: String(error?.message || error).slice(0, 300),
      });
    }
  }

  const outputGroups = [...groups.values()]
    .sort((a, b) => b.count - a.count || a.key.localeCompare(b.key, "fa"))
    .map((group) => ({
      key: group.key,
      count: group.count,
      titleSamples: topEntries(group.titles, 4),
      reportTypes: Object.fromEntries(topEntries(group.reportTypes, 10).map(({ value, count }) => [value, count])),
      effectSamples: topEntries(group.effects, 3).map((item) => item.value).filter(Boolean),
      descriptionSample: group.descriptionSample,
      files: group.files,
    }));

  process.stdout.write(`${JSON.stringify({
    phase: "unknown-profile",
    year,
    discovered: scan.count,
    eligible: scan.eligibleCount,
    parsed: parsedCount,
    unknownCount,
    unknownPercent: parsedCount ? Math.round((unknownCount / parsedCount) * 1000) / 10 : 0,
    groupCount: outputGroups.length,
    groups: outputGroups,
    failures,
  }, null, 2)}\n`);
}

function buildGroupKey(report) {
  const title = normalizeText(report.title)
    .replace(/^(?:گزارش\s+)?(?:حادثه|رخداد)\s+سایبری\s*[-–—:]?\s*/u, "")
    .replace(/^پیکربندی\s+نامناسب\s*[-–—:]?\s*/u, "")
    .replace(/^آسیب\s*پذیری\s*[-–—:]?\s*/u, "")
    .replace(/^گزارش\s*[-–—:]?\s*/u, "")
    .trim();
  return title || normalizeText(report.effect) || "untitled_unknown";
}

function normalizeText(value) {
  return String(value || "")
    .replace(/ي/g, "ی")
    .replace(/ك/g, "ک")
    .replace(/[\u200c\u200f\u202a-\u202e]/g, " ")
    .replace(/[\u064b-\u065f\u0670]/g, "")
    .replace(/[“”"'`]/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

function compact(value) {
  const text = String(value || "").replace(/\s+/g, " ").trim();
  return text || null;
}

function preview(value, max) {
  const text = compact(value) || "";
  return text.length <= max ? text : `${text.slice(0, max - 1).trimEnd()}…`;
}

function increment(map, value) {
  if (!value) return;
  map.set(value, (map.get(value) || 0) + 1);
}

function topEntries(map, limit) {
  return [...map.entries()]
    .sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0]), "fa"))
    .slice(0, limit)
    .map(([value, count]) => ({ value, count }));
}

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
  });
}

module.exports = { main, buildGroupKey, normalizeText };
