require("dotenv").config();

const mongoose = require("mongoose");
const { settings } = require("../src/core/config");
const HistoricalReport = require("../src/models/HistoricalReport");
const { ReportImportService } = require("../src/services/reportImportService");

async function main() {
  const args = process.argv.slice(2);
  const yearArg = args.find((value) => /^--year=/.test(value));
  const positionalYear = args.find((value) => /^\d{4}$/.test(value));
  const year = yearArg ? yearArg.split("=")[1] : positionalYear;
  const dryRun = args.includes("--dry-run");

  if (!year) {
    throw new Error("Usage: npm run import:reports -- --year=1404 [--dry-run]");
  }
  if (!settings.mongodbUri) throw new Error("MONGODB_URI is required to import reports");

  await mongoose.connect(settings.mongodbUri, {
    serverSelectionTimeoutMS: settings.mongodbServerSelectionTimeoutMs,
  });

  try {
    await HistoricalReport.init();
    const importer = new ReportImportService();
    const scan = await importer.scanYear(year);
    process.stdout.write(`${JSON.stringify({ phase: "scan", root: scan.root, year: scan.year, discovered: scan.count, eligible: scan.eligibleCount })}\n`);
    const result = await importer.importYear(year, { dryRun });
    process.stdout.write(`${JSON.stringify({ phase: "complete", ...result })}\n`);
  } finally {
    await mongoose.disconnect();
  }
}

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
  });
}

module.exports = { main };
