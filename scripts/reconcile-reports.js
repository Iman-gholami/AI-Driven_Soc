require("dotenv").config();

const mongoose = require("mongoose");
const { settings } = require("../src/core/config");
const HistoricalReport = require("../src/models/HistoricalReport");
const { ReportReconcileService } = require("../src/services/reportReconcileService");

async function main() {
  const args = process.argv.slice(2);
  const yearArg = args.find((value) => /^--year=/.test(value));
  const positionalYear = args.find((value) => /^\d{4}$/.test(value));
  const year = yearArg ? yearArg.split("=")[1] : positionalYear;
  const apply = args.includes("--apply");
  const pruneOrphans = args.includes("--prune-orphans");
  const detailLimitArg = args.find((value) => /^--detail-limit=/.test(value));
  const detailLimit = detailLimitArg ? Number(detailLimitArg.split("=")[1]) : 80;

  if (!year) {
    throw new Error("Usage: npm run reconcile:reports -- --year=1404 [--apply] [--prune-orphans] [--detail-limit=80]");
  }
  if (pruneOrphans && !apply) {
    throw new Error("--prune-orphans requires --apply");
  }
  if (!settings.mongodbUri) throw new Error("MONGODB_URI is required to reconcile reports");

  await mongoose.connect(settings.mongodbUri, {
    serverSelectionTimeoutMS: settings.mongodbServerSelectionTimeoutMs,
  });

  try {
    await HistoricalReport.init();
    const reconciler = new ReportReconcileService();
    process.stdout.write(`${JSON.stringify({ phase: "start", year: Number(year), apply, pruneOrphans })}\n`);
    const result = await reconciler.reconcileYear(year, {
      apply,
      pruneOrphans,
      detailLimit: Number.isFinite(detailLimit) && detailLimit > 0 ? detailLimit : 80,
    });
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
