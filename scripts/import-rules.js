require("dotenv").config();
const fs = require("node:fs");
const path = require("node:path");
const readline = require("node:readline");
const mongoose = require("mongoose");

const { settings } = require("../src/core/config");
const { DetectionRuleRepository } = require("../src/repositories/DetectionRuleRepository");
const { mapSourceRule } = require("../src/services/ruleParser");
const MitreCoverageSnapshot = require("../src/models/MitreCoverageSnapshot");

const DEFAULT_BATCH_SIZE = 1000;

async function importRules(filePath, { batchSize = DEFAULT_BATCH_SIZE, repository = new DetectionRuleRepository() } = {}) {
  const input = fs.createReadStream(filePath, { encoding: "utf8" });
  const lines = readline.createInterface({ input, crlfDelay: Infinity });
  const stats = { processed: 0, invalid: 0, batches: 0, upserted: 0, modified: 0 };
  let batch = [];

  async function flush() {
    if (batch.length === 0) return;
    const result = await repository.bulkUpsert(batch);
    stats.batches += 1;
    stats.upserted += Number(result?.upsertedCount || 0);
    stats.modified += Number(result?.modifiedCount || 0);
    batch = [];
  }

  for await (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    try {
      const source = JSON.parse(trimmed);
      batch.push(mapSourceRule(source));
      stats.processed += 1;
      if (batch.length >= batchSize) await flush();
    } catch (error) {
      stats.invalid += 1;
      process.stderr.write(`Skipping invalid rule at input line ${stats.processed + stats.invalid}: ${error.message}\n`);
    }
  }

  await flush();
  return stats;
}

async function main() {
  const filePath = process.argv[2] || process.env.RULE_DATASET_PATH;
  if (!filePath) {
    throw new Error("Usage: npm run import:rules -- /path/to/rules.dataset.json (or set RULE_DATASET_PATH)");
  }
  if (!settings.mongodbUri) {
    throw new Error("MONGODB_URI is required to import detection rules");
  }

  const resolved = path.resolve(filePath);
  await mongoose.connect(settings.mongodbUri, {
    serverSelectionTimeoutMS: settings.mongodbServerSelectionTimeoutMs,
  });

  try {
    const stats = await importRules(resolved);
    await MitreCoverageSnapshot.deleteMany({});
    process.stdout.write(`${JSON.stringify({ file: resolved, ...stats })}\n`);
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

module.exports = { importRules };
