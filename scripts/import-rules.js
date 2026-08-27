require("dotenv").config();
const fs = require("node:fs");
const path = require("node:path");
const readline = require("node:readline");
const mongoose = require("mongoose");

const { settings } = require("../src/core/config");
const { DetectionRuleRepository } = require("../src/repositories/DetectionRuleRepository");
const { normalizeTitle, parseRawRule } = require("../src/services/ruleParser");

const DEFAULT_BATCH_SIZE = 1000;

function mapSourceRule(source) {
  if (!source || typeof source !== "object") throw new Error("Rule record must be an object");
  if (!source.rule_id || !source.title || !source.raw_rule) {
    throw new Error("Rule is missing rule_id, title, or raw_rule");
  }

  const revision = Number(source.rev || 0);
  const parsedRule = parseRawRule(source.raw_rule);
  if ((!parsedRule.pcre || parsedRule.pcre.length === 0) && source.pcre) {
    parsedRule.pcre = [String(source.pcre)];
  }

  return {
    ruleId: String(source.rule_id),
    action: String(source.raw_rule).trim().split(/\s+/, 1)[0].toLowerCase(),
    revision: Number.isFinite(revision) ? revision : 0,
    title: String(source.title).trim(),
    normalizedTitle: normalizeTitle(source.title),
    classtype: source.classtype ? String(source.classtype) : undefined,
    protocol: source.protocol ? String(source.protocol).toLowerCase() : undefined,
    src: source.src ? String(source.src) : undefined,
    srcPort: source.src_port ? String(source.src_port) : undefined,
    direction: source.direction ? String(source.direction) : undefined,
    dst: source.dst ? String(source.dst) : undefined,
    dstPort: source.dst_port ? String(source.dst_port) : undefined,
    sourceContents: Array.isArray(source.contents) ? source.contents.map(String) : [],
    sourcePcre: source.pcre ? String(source.pcre) : undefined,
    rawRule: String(source.raw_rule),
    sourceFile: source.source_file ? String(source.source_file) : undefined,
    parsedRule,
  };
}

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

module.exports = { mapSourceRule, importRules };
