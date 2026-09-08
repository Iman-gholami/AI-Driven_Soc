require("dotenv").config();

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const readline = require("node:readline");
const mongoose = require("mongoose");

const { settings } = require("../src/core/config");
const IpAsset = require("../src/models/IpAsset");
const IntelDatasetState = require("../src/models/IntelDatasetState");
const { normalizeIpv4 } = require("../src/services/ipExtractor");

const DEFAULT_BATCH_SIZE = 2000;

async function importAssets(filePath, { batchSize = DEFAULT_BATCH_SIZE } = {}) {
  const importId = crypto.randomUUID();
  const input = fs.createReadStream(filePath, { encoding: "utf8" });
  const hash = crypto.createHash("sha256");
  input.on("data", (chunk) => hash.update(chunk));

  const lines = readline.createInterface({ input, crlfDelay: Infinity });
  const stats = { processed: 0, invalid: 0, batches: 0, upserted: 0, modified: 0 };
  let headers = null;
  let delimiter = null;
  let batch = [];

  async function flush() {
    if (!batch.length) return;

    const uniqueBatch = [...new Map(batch.map((asset) => [asset.ip, asset])).values()];
    const operations = uniqueBatch.map((asset) => ({
      updateOne: {
        filter: { importId, ip: asset.ip },
        update: { $set: { ...asset, importId } },
        upsert: true,
      },
    }));

    const result = await IpAsset.bulkWrite(operations, { ordered: false });
    stats.batches += 1;
    stats.upserted += Number(result.upsertedCount || 0);
    stats.modified += Number(result.modifiedCount || 0);
    batch = [];
  }

  for await (const rawLine of lines) {
    const line = rawLine.replace(/^\uFEFF/, "").trim();
    if (!line) continue;

    if (!headers) {
      delimiter = detectDelimiter(line);
      headers = parseDelimitedLine(line, delimiter).map((value) => value.trim().toLowerCase());
      const required = ["asset", "bunit", "category", "province"];
      const missing = required.filter((key) => !headers.includes(key));
      if (missing.length) {
        throw new Error(`Asset file is missing required columns: ${missing.join(", ")}`);
      }
      continue;
    }

    const values = parseDelimitedLine(line, delimiter);
    const row = Object.fromEntries(headers.map((header, index) => [header, values[index] ?? ""]));
    const ip = normalizeIpv4(row.asset);

    if (!ip || !String(row.bunit || "").trim()) {
      stats.invalid += 1;
      continue;
    }

    batch.push({
      ip,
      bunit: String(row.bunit).trim(),
      category: String(row.category || "").trim() || undefined,
      province: String(row.province || "").trim() || undefined,
    });
    stats.processed += 1;

    if (batch.length >= batchSize) await flush();
  }

  await flush();

  if (!stats.processed) throw new Error("No valid IPv4 asset records were imported");

  const checksumSha256 = hash.digest("hex");
  const recordCount = await IpAsset.countDocuments({ importId });

  await IntelDatasetState.findOneAndUpdate(
    { dataset: "asset_registry" },
    {
      $set: {
        activeImportId: importId,
        sourceFile: path.basename(filePath),
        checksumSha256,
        recordCount,
        invalidCount: stats.invalid,
        importedAt: new Date(),
      },
    },
    { upsert: true, new: true, setDefaultsOnInsert: true },
  );

  const cleanup = await IpAsset.deleteMany({ importId: { $ne: importId } });

  return {
    importId,
    checksumSha256,
    recordCount,
    deletedPreviousRecords: Number(cleanup.deletedCount || 0),
    ...stats,
  };
}

function detectDelimiter(headerLine) {
  const candidates = [",", "\t", ";"];
  const scored = candidates
    .map((candidate) => ({
      candidate,
      count: headerLine.split(candidate).length - 1,
    }))
    .sort((a, b) => b.count - a.count);

  if (!scored[0]?.count) throw new Error("Unable to detect CSV/TSV delimiter");
  return scored[0].candidate;
}

function parseDelimitedLine(line, delimiter) {
  const values = [];
  let current = "";
  let quoted = false;

  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];

    if (char === '"') {
      if (quoted && line[index + 1] === '"') {
        current += '"';
        index += 1;
      } else {
        quoted = !quoted;
      }
      continue;
    }

    if (char === delimiter && !quoted) {
      values.push(current);
      current = "";
      continue;
    }

    current += char;
  }

  values.push(current);
  return values;
}

async function main() {
  const filePath = process.argv[2] || process.env.IP_ASSET_DATASET_PATH;
  if (!filePath) {
    throw new Error(
      "Usage: npm run import:ip-assets -- /path/to/assets.csv (or set IP_ASSET_DATASET_PATH)",
    );
  }
  if (!settings.mongodbUri) throw new Error("MONGODB_URI is required to import IP assets");

  const resolved = path.resolve(filePath);
  await mongoose.connect(settings.mongodbUri, {
    serverSelectionTimeoutMS: settings.mongodbServerSelectionTimeoutMs,
  });

  try {
    await Promise.all([IpAsset.init(), IntelDatasetState.init()]);
    const stats = await importAssets(resolved);
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

module.exports = { importAssets, parseDelimitedLine, detectDelimiter };
