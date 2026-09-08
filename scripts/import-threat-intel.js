require("dotenv").config();

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const readline = require("node:readline");
const mongoose = require("mongoose");

const { settings } = require("../src/core/config");
const ThreatIntelObservation = require("../src/models/ThreatIntelObservation");
const IntelDatasetState = require("../src/models/IntelDatasetState");
const { normalizeIpv4 } = require("../src/services/ipExtractor");

const DEFAULT_BATCH_SIZE = 2000;

async function importThreatIntel(filePath, { batchSize = DEFAULT_BATCH_SIZE } = {}) {
  const importId = crypto.randomUUID();
  const input = fs.createReadStream(filePath, { encoding: "utf8" });
  const hash = crypto.createHash("sha256");
  input.on("data", (chunk) => hash.update(chunk));

  const lines = readline.createInterface({ input, crlfDelay: Infinity });
  const stats = { processed: 0, invalid: 0, batches: 0, upserted: 0, modified: 0 };
  let batch = [];

  async function flush() {
    if (!batch.length) return;

    const operations = batch.map((observation) => ({
      updateOne: {
        filter: { importId, uniqueId: observation.uniqueId },
        update: { $set: { ...observation, importId } },
        upsert: true,
      },
    }));

    const result = await ThreatIntelObservation.bulkWrite(operations, { ordered: false });
    stats.batches += 1;
    stats.upserted += Number(result.upsertedCount || 0);
    stats.modified += Number(result.modifiedCount || 0);
    batch = [];
  }

  for await (const rawLine of lines) {
    const line = rawLine.replace(/^\uFEFF/, "").trim();
    if (!line) continue;

    try {
      const source = JSON.parse(line);
      const mapped = mapThreatObservation(source);
      if (!mapped) {
        stats.invalid += 1;
        continue;
      }

      batch.push(mapped);
      stats.processed += 1;
      if (batch.length >= batchSize) await flush();
    } catch (_) {
      stats.invalid += 1;
    }
  }

  await flush();
  if (!stats.processed) throw new Error("No valid threat-intelligence records were imported");

  const checksumSha256 = hash.digest("hex");
  const recordCount = await ThreatIntelObservation.countDocuments({ importId });

  await IntelDatasetState.findOneAndUpdate(
    { dataset: "threat_intel" },
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

  const cleanup = await ThreatIntelObservation.deleteMany({ importId: { $ne: importId } });

  return {
    importId,
    checksumSha256,
    recordCount,
    deletedPreviousRecords: Number(cleanup.deletedCount || 0),
    ...stats,
  };
}

function mapThreatObservation(source = {}) {
  const uniqueId = stringValue(source.unique_id);
  if (!uniqueId) return null;

  const sourceIp = normalizeIpv4(source["source.ip"]);
  const destinationIp = normalizeIpv4(source["destination.ip"]);
  if (!sourceIp && !destinationIp) return null;

  return {
    uniqueId,
    provider: stringValue(source["feed.provider"]),
    feedName: stringValue(source["feed.name"]),
    classification: {
      identifier: stringValue(source["classification.identifier"]),
      taxonomy: stringValue(source["classification.taxonomy"]),
      type: stringValue(source["classification.type"]),
    },
    malwareName: stringValue(source["malware.name"]),
    protocol: stringValue(source["protocol.transport"])?.toLowerCase(),
    source: {
      ip: sourceIp || undefined,
      port: portValue(source["source.port"]),
      asn: integerValue(source["source.asn"]),
      asName: stringValue(source["source.as_name"]),
      orgEnName: stringValue(source["source.org_en_name"]),
      orgFaName: stringValue(source["source.org_fa_name"]),
      orgFullName: stringValue(source["source.org_full_name"]),
      orgType: stringValue(source["source.org_type"]),
      geo: {
        country: stringValue(source["source.geolocation.cc"]),
        city: stringValue(source["source.geolocation.city"]),
        latitude: numberValue(source["source.geolocation.latitude"]),
        longitude: numberValue(source["source.geolocation.longitude"]),
      },
    },
    destination: {
      ip: destinationIp || undefined,
      port: portValue(source["destination.port"]),
      fqdn: stringValue(source["destination.fqdn"]),
      asn: integerValue(source["destination.asn"]),
      asName: stringValue(source["destination.as_name"]),
      orgEnName: stringValue(source["destination.org_en_name"]),
      orgFaName: stringValue(source["destination.org_fa_name"]),
      orgFullName: stringValue(source["destination.org_full_name"]),
      orgType: stringValue(source["destination.org_type"]),
      geo: {
        country: stringValue(source["destination.geolocation.cc"]),
        city: stringValue(source["destination.geolocation.city"]),
        latitude: numberValue(source["destination.geolocation.latitude"]),
        longitude: numberValue(source["destination.geolocation.longitude"]),
      },
    },
    sourceTime: dateValue(source["time.source"]),
    observationTime: dateValue(source["time.observation"]),
  };
}

function stringValue(value) {
  if (value === undefined || value === null) return undefined;
  const text = String(value).trim();
  return text || undefined;
}

function numberValue(value) {
  if (value === undefined || value === null || value === "") return undefined;
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : undefined;
}

function integerValue(value) {
  const numeric = numberValue(value);
  return Number.isInteger(numeric) && numeric >= 0 ? numeric : undefined;
}

function portValue(value) {
  const numeric = integerValue(value);
  return numeric !== undefined && numeric <= 65535 ? numeric : undefined;
}

function dateValue(value) {
  if (!value) return undefined;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date;
}

async function main() {
  const filePath = process.argv[2] || process.env.THREAT_INTEL_DATASET_PATH;
  if (!filePath) {
    throw new Error(
      "Usage: npm run import:threat-intel -- /path/to/threat-feed.jsonl (or set THREAT_INTEL_DATASET_PATH)",
    );
  }
  if (!settings.mongodbUri) throw new Error("MONGODB_URI is required to import threat intelligence");

  const resolved = path.resolve(filePath);
  await mongoose.connect(settings.mongodbUri, {
    serverSelectionTimeoutMS: settings.mongodbServerSelectionTimeoutMs,
  });

  try {
    await Promise.all([ThreatIntelObservation.init(), IntelDatasetState.init()]);
    const stats = await importThreatIntel(resolved);
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

module.exports = {
  importThreatIntel,
  mapThreatObservation,
};
