#!/usr/bin/env node

require("dotenv").config();

const mongoose = require("mongoose");

// This migration must be able to inspect/drop the existing text index before
// Mongoose tries to auto-create the newer schema definition.
mongoose.set("autoIndex", false);

const { settings } = require("../src/core/config");
const HistoricalReport = require("../src/models/HistoricalReport");

async function main() {
  const apply = process.argv.includes("--apply");
  if (!settings.mongodbUri) throw new Error("MONGODB_URI is required");

  await mongoose.connect(settings.mongodbUri, {
    serverSelectionTimeoutMS: settings.mongodbServerSelectionTimeoutMs,
    autoIndex: false,
  });

  try {
    const collection = HistoricalReport.collection;
    const indexes = await collection.indexes();
    const existingTextIndexes = indexes.filter((index) => index?.key?._fts === "text");

    const desiredEntry = HistoricalReport.schema.indexes().find(([fields]) =>
      Object.values(fields || {}).some((value) => value === "text"),
    );
    if (!desiredEntry) throw new Error("HistoricalReport schema has no text index definition");

    const [desiredFields, desiredOptions = {}] = desiredEntry;
    const desiredFieldNames = Object.keys(desiredFields);
    const desiredName = desiredFieldNames.map((field) => `${field}_text`).join("_");
    const existing = existingTextIndexes.map((index) => ({
      name: index.name,
      fields: Object.keys(index.weights || {}).sort(),
    }));
    const desiredSorted = [...desiredFieldNames].sort();
    const alreadyCurrent = existingTextIndexes.length === 1
      && arraysEqual(Object.keys(existingTextIndexes[0].weights || {}).sort(), desiredSorted)
      && existingTextIndexes[0].name === desiredName;

    const plan = {
      apply,
      collection: collection.collectionName,
      existingTextIndexes: existing,
      desiredTextIndex: {
        name: desiredName,
        fields: desiredSorted,
      },
      alreadyCurrent,
      action: alreadyCurrent ? "none" : (apply ? "replace_text_index" : "would_replace_text_index"),
    };

    process.stdout.write(`${JSON.stringify({ phase: "plan", ...plan })}\n`);

    if (!apply || alreadyCurrent) return;

    for (const index of existingTextIndexes) {
      await collection.dropIndex(index.name);
      process.stdout.write(`${JSON.stringify({ phase: "drop", name: index.name })}\n`);
    }

    const createdName = await collection.createIndex(desiredFields, desiredOptions);
    process.stdout.write(`${JSON.stringify({ phase: "create", name: createdName })}\n`);

    const finalIndexes = await collection.indexes();
    const finalText = finalIndexes.find((index) => index?.key?._fts === "text");
    const finalFields = Object.keys(finalText?.weights || {}).sort();
    const verified = Boolean(finalText)
      && finalText.name === desiredName
      && arraysEqual(finalFields, desiredSorted);

    process.stdout.write(`${JSON.stringify({
      phase: "complete",
      verified,
      name: finalText?.name || null,
      fields: finalFields,
    })}\n`);

    if (!verified) throw new Error("Text index migration verification failed");
  } finally {
    await mongoose.disconnect();
  }
}

function arraysEqual(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
  });
}

module.exports = { main, arraysEqual };
