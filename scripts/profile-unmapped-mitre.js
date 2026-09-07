require("dotenv").config();

const mongoose = require("mongoose");
const { settings } = require("../src/core/config");

async function main() {
  if (!settings.mongodbUri) throw new Error("MONGODB_URI is required");

  await mongoose.connect(settings.mongodbUri, {
    serverSelectionTimeoutMS: settings.mongodbServerSelectionTimeoutMs,
  });

  try {
    const collection = mongoose.connection.collection("detectionrules");
    const baseMatch = {
      isCurrent: true,
      "mitre.mapped": { $ne: true },
    };

    const [total, sourceFiles, classtypes, protocols] = await Promise.all([
      collection.countDocuments(baseMatch),
      collection.aggregate([
        { $match: baseMatch },
        { $group: { _id: { $ifNull: ["$sourceFile", "unknown"] }, count: { $sum: 1 } } },
        { $sort: { count: -1, _id: 1 } },
        { $limit: 30 },
        { $project: { _id: 0, value: "$_id", count: 1 } },
      ], { allowDiskUse: true }).toArray(),
      collection.aggregate([
        { $match: baseMatch },
        { $group: { _id: { $ifNull: ["$classtype", "unknown"] }, count: { $sum: 1 } } },
        { $sort: { count: -1, _id: 1 } },
        { $limit: 30 },
        { $project: { _id: 0, value: "$_id", count: 1 } },
      ], { allowDiskUse: true }).toArray(),
      collection.aggregate([
        { $match: baseMatch },
        { $group: { _id: { $ifNull: ["$protocol", "unknown"] }, count: { $sum: 1 } } },
        { $sort: { count: -1, _id: 1 } },
        { $limit: 20 },
        { $project: { _id: 0, value: "$_id", count: 1 } },
      ], { allowDiskUse: true }).toArray(),
    ]);

    const topSources = sourceFiles.slice(0, 12).map((item) => item.value);
    const samples = [];

    for (const sourceFile of topSources) {
      const rows = await collection.find(
        { ...baseMatch, sourceFile: sourceFile === "unknown" ? null : sourceFile },
        {
          projection: {
            _id: 0,
            ruleId: 1,
            title: 1,
            classtype: 1,
            protocol: 1,
            sourceFile: 1,
            "parsedRule.references": 1,
            "parsedRule.metadata": 1,
          },
        },
      ).limit(3).toArray();

      samples.push({ sourceFile, rules: rows });
    }

    process.stdout.write(JSON.stringify({
      totalUnmapped: total,
      topSourceFiles: sourceFiles,
      topClasstypes: classtypes,
      topProtocols: protocols,
      samples,
    }, null, 2) + "\n");
  } finally {
    await mongoose.disconnect();
  }
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});
