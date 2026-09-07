require("dotenv").config();

const mongoose = require("mongoose");
const { settings } = require("../src/core/config");
const DetectionRule = require("../src/models/DetectionRule");
const MitreTechnique = require("../src/models/MitreTechnique");
const MitreCoverageSnapshot = require("../src/models/MitreCoverageSnapshot");
const {
  CURATION_VERSION,
  deriveCuratedMitreMappings,
} = require("../src/services/mitreCuratedMapping");

const APPLY = process.argv.includes("--apply");

async function main() {
  if (!settings.mongodbUri) throw new Error("MONGODB_URI is required");

  await mongoose.connect(settings.mongodbUri, {
    serverSelectionTimeoutMS: settings.mongodbServerSelectionTimeoutMs,
  });

  try {
    const activeTechniques = await MitreTechnique
      .find({ revoked: { $ne: true }, deprecated: { $ne: true } })
      .select("techniqueId")
      .lean()
      .exec();
    const activeIds = new Set(activeTechniques.map((item) => item.techniqueId));

    const cursor = DetectionRule
      .find({
        isCurrent: true,
        "mitre.mapped": { $ne: true },
      })
      .select("_id ruleId revision title classtype protocol sourceFile parsedRule mitre")
      .lean()
      .cursor({ batchSize: 1000 });

    const stats = {
      mode: APPLY ? "apply" : "preview",
      curationVersion: CURATION_VERSION,
      scanned: 0,
      matchedRules: 0,
      appliedRules: 0,
      invalidTechniqueMappings: 0,
      uniqueTechniqueIds: [],
      byMappingRule: {},
      byMappingRuleSource: {},
      samples: {},
    };

    const techniqueIds = new Set();
    let operations = [];

    const flush = async () => {
      if (!APPLY || !operations.length) return;
      const result = await DetectionRule.bulkWrite(operations, { ordered: false });
      stats.appliedRules += Number(result.modifiedCount || 0);
      operations = [];
    };

    for await (const rule of cursor) {
      stats.scanned += 1;
      const result = deriveCuratedMitreMappings(rule);
      if (!result.mapped) continue;

      const validMappings = result.mappings.filter((mapping) => {
        const valid = activeIds.has(mapping.techniqueId);
        if (!valid) stats.invalidTechniqueMappings += 1;
        return valid;
      });
      if (!validMappings.length) continue;

      stats.matchedRules += 1;
      const validIds = [...new Set(validMappings.map((mapping) => mapping.techniqueId))];

      for (const mapping of validMappings) {
        techniqueIds.add(mapping.techniqueId);
        const key = mapping.mappingRuleId;
        stats.byMappingRule[key] = (stats.byMappingRule[key] || 0) + 1;
        if (!stats.byMappingRuleSource[key]) stats.byMappingRuleSource[key] = {};
        const sourceKey = rule.sourceFile || "unknown";
        stats.byMappingRuleSource[key][sourceKey] =
          (stats.byMappingRuleSource[key][sourceKey] || 0) + 1;
        if (!stats.samples[key]) stats.samples[key] = [];
        if (stats.samples[key].length < 5) {
          stats.samples[key].push({
            ruleId: rule.ruleId,
            revision: rule.revision,
            title: rule.title,
            sourceFile: rule.sourceFile,
            classtype: rule.classtype,
            protocol: rule.protocol,
            techniqueId: mapping.techniqueId,
            confidence: mapping.confidence,
            evidence: mapping.evidence,
          });
        }
      }

      if (APPLY) {
        operations.push({
          updateOne: {
            filter: {
              _id: rule._id,
              "mitre.mapped": { $ne: true },
            },
            update: {
              $set: {
                "mitre.mapped": true,
                "mitre.techniqueIds": validIds,
                "mitre.rawTechniqueIds": validIds,
                "mitre.legacyTechniqueIds": [],
                "mitre.replacements": [],
                "mitre.mappings": validMappings,
                "mitre.curationVersion": CURATION_VERSION,
                "mitre.lastCuratedAt": new Date(),
                "mitre.normalizationVersion": 1,
                "mitre.lastNormalizedAt": new Date(),
              },
            },
          },
        });

        if (operations.length >= 1000) await flush();
      }
    }
    await flush();

    if (APPLY && stats.appliedRules > 0) {
      await MitreCoverageSnapshot.deleteMany({});
    }

    stats.uniqueTechniqueIds = [...techniqueIds].sort();
    stats.byMappingRule = Object.fromEntries(
      Object.entries(stats.byMappingRule).sort((a, b) => b[1] - a[1]),
    );
    stats.byMappingRuleSource = Object.fromEntries(
      Object.entries(stats.byMappingRuleSource).map(([mappingRuleId, sources]) => [
        mappingRuleId,
        Object.fromEntries(Object.entries(sources).sort((a, b) => b[1] - a[1])),
      ]),
    );

    process.stdout.write(JSON.stringify(stats, null, 2) + "\n");
  } finally {
    await mongoose.disconnect();
  }
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});
