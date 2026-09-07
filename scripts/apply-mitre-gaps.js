require("dotenv").config();

const mongoose = require("mongoose");
const { settings } = require("../src/core/config");
const DetectionRule = require("../src/models/DetectionRule");
const MitreTechnique = require("../src/models/MitreTechnique");
const MitreCoverageSnapshot = require("../src/models/MitreCoverageSnapshot");
const {
  GAP_SIGNAL_VERSION,
  findGapSignals,
} = require("../src/services/mitreGapSignals");

async function main() {
  if (!settings.mongodbUri) throw new Error("MONGODB_URI is required");

  await mongoose.connect(settings.mongodbUri, {
    serverSelectionTimeoutMS: settings.mongodbServerSelectionTimeoutMs,
  });

  try {
    const [activeTechniques, coveredTechniqueIds] = await Promise.all([
      MitreTechnique
        .find({ revoked: { $ne: true }, deprecated: { $ne: true } })
        .select("techniqueId name")
        .lean()
        .exec(),
      DetectionRule.distinct("mitre.techniqueIds", {
        isCurrent: true,
        "mitre.techniqueIds.0": { $exists: true },
      }),
    ]);

    if (!activeTechniques.length) {
      throw new Error("Active MITRE ATT&CK catalog is empty. Run npm run import:mitre first.");
    }

    const activeIds = new Set(activeTechniques.map((item) => item.techniqueId));
    const covered = new Set(coveredTechniqueIds);
    const uncovered = new Set(
      [...activeIds].filter((techniqueId) => !covered.has(techniqueId)),
    );

    const cursor = DetectionRule
      .find({
        isCurrent: true,
        "mitre.mapped": { $ne: true },
      })
      .select("_id ruleId revision title classtype protocol sourceFile parsedRule mitre")
      .lean()
      .cursor({ batchSize: 1000 });

    const stats = {
      mode: "apply",
      gapSignalVersion: GAP_SIGNAL_VERSION,
      scannedUnmappedRules: 0,
      matchedRules: 0,
      matchedTechniqueAssignments: 0,
      appliedRules: 0,
      invalidTechniqueMappings: 0,
      appliedNewTechniques: [],
      bySignal: {},
      byTechnique: {},
      bySourceFile: {},
      samples: {},
    };

    const matchedRuleIds = new Set();
    const matchedTechniqueIds = new Set();
    let operations = [];

    const flush = async () => {
      if (!operations.length) return;
      const result = await DetectionRule.bulkWrite(operations, { ordered: false });
      stats.appliedRules += Number(result.modifiedCount || 0);
      operations = [];
    };

    for await (const rule of cursor) {
      stats.scannedUnmappedRules += 1;
      const signals = findGapSignals(rule, uncovered);
      if (!signals.length) continue;

      const validSignals = signals.filter((signal) => {
        if (activeIds.has(signal.techniqueId)) return true;
        stats.invalidTechniqueMappings += 1;
        return false;
      });
      if (!validSignals.length) continue;

      matchedRuleIds.add(String(rule._id));
      const now = new Date();
      const techniqueIds = [...new Set(validSignals.map((signal) => signal.techniqueId))];

      const mappings = validSignals.map((signal) => ({
        techniqueId: signal.techniqueId,
        source: "curated-gap",
        mappingRuleId: signal.signalId,
        confidence: signal.confidence,
        reviewed: false,
        evidence: signal.evidence,
      }));

      for (const signal of validSignals) {
        stats.matchedTechniqueAssignments += 1;
        matchedTechniqueIds.add(signal.techniqueId);
        stats.bySignal[signal.signalId] = (stats.bySignal[signal.signalId] || 0) + 1;
        stats.byTechnique[signal.techniqueId] = (stats.byTechnique[signal.techniqueId] || 0) + 1;

        const sourceFile = rule.sourceFile || "unknown";
        stats.bySourceFile[sourceFile] = (stats.bySourceFile[sourceFile] || 0) + 1;

        if (!stats.samples[signal.signalId]) stats.samples[signal.signalId] = [];
        if (stats.samples[signal.signalId].length < 5) {
          stats.samples[signal.signalId].push({
            ruleId: rule.ruleId,
            revision: rule.revision,
            title: rule.title,
            sourceFile: rule.sourceFile,
            classtype: rule.classtype,
            protocol: rule.protocol,
            techniqueId: signal.techniqueId,
            confidence: signal.confidence,
            evidence: signal.evidence,
          });
        }
      }

      operations.push({
        updateOne: {
          filter: {
            _id: rule._id,
            isCurrent: true,
            "mitre.mapped": { $ne: true },
          },
          update: {
            $set: {
              "mitre.mapped": true,
              "mitre.techniqueIds": techniqueIds,
              "mitre.rawTechniqueIds": techniqueIds,
              "mitre.legacyTechniqueIds": [],
              "mitre.replacements": [],
              "mitre.mappings": mappings,
              "mitre.normalizationVersion": 1,
              "mitre.lastNormalizedAt": now,
              "mitre.gapSignalVersion": GAP_SIGNAL_VERSION,
              "mitre.lastGapCuratedAt": now,
            },
          },
        },
      });

      if (operations.length >= 1000) await flush();
    }

    await flush();

    stats.matchedRules = matchedRuleIds.size;
    stats.appliedNewTechniques = [...matchedTechniqueIds].sort();
    stats.bySignal = sortObject(stats.bySignal);
    stats.byTechnique = sortObject(stats.byTechnique);
    stats.bySourceFile = sortObject(stats.bySourceFile);

    if (stats.appliedRules > 0) {
      await MitreCoverageSnapshot.deleteMany({});
    }

    process.stdout.write(JSON.stringify(stats, null, 2) + "\n");
  } finally {
    await mongoose.disconnect();
  }
}

function sortObject(value) {
  return Object.fromEntries(
    Object.entries(value).sort((a, b) => Number(b[1]) - Number(a[1]) || a[0].localeCompare(b[0])),
  );
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});
