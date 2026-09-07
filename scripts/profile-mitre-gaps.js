require("dotenv").config();

const mongoose = require("mongoose");
const { settings } = require("../src/core/config");
const DetectionRule = require("../src/models/DetectionRule");
const MitreTechnique = require("../src/models/MitreTechnique");
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
        .select("techniqueId name tactics")
        .lean()
        .exec(),
      DetectionRule.distinct("mitre.techniqueIds", {
        isCurrent: true,
        "mitre.techniqueIds.0": { $exists: true },
      }),
    ]);

    const covered = new Set(coveredTechniqueIds);
    const techniqueById = new Map(activeTechniques.map((item) => [item.techniqueId, item]));
    const uncovered = new Set(
      activeTechniques
        .map((item) => item.techniqueId)
        .filter((techniqueId) => !covered.has(techniqueId)),
    );

    const cursor = DetectionRule
      .find({
        isCurrent: true,
        "mitre.mapped": { $ne: true },
      })
      .select("_id ruleId revision title classtype protocol sourceFile parsedRule")
      .lean()
      .cursor({ batchSize: 1000 });

    const stats = {
      mode: "preview",
      gapSignalVersion: GAP_SIGNAL_VERSION,
      scannedUnmappedRules: 0,
      candidateRules: 0,
      candidateTechniqueAssignments: 0,
      candidateNewTechniques: [],
      bySignal: {},
      byTechnique: {},
      bySourceFile: {},
      samples: {},
    };

    const candidateTechniqueIds = new Set();
    const candidateRuleIds = new Set();

    for await (const rule of cursor) {
      stats.scannedUnmappedRules += 1;
      const signals = findGapSignals(rule, uncovered);
      if (!signals.length) continue;

      candidateRuleIds.add(String(rule._id));

      for (const signal of signals) {
        stats.candidateTechniqueAssignments += 1;
        candidateTechniqueIds.add(signal.techniqueId);

        stats.bySignal[signal.signalId] = (stats.bySignal[signal.signalId] || 0) + 1;
        stats.byTechnique[signal.techniqueId] = (stats.byTechnique[signal.techniqueId] || 0) + 1;

        const sourceFile = rule.sourceFile || "unknown";
        stats.bySourceFile[sourceFile] = (stats.bySourceFile[sourceFile] || 0) + 1;

        if (!stats.samples[signal.signalId]) stats.samples[signal.signalId] = [];
        if (stats.samples[signal.signalId].length < 8) {
          const technique = techniqueById.get(signal.techniqueId);
          stats.samples[signal.signalId].push({
            ruleId: rule.ruleId,
            revision: rule.revision,
            title: rule.title,
            sourceFile: rule.sourceFile,
            classtype: rule.classtype,
            protocol: rule.protocol,
            techniqueId: signal.techniqueId,
            techniqueName: technique?.name,
            confidence: signal.confidence,
            evidence: signal.evidence,
          });
        }
      }
    }

    stats.candidateRules = candidateRuleIds.size;
    stats.candidateNewTechniques = [...candidateTechniqueIds]
      .sort()
      .map((techniqueId) => ({
        techniqueId,
        name: techniqueById.get(techniqueId)?.name || null,
        candidateRules: stats.byTechnique[techniqueId] || 0,
      }));

    stats.bySignal = sortObject(stats.bySignal);
    stats.byTechnique = sortObject(stats.byTechnique);
    stats.bySourceFile = sortObject(stats.bySourceFile);

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
