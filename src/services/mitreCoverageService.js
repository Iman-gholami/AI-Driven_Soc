const DetectionRule = require("../models/DetectionRule");
const MitreTechnique = require("../models/MitreTechnique");
const MitreCoverageSnapshot = require("../models/MitreCoverageSnapshot");
const { parseRawRule } = require("./ruleParser");
const { extractMitreMapping } = require("./mitreMapping");

const TIERS = ["all", "native", "imported", "community"];
const TACTIC_ORDER = [
  "TA0043", "TA0042", "TA0001", "TA0002", "TA0003", "TA0004", "TA0005",
  "TA0006", "TA0007", "TA0008", "TA0009", "TA0011", "TA0010", "TA0040",
];

class MitreCoverageService {
  constructor({
    detectionRuleModel = DetectionRule,
    techniqueModel = MitreTechnique,
    snapshotModel = MitreCoverageSnapshot,
  } = {}) {
    this.detectionRuleModel = detectionRuleModel;
    this.techniqueModel = techniqueModel;
    this.snapshotModel = snapshotModel;
  }

  async prepareRules({ enrich = true } = {}) {
    const defaults = await Promise.all([
      this.detectionRuleModel.updateMany(
        { tier: { $exists: false } },
        { $set: { tier: "imported" } },
      ),
      this.detectionRuleModel.updateMany(
        { quarantined: { $exists: false } },
        { $set: { quarantined: false } },
      ),
    ]);

    const current = await this.refreshCurrentFlags();
    const enrichment = enrich ? await this.enrichStoredRules() : { scanned: 0, mapped: 0, modified: 0 };

    return {
      defaultsModified: defaults.reduce((sum, item) => sum + Number(item.modifiedCount || 0), 0),
      current,
      enrichment,
    };
  }

  async refreshCurrentFlags() {
    await this.detectionRuleModel.updateMany(
      { isCurrent: true },
      { $set: { isCurrent: false } },
    );

    const latest = await this.detectionRuleModel.aggregate([
      { $sort: { ruleId: 1, revision: -1, updatedAt: -1 } },
      { $group: { _id: "$ruleId", docId: { $first: "$_id" } } },
      { $project: { _id: 0, docId: 1 } },
    ]).allowDiskUse(true).exec();

    let modified = 0;
    for (let index = 0; index < latest.length; index += 1000) {
      const ids = latest.slice(index, index + 1000).map((item) => item.docId);
      if (!ids.length) continue;
      const result = await this.detectionRuleModel.updateMany(
        { _id: { $in: ids } },
        { $set: { isCurrent: true } },
      );
      modified += Number(result.modifiedCount || 0);
    }

    return { currentRules: latest.length, modified };
  }

  async enrichStoredRules() {
    const query = {
      $or: [
        { "mitre.mapped": { $exists: false } },
        { "mitre.techniqueIds": { $exists: false } },
        { "mitre.techniqueIds.0": { $exists: false } },
      ],
    };

    const cursor = this.detectionRuleModel
      .find(query)
      .select("_id rawRule parsedRule mitre")
      .lean()
      .cursor({ batchSize: 1000 });

    let scanned = 0;
    let mapped = 0;
    let modified = 0;
    let batch = [];

    const flush = async () => {
      if (!batch.length) return;
      const result = await this.detectionRuleModel.bulkWrite(batch, { ordered: false });
      modified += Number(result.modifiedCount || 0);
      batch = [];
    };

    for await (const rule of cursor) {
      scanned += 1;
      const parsedRule = rule.parsedRule && Object.keys(rule.parsedRule).length
        ? rule.parsedRule
        : parseRawRule(rule.rawRule || "");
      const mitre = extractMitreMapping({}, parsedRule);
      if (mitre.mapped) mapped += 1;

      batch.push({
        updateOne: {
          filter: { _id: rule._id },
          update: {
            $set: {
              mitre,
              parsedRule,
            },
          },
        },
      });

      if (batch.length >= 1000) await flush();
    }
    await flush();

    return { scanned, mapped, modified };
  }

  async rebuildAll({ enrich = false } = {}) {
    const preparation = await this.prepareRules({ enrich });
    const snapshots = [];
    for (const tier of TIERS) {
      snapshots.push(await this.rebuildTier(tier));
    }
    return { preparation, snapshots };
  }

  async rebuildTier(tier = "all") {
    const safeTier = normalizeTier(tier);
    const ruleFilter = { isCurrent: true };
    if (safeTier !== "all") ruleFilter.tier = safeTier;

    const [summaryRows, tierRows, techniqueRows, techniques] = await Promise.all([
      this.detectionRuleModel.aggregate([
        { $match: ruleFilter },
        {
          $group: {
            _id: null,
            total: { $sum: 1 },
            withMitre: {
              $sum: {
                $cond: [
                  { $gt: [{ $size: { $ifNull: ["$mitre.techniqueIds", []] } }, 0] },
                  1,
                  0,
                ],
              },
            },
            quarantined: { $sum: { $cond: ["$quarantined", 1, 0] } },
          },
        },
        { $project: { _id: 0, total: 1, withMitre: 1, quarantined: 1 } },
      ]).exec(),
      this.detectionRuleModel.aggregate([
        { $match: { isCurrent: true } },
        { $group: { _id: { $ifNull: ["$tier", "imported"] }, count: { $sum: 1 } } },
        { $project: { _id: 0, tier: "$_id", count: 1 } },
      ]).exec(),
      this.detectionRuleModel.aggregate([
        { $match: { ...ruleFilter, "mitre.techniqueIds.0": { $exists: true } } },
        { $unwind: "$mitre.techniqueIds" },
        { $group: { _id: "$mitre.techniqueIds", ruleCount: { $sum: 1 } } },
        { $project: { _id: 0, techniqueId: "$_id", ruleCount: 1 } },
      ]).exec(),
      this.techniqueModel
        .find({ revoked: { $ne: true }, deprecated: { $ne: true } })
        .select("techniqueId name tactics platforms isSubTechnique parentTechniqueId attackVersion")
        .lean()
        .exec(),
    ]);

    const ruleSummary = summaryRows[0] || { total: 0, withMitre: 0, quarantined: 0 };
    const ruleCounts = new Map(techniqueRows.map((item) => [item.techniqueId, Number(item.ruleCount || 0)]));
    const byTier = Object.fromEntries(["native", "imported", "community"].map((name) => [name, 0]));
    for (const row of tierRows) {
      if (row.tier in byTier) byTier[row.tier] = Number(row.count || 0);
    }

    const techniqueStats = techniques.map((technique) => ({
      techniqueId: technique.techniqueId,
      name: technique.name,
      isSubTechnique: Boolean(technique.isSubTechnique),
      parentTechniqueId: technique.parentTechniqueId || null,
      tactics: Array.isArray(technique.tactics) ? technique.tactics : [],
      platforms: Array.isArray(technique.platforms) ? technique.platforms : [],
      ruleCount: ruleCounts.get(technique.techniqueId) || 0,
    }));

    const covered = techniqueStats.filter((item) => item.ruleCount > 0).length;
    const tacticsById = new Map();

    for (const technique of techniqueStats) {
      for (const tactic of technique.tactics) {
        if (!tacticsById.has(tactic.id)) {
          tacticsById.set(tactic.id, {
            tacticId: tactic.id,
            name: tactic.name,
            shortName: tactic.shortName,
            techniques: [],
          });
        }
        tacticsById.get(tactic.id).techniques.push({
          techniqueId: technique.techniqueId,
          name: technique.name,
          isSubTechnique: technique.isSubTechnique,
          parentTechniqueId: technique.parentTechniqueId,
          ruleCount: technique.ruleCount,
        });
      }
    }

    const tactics = [...tacticsById.values()]
      .sort((a, b) => tacticRank(a.tacticId) - tacticRank(b.tacticId))
      .map((tactic) => {
        const sorted = tactic.techniques.sort((a, b) => (
          b.ruleCount - a.ruleCount || a.techniqueId.localeCompare(b.techniqueId)
        ));
        const coveredTechniques = sorted.filter((item) => item.ruleCount > 0).length;
        return {
          ...tactic,
          totalTechniques: sorted.length,
          coveredTechniques,
          coveragePercent: percent(coveredTechniques, sorted.length),
          techniques: sorted,
        };
      });

    const attackVersion = mostCommon(
      techniques.map((item) => item.attackVersion).filter(Boolean),
    );

    const summary = {
      rules: {
        total: Number(ruleSummary.total || 0),
        withMitre: Number(ruleSummary.withMitre || 0),
        unmapped: Math.max(Number(ruleSummary.total || 0) - Number(ruleSummary.withMitre || 0), 0),
        quarantined: Number(ruleSummary.quarantined || 0),
        mappingCoveragePercent: percent(Number(ruleSummary.withMitre || 0), Number(ruleSummary.total || 0)),
        byTier,
      },
      techniques: {
        total: techniqueStats.length,
        covered,
        uncovered: Math.max(techniqueStats.length - covered, 0),
        coveragePercent: percent(covered, techniqueStats.length),
      },
    };

    const generatedAt = new Date();
    const snapshot = await this.snapshotModel.findOneAndUpdate(
      { scopeTier: safeTier },
      {
        $set: {
          scopeTier: safeTier,
          generatedAt,
          attackVersion,
          summary,
          tactics,
          techniqueStats,
        },
      },
      { upsert: true, new: true, setDefaultsOnInsert: true },
    ).lean().exec();

    return snapshot;
  }

  async getSnapshot(tier = "all") {
    const safeTier = normalizeTier(tier);
    const snapshot = await this.snapshotModel.findOne({ scopeTier: safeTier }).lean().exec();
    if (snapshot) return snapshot;
    return this.rebuildTier(safeTier);
  }

  async getTechnique(techniqueId) {
    return this.techniqueModel.findOne({
      techniqueId: String(techniqueId || "").toUpperCase(),
      revoked: { $ne: true },
      deprecated: { $ne: true },
    }).lean().exec();
  }

  async getTechniqueRules(techniqueId, { tier = "all", page = 1, limit = 50 } = {}) {
    const safeTier = normalizeTier(tier);
    const safePage = Math.max(Number(page) || 1, 1);
    const safeLimit = Math.min(Math.max(Number(limit) || 50, 1), 100);
    const filter = {
      isCurrent: true,
      "mitre.techniqueIds": String(techniqueId || "").toUpperCase(),
    };
    if (safeTier !== "all") filter.tier = safeTier;

    const [rules, total] = await Promise.all([
      this.detectionRuleModel
        .find(filter)
        .sort({ ruleId: 1 })
        .skip((safePage - 1) * safeLimit)
        .limit(safeLimit)
        .select("ruleId revision title protocol classtype sourceFile tier quarantined mitre")
        .lean()
        .exec(),
      this.detectionRuleModel.countDocuments(filter),
    ]);

    return {
      rules,
      pagination: {
        page: safePage,
        limit: safeLimit,
        total,
        pages: Math.ceil(total / safeLimit),
      },
    };
  }
}

function normalizeTier(tier) {
  const value = String(tier || "all").toLowerCase();
  return TIERS.includes(value) ? value : "all";
}

function percent(part, total) {
  if (!total) return 0;
  return Math.round((Number(part || 0) / Number(total)) * 1000) / 10;
}

function tacticRank(tacticId) {
  const index = TACTIC_ORDER.indexOf(tacticId);
  return index === -1 ? 999 : index;
}

function mostCommon(values) {
  if (!values.length) return null;
  const counts = new Map();
  for (const value of values) counts.set(value, (counts.get(value) || 0) + 1);
  return [...counts.entries()].sort((a, b) => b[1] - a[1])[0][0];
}

module.exports = { MitreCoverageService, normalizeTier, TACTIC_ORDER };
