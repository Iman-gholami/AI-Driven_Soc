const DetectionRule = require("../models/DetectionRule");
const { normalizeTitle } = require("../services/ruleParser");

class DetectionRuleRepository {
  constructor({ detectionRuleModel = DetectionRule } = {}) {
    this.detectionRuleModel = detectionRuleModel;
  }

  async bulkUpsert(rules) {
    if (!Array.isArray(rules) || rules.length === 0) {
      return { matchedCount: 0, modifiedCount: 0, upsertedCount: 0 };
    }

    const operations = rules.map((rule) => ({
      updateOne: {
        filter: { ruleId: rule.ruleId, revision: rule.revision },
        update: { $set: rule },
        upsert: true,
      },
    }));

    return this.detectionRuleModel.bulkWrite(operations, { ordered: false });
  }

  async findByRuleId(ruleId, revision) {
    const filter = { ruleId: String(ruleId) };
    if (revision !== undefined && revision !== null) filter.revision = Number(revision);
    return this.detectionRuleModel.find(filter).sort({ revision: -1 }).lean().exec();
  }

  async findByExactTitle(title) {
    return this.detectionRuleModel.find({ title: String(title || "").trim() }).lean().exec();
  }

  async findByNormalizedTitle(title) {
    return this.detectionRuleModel.find({ normalizedTitle: normalizeTitle(title) }).lean().exec();
  }
}

module.exports = { DetectionRuleRepository };
