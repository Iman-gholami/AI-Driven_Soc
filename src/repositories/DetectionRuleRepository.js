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

  async list({ action, protocol, search, page = 1, limit = 50 } = {}) {
    const safePage = Math.max(Number(page) || 1, 1);
    const safeLimit = Math.min(Math.max(Number(limit) || 50, 1), 100);
    const filter = {};

    if (action) filter.action = String(action).toLowerCase();
    if (protocol) filter.protocol = String(protocol).toLowerCase();
    if (search) {
      const expression = new RegExp(escapeRegex(String(search).trim()), "i");
      filter.$or = [
        { ruleId: expression },
        { title: expression },
        { normalizedTitle: expression },
        { classtype: expression },
      ];
    }

    const [rules, total] = await Promise.all([
      this.detectionRuleModel
        .find(filter)
        .sort({ updatedAt: -1, revision: -1 })
        .skip((safePage - 1) * safeLimit)
        .limit(safeLimit)
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

  async findByRuleId(ruleId, revision) {
    const filter = { ruleId: String(ruleId) };
    if (revision !== undefined && revision !== null) filter.revision = Number(revision);
    return this.detectionRuleModel.find(filter).sort({ revision: -1 }).lean().exec();
  }

  async deleteByRuleId(ruleId, revision) {
    const filter = { ruleId: String(ruleId) };
    if (revision !== undefined && revision !== null) filter.revision = Number(revision);
    return this.detectionRuleModel.deleteMany(filter);
  }

  async findByExactTitle(title) {
    return this.detectionRuleModel.find({ title: String(title || "").trim() }).lean().exec();
  }

  async findByNormalizedTitle(title) {
    return this.detectionRuleModel.find({ normalizedTitle: normalizeTitle(title) }).lean().exec();
  }
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

module.exports = { DetectionRuleRepository };
