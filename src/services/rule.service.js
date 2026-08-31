const Rule = require('../models/rule.model');
const { mapSourceRule } = require('../utils/ruleParser');

class RuleService {
  /**
   * Bulk upsert rules
   */
  async bulkUpsert(rules) {
    if (!rules || rules.length === 0) {
      return { upsertedCount: 0, modifiedCount: 0 };
    }

    const operations = rules.map(rule => ({
      updateOne: {
        filter: { ruleId: rule.ruleId },
        update: { $set: rule },
        upsert: true
      }
    }));

    const result = await Rule.bulkWrite(operations);
    return {
      upsertedCount: result.upsertedCount || 0,
      modifiedCount: result.modifiedCount || 0,
      matchedCount: result.matchedCount || 0
    };
  }

  /**
   * Import rules from JSON data
   */
  async importRules(rulesData, batchSize = 1000) {
    const stats = {
      processed: 0,
      invalid: 0,
      batches: 0,
      upserted: 0,
      modified: 0,
      errors: []
    };

    let batch = [];

    const flush = async () => {
      if (batch.length === 0) return;
      try {
        const result = await this.bulkUpsert(batch);
        stats.batches += 1;
        stats.upserted += result.upsertedCount || 0;
        stats.modified += result.modifiedCount || 0;
      } catch (error) {
        stats.errors.push({
          batchSize: batch.length,
          error: error.message
        });
        console.error(`Batch flush error: ${error.message}`);
      }
      batch = [];
    };

    for (const line of rulesData) {
      const trimmed = String(line).trim();
      if (!trimmed) continue;

      try {
        const source = JSON.parse(trimmed);
        const mappedRule = mapSourceRule(source);
        batch.push(mappedRule);
        stats.processed += 1;

        if (batch.length >= batchSize) {
          await flush();
        }
      } catch (error) {
        stats.invalid += 1;
        stats.errors.push({
          line: trimmed.substring(0, 100) + (trimmed.length > 100 ? '...' : ''),
          error: error.message
        });
        // Keep last 10 errors only to avoid memory issues
        if (stats.errors.length > 10) {
          stats.errors = stats.errors.slice(-10);
        }
      }
    }

    await flush();
    return stats;
  }

  /**
   * Get all rules (for export)
   */
  async getAllRules() {
    return await Rule.find().sort({ createdAt: -1 });
  }

  /**
   * Get rules with pagination
   */
  async getRules(filters = {}, page = 1, limit = 50) {
    const skip = (page - 1) * limit;
    const query = {};

    if (filters.action) query.action = filters.action;
    if (filters.protocol) query.protocol = filters.protocol;
    if (filters.search) {
      query.$text = { $search: filters.search };
    }

    const [rules, total] = await Promise.all([
      Rule.find(query)
        .skip(skip)
        .limit(limit)
        .sort({ createdAt: -1 }),
      Rule.countDocuments(query)
    ]);

    return {
      rules,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    };
  }

  /**
   * Get rule by ID
   */
  async getRuleById(ruleId) {
    return await Rule.findOne({ ruleId });
  }

  /**
   * Delete rule by ID
   */
  async deleteRule(ruleId) {
    return await Rule.findOneAndDelete({ ruleId });
  }
}

module.exports = new RuleService();