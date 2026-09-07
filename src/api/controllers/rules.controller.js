const fs = require('node:fs/promises');
const { DetectionRuleRepository } = require('../../repositories/DetectionRuleRepository');
const { mapSourceRule } = require('../../services/ruleParser');
const MitreCoverageSnapshot = require('../../models/MitreCoverageSnapshot');
const { successResponse, errorResponse } = require('../../utils/response');

class RuleController {
  constructor({ repository = new DetectionRuleRepository() } = {}) {
    this.repository = repository;
  }

  async importRules(req, res, next) {
    const tempFilePath = req.file?.path || null;

    try {
      if (!req.file) {
        return errorResponse(res, 'No file uploaded. Please provide a rules file.', 400);
      }

      const fileContent = await fs.readFile(tempFilePath, 'utf8');
      const records = parseRuleFile(fileContent);
      if (records.length === 0) {
        return errorResponse(res, 'No valid JSON rule records found in file', 400);
      }

      const requestedBatchSize = Number(req.query.batchSize || 1000);
      const batchSize = Math.min(Math.max(requestedBatchSize || 1000, 1), 5000);
      const stats = {
        processed: 0,
        invalid: 0,
        batches: 0,
        upserted: 0,
        modified: 0,
        errors: [],
      };

      let batch = [];
      const flush = async () => {
        if (batch.length === 0) return;
        const result = await this.repository.bulkUpsert(batch);
        stats.batches += 1;
        stats.upserted += Number(result?.upsertedCount || 0);
        stats.modified += Number(result?.modifiedCount || 0);
        batch = [];
      };

      for (const record of records) {
        try {
          batch.push(mapSourceRule(record));
          stats.processed += 1;
          if (batch.length >= batchSize) await flush();
        } catch (error) {
          stats.invalid += 1;
          if (stats.errors.length < 10) stats.errors.push(error.message);
        }
      }
      await flush();
      await MitreCoverageSnapshot.deleteMany({});

      return successResponse(res, {
        message: 'Detection rules imported successfully',
        fileName: req.file.originalname,
        fileSize: req.file.size,
        stats,
      });
    } catch (error) {
      return next(error);
    } finally {
      if (tempFilePath) await fs.unlink(tempFilePath).catch(() => {});
    }
  }

  async getRules(req, res, next) {
    try {
      const result = await this.repository.list({
        page: req.query.page,
        limit: req.query.limit,
        action: req.query.action,
        protocol: req.query.protocol,
        search: req.query.search || req.query.q,
      });
      return successResponse(res, result);
    } catch (error) {
      return next(error);
    }
  }

  async getRuleById(req, res, next) {
    try {
      const rules = await this.repository.findByRuleId(req.params.ruleId, req.query.revision);
      if (!rules.length) return errorResponse(res, 'Rule not found', 404);
      return successResponse(res, {
        rule: rules[0],
        revisions: rules,
      });
    } catch (error) {
      return next(error);
    }
  }

  async deleteRule(req, res, next) {
    try {
      const result = await this.repository.deleteByRuleId(req.params.ruleId, req.query.revision);
      if (!result?.deletedCount) return errorResponse(res, 'Rule not found', 404);
      await MitreCoverageSnapshot.deleteMany({});
      return successResponse(res, {
        message: 'Detection rule deleted successfully',
        ruleId: req.params.ruleId,
        deletedCount: result.deletedCount,
      });
    } catch (error) {
      return next(error);
    }
  }
}

function parseRuleFile(fileContent) {
  const text = String(fileContent || '').trim();
  if (!text) return [];

  try {
    const parsed = JSON.parse(text);
    return Array.isArray(parsed) ? parsed : [parsed];
  } catch (_) {
    return text
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => {
        try {
          return JSON.parse(line);
        } catch (_) {
          return null;
        }
      })
      .filter(Boolean);
  }
}

module.exports = new RuleController();
module.exports.RuleController = RuleController;
module.exports.parseRuleFile = parseRuleFile;
