const express = require('express');
const { successResponse } = require('../utils/response');
const {
  WorkbenchAnalyticsService,
  WorkbenchInputError,
} = require('../services/workbenchAnalyticsService');
const { SocEntityContextService } = require('../services/socEntityContextService');

function createWorkbenchRouter({
  service = new WorkbenchAnalyticsService(),
  entityContextService = new SocEntityContextService(),
} = {}) {
  const router = express.Router();

  router.get('/workbench/ai-evaluation', async (req, res) => {
    try {
      return successResponse(res, await service.getAiEvaluation({ days: req.query.days }));
    } catch (error) {
      req.log?.error?.({ err: error }, 'workbench_ai_evaluation_failed');
      return res.status(500).json({ detail: 'Unable to load AI evaluation metrics' });
    }
  });

  router.get('/workbench/entities/:entityType/:id/context', async (req, res) => {
    try {
      const data = await entityContextService.getContext({
        entityType: req.params.entityType,
        id: req.params.id,
      });
      return successResponse(res, data);
    } catch (error) {
      if (/not found/i.test(String(error?.message || ''))) {
        return res.status(404).json({ detail: 'SOC entity not found' });
      }
      if (/unsupported|required/i.test(String(error?.message || ''))) {
        return res.status(400).json({ detail: String(error.message) });
      }
      req.log?.error?.({ err: error }, 'workbench_entity_context_failed');
      return res.status(500).json({ detail: 'Unable to load SOC entity context' });
    }
  });

  router.get('/workbench/rules/:ruleId/insights', async (req, res) => {
    try {
      const data = await service.getRuleInsights(req.params.ruleId, { days: req.query.days });
      if (!data) return res.status(404).json({ detail: 'Detection rule not found' });
      return successResponse(res, data);
    } catch (error) {
      if (error instanceof WorkbenchInputError) {
        return res.status(400).json({ detail: error.message });
      }
      req.log?.error?.({ err: error, ruleId: req.params.ruleId }, 'workbench_rule_insights_failed');
      return res.status(500).json({ detail: 'Unable to load detection rule insights' });
    }
  });

  return router;
}

module.exports = { createWorkbenchRouter };
