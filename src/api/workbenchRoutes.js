const express = require('express');
const { successResponse } = require('../utils/response');
const {
  WorkbenchAnalyticsService,
  WorkbenchInputError,
} = require('../services/workbenchAnalyticsService');

function createWorkbenchRouter({ service = new WorkbenchAnalyticsService() } = {}) {
  const router = express.Router();

  router.get('/workbench/ai-evaluation', async (req, res) => {
    try {
      return successResponse(res, await service.getAiEvaluation({ days: req.query.days }));
    } catch (error) {
      req.log?.error?.({ err: error }, 'workbench_ai_evaluation_failed');
      return res.status(500).json({ detail: 'Unable to load AI evaluation metrics' });
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
