const { successResponse } = require('../../utils/response');

function createAlertMemoryController({ alertMemoryService }) {
  return {
    history: async (req, res) => {
      const data = await alertMemoryService.getHistory(req.params.id, { limit: req.query.limit });
      req.log.info(
        { alertId: req.params.id, matches: data.summary.count },
        'alert_memory_loaded',
      );
      return successResponse(res, data);
    },

    saveOutcome: async (req, res) => {
      const data = await alertMemoryService.saveOutcome(req.params.id, req.body || {}, {
        user: req.user,
      });
      req.log.info(
        { alertId: req.params.id, outcome: data.outcome, actor: data.resolvedBy?.id || null },
        'alert_outcome_saved',
      );
      return successResponse(res, data, 'Analyst outcome saved');
    },
  };
}

module.exports = { createAlertMemoryController };
