const { successResponse } = require('../../utils/response');

function createAlertMemoryController({ alertMemoryService }) {
  return {
    history: async (req, res) => {
      const data = await alertMemoryService.getHistory(req.params.id, { limit: req.query.limit });
      req.log.info(
        { alertId: req.params.id, matches: data.summary.count, status: data.current.status },
        'alert_memory_loaded',
      );
      return successResponse(res, data);
    },

    saveInvestigation: async (req, res) => {
      const data = await alertMemoryService.saveInvestigation(req.params.id, req.body || {}, {
        user: req.user,
      });
      req.log.info(
        { alertId: req.params.id, status: data.status, actor: data.analystCase?.updatedBy?.id || null },
        'alert_investigation_saved',
      );
      return successResponse(res, data, 'Investigation progress saved');
    },

    closeAlert: async (req, res) => {
      const data = await alertMemoryService.closeAlert(req.params.id, req.body || {}, {
        user: req.user,
      });
      req.log.info(
        {
          alertId: req.params.id,
          outcome: data.analystCase?.finalOutcome || null,
          actor: data.analystCase?.closedBy?.id || null,
        },
        'alert_closed',
      );
      return successResponse(res, data, 'Alert closed');
    },
  };
}

module.exports = { createAlertMemoryController };
