const { successResponse } = require('../../utils/response');

// Factory-style controller: every dependency is injected, so tests can drive it over HTTP with fakes.
function createInvestigationController({ investigationService }) {
  function write(method) {
    return async (req, res) => {
      const result = await investigationService[method](req.params.id, req.body, {
        idempotencyKey: req.get('Idempotency-Key'),
        user: req.user,
      });
      req.log.info(
        {
          alertId: req.params.id,
          type: result.event.type,
          sequence: result.event.sequence,
          replayed: result.replayed,
          actor: result.event.actor?.id,
        },
        'investigation_event_recorded',
      );
      if (result.replayed) res.set('Idempotent-Replayed', 'true');
      return successResponse(
        res,
        result,
        result.replayed ? 'Replayed existing event' : 'Created',
        result.replayed ? 200 : 201,
      );
    };
  }

  return {
    listReasons: async (_req, res) => successResponse(res, investigationService.listReasons()),

    getInvestigation: async (req, res) =>
      successResponse(
        res,
        await investigationService.getInvestigation(req.params.id, {
          limit: req.query.limit,
          before: req.query.before,
        }),
      ),

    recordReview: write('recordReview'),
    recordDisposition: write('recordDisposition'),
    recordNote: write('recordNote'),
    reopen: write('reopen'),
  };
}

module.exports = { createInvestigationController };
