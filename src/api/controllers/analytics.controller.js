const { successResponse } = require('../../utils/response');

function createAnalyticsController({ analystFeedbackService }) {
  return {
    aiAccuracy: async (req, res) =>
      successResponse(
        res,
        await analystFeedbackService.getReport({ from: req.query.from, to: req.query.to }),
      ),
  };
}

module.exports = { createAnalyticsController };
