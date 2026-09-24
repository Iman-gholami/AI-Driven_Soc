const { AnalystFeedbackRepository } = require('../repositories/AnalystFeedbackRepository');
const { parseFeedbackWindow, createFeedbackAccumulator } = require('../investigation/feedbackMetrics');

// Analyst Feedback report (served at /analytics/ai-accuracy). Read-only; never calls the LLM.
class AnalystFeedbackService {
  constructor({ repository = new AnalystFeedbackRepository(), now = () => new Date() } = {}) {
    this.repository = repository;
    this.now = now;
  }

  async getReport(query = {}) {
    const window = parseFeedbackWindow(query, this.now());
    const accumulator = createFeedbackAccumulator(window);

    for await (const row of this.repository.reviewRows(window)) accumulator.addReview(row);
    for await (const row of this.repository.dispositionRows(window)) accumulator.addDisposition(row);
    for await (const row of this.repository.coverageRows(window)) accumulator.addCoverage(row);

    return accumulator.finish();
  }
}

module.exports = { AnalystFeedbackService };
