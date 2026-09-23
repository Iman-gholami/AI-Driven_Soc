const crypto = require('node:crypto');
const { InputError } = require('../../core/errors');
const { successResponse } = require('../../utils/response');

class CopilotController {
  constructor({ copilot }) {
    this.copilot = copilot;
  }

  describeSchema = async (req, res) => {
    try {
      return successResponse(res, await this.copilot.describeSchema(req.query.dataset || undefined));
    } catch (error) {
      throw new InputError('Unknown or unavailable SOC dataset', { cause: error });
    }
  };

  listTools = async (_req, res) => successResponse(res, await this.copilot.listTools());

  query = async (req, res) => {
    const requestId = crypto.randomUUID();
    const data = await this.copilot.query(req.body?.message, {
      history: req.body?.history,
      state: req.body?.state,
    });
    req.log.info(
      {
        requestId,
        supported: data.supported,
        tool: data.tool,
        dataset: data.queryPlan?.dataset || null,
        operation: data.queryPlan?.operation || null,
        batchSize: Array.isArray(data.queryPlan?.queries) ? data.queryPlan.queries.length : 0,
      },
      'copilot_query_completed',
    );
    return successResponse(res, data);
  };
}

module.exports = { CopilotController };
