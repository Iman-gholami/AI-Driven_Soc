const { MitreCoverageService } = require("../../services/mitreCoverageService");
const { successResponse, errorResponse } = require("../../utils/response");

class MitreController {
  constructor({ service = new MitreCoverageService() } = {}) {
    this.service = service;
  }

  getCoverage = async (req, res, next) => {
    try {
      const snapshot = await this.service.getSnapshot(req.query.tier);
      return successResponse(res, snapshot);
    } catch (error) {
      return next(error);
    }
  };

  rebuildCoverage = async (req, res, next) => {
    try {
      const enrich = req.body?.enrich === true || req.query.enrich === "true" || req.query.enrich === "1";
      const result = await this.service.rebuildAll({ enrich });
      return successResponse(res, result);
    } catch (error) {
      return next(error);
    }
  };

  getTechnique = async (req, res, next) => {
    try {
      const technique = await this.service.getTechnique(req.params.techniqueId);
      if (!technique) return errorResponse(res, "MITRE technique not found", 404);
      return successResponse(res, technique);
    } catch (error) {
      return next(error);
    }
  };

  getTechniqueRules = async (req, res, next) => {
    try {
      const technique = await this.service.getTechnique(req.params.techniqueId);
      if (!technique) return errorResponse(res, "MITRE technique not found", 404);
      const result = await this.service.getTechniqueRules(req.params.techniqueId, {
        tier: req.query.tier,
        page: req.query.page,
        limit: req.query.limit,
      });
      return successResponse(res, { technique, ...result });
    } catch (error) {
      return next(error);
    }
  };
}

module.exports = { MitreController };
