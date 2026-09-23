const { InputError, NotFoundError } = require('../../core/errors');
const { successResponse } = require('../../utils/response');

class ReportController {
  constructor({ analytics, importer, uploadReview, copilot }) {
    this.analytics = analytics;
    this.importer = importer;
    this.uploadReview = uploadReview;
    this.copilot = copilot;
  }

  years = async (_req, res) => successResponse(res, await this.analytics.getYears());

  stats = async (req, res) => successResponse(res, await this.analytics.getStats(req.query || {}));

  facets = async (req, res) => successResponse(res, await this.analytics.getFacets(req.query || {}));

  entity = async (req, res) => {
    if (!req.query.value) throw new InputError('value is required');
    return successResponse(
      res,
      await this.analytics.getEntitySummary(req.params.type, req.query.value, req.query || {}),
    );
  };

  list = async (req, res) => successResponse(res, await this.analytics.list(req.query || {}));

  get = async (req, res) => {
    const report = await this.analytics.getById(req.params.id);
    if (!report) throw new NotFoundError('Report not found');
    return successResponse(res, report);
  };

  scanImport = async (req, res) => {
    if (!req.query.year) throw new InputError('year is required');
    return successResponse(res, await this.importer.scanYear(req.query.year));
  };

  importYear = async (req, res) => {
    const data = await this.importer.importYear(req.body?.year, {
      dryRun: req.body?.dryRun === true,
    });
    req.log.info(
      {
        year: data.year,
        imported: data.imported,
        updated: data.updated,
        skipped: data.skipped,
        failed: data.failed,
        dryRun: data.dryRun,
      },
      'historical_reports_imported',
    );
    return successResponse(res, data);
  };

  previewUpload = async (req, res) => {
    const data = await this.uploadReview.previewUpload(req.body?.year, req.files || []);
    req.log.info(
      { year: data.year, discovered: data.discovered, ready: data.ready, failed: data.failed },
      'historical_report_upload_previewed',
    );
    return successResponse(res, data);
  };

  commitUpload = async (req, res) => {
    const token = String(req.body?.sessionToken || '').trim();
    const data = await this.uploadReview.commitUpload(token, {
      selectedIds: req.body?.selectedIds,
    });
    req.log.info(
      {
        year: data.year,
        selected: data.selected,
        imported: data.imported,
        updated: data.updated,
        skipped: data.skipped,
        failed: data.failed,
      },
      'historical_report_upload_committed',
    );
    return successResponse(res, data);
  };

  cancelUpload = async (req, res) =>
    successResponse(res, await this.uploadReview.cancelUpload(req.params.sessionToken));

  copilotQuery = async (req, res) => successResponse(res, await this.copilot.query(req.body?.message));
}

module.exports = { ReportController };
