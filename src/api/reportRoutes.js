const express = require('express');
const multer = require('multer');
const os = require('node:os');
const path = require('node:path');
const { settings } = require('../core/config');
const HistoricalReport = require('../models/HistoricalReport');
const { ReportAnalyticsService } = require('../services/reportAnalyticsService');
const { ReportImportService, ReportImportInputError } = require('../services/reportImportService');
const { ReportUploadReviewService } = require('../services/reportUploadReviewService');
const { ReportCopilotService } = require('../services/reportCopilotService');
const { ReportController } = require('./controllers/reports.controller');
const { asyncHandler } = require('./middleware/asyncHandler');

const incomingUpload = multer({
  dest: path.join(os.tmpdir(), 'ai-driven-soc-report-incoming'),
  limits: {
    files: 100,
    fileSize: settings.reportImportMaxFileBytes,
  },
  fileFilter: (_req, file, callback) => {
    if (path.extname(String(file.originalname || '')).toLowerCase() !== '.docx') {
      return callback(new ReportImportInputError('Only .docx report files are supported'));
    }
    return callback(null, true);
  },
});

function createReportRouter({
  model = HistoricalReport,
  analytics = new ReportAnalyticsService({ model }),
  importer = new ReportImportService({ model }),
  uploadReview = new ReportUploadReviewService({ model }),
  copilot = new ReportCopilotService({ model, analytics }),
} = {}) {
  const router = express.Router();
  const reports = new ReportController({ analytics, importer, uploadReview, copilot });

  router.get('/reports/years', asyncHandler(reports.years));
  router.get('/reports/stats', asyncHandler(reports.stats));
  router.get('/reports/facets', asyncHandler(reports.facets));
  router.get('/reports/entities/:type', asyncHandler(reports.entity));
  router.get('/reports', asyncHandler(reports.list));
  router.get('/reports/import/scan', asyncHandler(reports.scanImport));
  router.post('/reports/import', asyncHandler(reports.importYear));
  router.post('/reports/import/upload/preview', incomingUpload.array('reports', 100), asyncHandler(reports.previewUpload));
  router.post('/reports/import/upload/commit', asyncHandler(reports.commitUpload));
  router.delete('/reports/import/upload/:sessionToken', asyncHandler(reports.cancelUpload));
  router.post('/reports/copilot/query', asyncHandler(reports.copilotQuery));
  router.get('/reports/:id', asyncHandler(reports.get));

  return router;
}

module.exports = { createReportRouter };
