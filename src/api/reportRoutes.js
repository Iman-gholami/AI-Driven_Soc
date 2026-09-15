const express = require("express");
const { successResponse } = require("../utils/response");
const HistoricalReport = require("../models/HistoricalReport");
const { ReportAnalyticsService } = require("../services/reportAnalyticsService");
const {
  ReportImportService,
  ReportImportInputError,
} = require("../services/reportImportService");
const {
  ReportCopilotService,
  ReportCopilotInputError,
} = require("../services/reportCopilotService");

function createReportRouter({
  model = HistoricalReport,
  analytics = new ReportAnalyticsService({ model }),
  importer = new ReportImportService({ model }),
  copilot = new ReportCopilotService({ model, analytics }),
} = {}) {
  const router = express.Router();

  router.get("/reports/years", async (req, res) => {
    try {
      return successResponse(res, await analytics.getYears());
    } catch (error) {
      req.log.error({ err: error }, "report_years_failed");
      return res.status(500).json({ detail: "Unable to load report years" });
    }
  });

  router.get("/reports/stats", async (req, res) => {
    try {
      if (!req.query.year) return res.status(400).json({ detail: "year is required" });
      return successResponse(res, await analytics.getStats(req.query.year));
    } catch (error) {
      if (error instanceof ReportImportInputError) {
        return res.status(400).json({ detail: error.message });
      }
      req.log.error({ err: error }, "report_stats_failed");
      return res.status(500).json({ detail: "Unable to load report statistics" });
    }
  });

  router.get("/reports", async (req, res) => {
    try {
      return successResponse(res, await analytics.list(req.query || {}));
    } catch (error) {
      if (error instanceof ReportImportInputError) {
        return res.status(400).json({ detail: error.message });
      }
      req.log.error({ err: error }, "report_list_failed");
      return res.status(500).json({ detail: "Unable to load historical reports" });
    }
  });

  router.get("/reports/import/scan", async (req, res) => {
    try {
      if (!req.query.year) return res.status(400).json({ detail: "year is required" });
      return successResponse(res, await importer.scanYear(req.query.year));
    } catch (error) {
      if (error instanceof ReportImportInputError) {
        return res.status(400).json({ detail: error.message });
      }
      req.log.error({ err: error }, "report_import_scan_failed");
      return res.status(500).json({ detail: "Unable to scan local report folder" });
    }
  });

  router.post("/reports/import", async (req, res) => {
    try {
      const data = await importer.importYear(req.body?.year, {
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
        "historical_reports_imported",
      );
      return successResponse(res, data);
    } catch (error) {
      if (error instanceof ReportImportInputError) {
        return res.status(400).json({ detail: error.message });
      }
      req.log.error({ err: error }, "report_import_failed");
      return res.status(500).json({ detail: "Unable to import local DOCX reports" });
    }
  });

  router.post("/reports/copilot/query", async (req, res) => {
    try {
      return successResponse(res, await copilot.query(req.body?.message));
    } catch (error) {
      if (error instanceof ReportCopilotInputError) {
        return res.status(400).json({ detail: error.message });
      }
      req.log.error({ err: error }, "report_copilot_failed");
      return res.status(500).json({ detail: "Unable to query historical report data" });
    }
  });

  router.get("/reports/:id", async (req, res) => {
    try {
      const report = await analytics.getById(req.params.id);
      if (!report) return res.status(404).json({ detail: "Report not found" });
      return successResponse(res, report);
    } catch (error) {
      req.log.error({ err: error, reportId: req.params.id }, "report_detail_failed");
      return res.status(500).json({ detail: "Unable to load report" });
    }
  });

  return router;
}

module.exports = { createReportRouter };
