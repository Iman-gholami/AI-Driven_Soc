const express = require("express");
const multer = require("multer");
const os = require("node:os");
const path = require("node:path");
const { settings } = require("../core/config");
const { successResponse } = require("../utils/response");
const HistoricalReport = require("../models/HistoricalReport");
const { ReportAnalyticsService } = require("../services/reportAnalyticsService");
const {
  ReportImportService,
  ReportImportInputError,
} = require("../services/reportImportService");
const { ReportUploadReviewService } = require("../services/reportUploadReviewService");
const {
  ReportCopilotService,
  ReportCopilotInputError,
} = require("../services/reportCopilotService");

const incomingUpload = multer({
  dest: path.join(os.tmpdir(), "ai-driven-soc-report-incoming"),
  limits: {
    files: 100,
    fileSize: Number(settings.reportImportMaxFileBytes || 25 * 1024 * 1024),
  },
  fileFilter: (_req, file, callback) => {
    if (path.extname(String(file.originalname || "")).toLowerCase() !== ".docx") {
      return callback(new ReportImportInputError("Only .docx report files are supported"));
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
      return successResponse(res, await analytics.getStats(req.query || {}));
    } catch (error) {
      if (error instanceof ReportImportInputError) {
        return res.status(400).json({ detail: error.message });
      }
      req.log.error({ err: error }, "report_stats_failed");
      return res.status(500).json({ detail: "Unable to load report statistics" });
    }
  });

  router.get("/reports/facets", async (req, res) => {
    try {
      return successResponse(res, await analytics.getFacets(req.query || {}));
    } catch (error) {
      if (error instanceof ReportImportInputError) {
        return res.status(400).json({ detail: error.message });
      }
      req.log.error({ err: error }, "report_facets_failed");
      return res.status(500).json({ detail: "Unable to load report facets" });
    }
  });

  router.get("/reports/entities/:type", async (req, res) => {
    try {
      if (!req.query.value) return res.status(400).json({ detail: "value is required" });
      return successResponse(res, await analytics.getEntitySummary(req.params.type, req.query.value, req.query || {}));
    } catch (error) {
      if (/unsupported entity type|entity value is required/i.test(String(error?.message || ""))) {
        return res.status(400).json({ detail: error.message });
      }
      req.log.error({ err: error, entityType: req.params.type }, "report_entity_failed");
      return res.status(500).json({ detail: "Unable to load report entity intelligence" });
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

  router.post(
    "/reports/import/upload/preview",
    incomingUpload.array("reports", 100),
    async (req, res) => {
      try {
        const data = await uploadReview.previewUpload(req.body?.year, req.files || []);
        req.log.info(
          {
            year: data.year,
            discovered: data.discovered,
            ready: data.ready,
            failed: data.failed,
          },
          "historical_report_upload_previewed",
        );
        return successResponse(res, data);
      } catch (error) {
        await cleanupTempUploads(req.files);
        if (error instanceof ReportImportInputError) {
          return res.status(400).json({ detail: error.message });
        }
        req.log.error({ err: error }, "historical_report_upload_preview_failed");
        return res.status(500).json({ detail: "Unable to extract uploaded DOCX reports for review" });
      }
    },
  );

  router.post("/reports/import/upload/commit", async (req, res) => {
    try {
      const token = String(req.body?.sessionToken || "").trim();
      const data = await uploadReview.commitUpload(token, {
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
        "historical_report_upload_committed",
      );
      return successResponse(res, data);
    } catch (error) {
      if (error instanceof ReportImportInputError) {
        return res.status(400).json({ detail: error.message });
      }
      req.log.error({ err: error }, "historical_report_upload_commit_failed");
      return res.status(500).json({ detail: "Unable to save reviewed historical reports" });
    }
  });

  router.delete("/reports/import/upload/:sessionToken", async (req, res) => {
    try {
      return successResponse(res, await uploadReview.cancelUpload(req.params.sessionToken));
    } catch (error) {
      if (error instanceof ReportImportInputError) {
        return res.status(400).json({ detail: error.message });
      }
      req.log.error({ err: error }, "historical_report_upload_cancel_failed");
      return res.status(500).json({ detail: "Unable to cancel report upload preview" });
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

  router.use((error, req, res, next) => {
    if (error instanceof multer.MulterError) {
      cleanupTempUploads(req.files).catch(() => {});
      const status = error.code === "LIMIT_FILE_SIZE" ? 413 : 400;
      const detail = error.code === "LIMIT_FILE_SIZE"
        ? `Each DOCX must be smaller than ${Math.round(settings.reportImportMaxFileBytes / 1024 / 1024)} MB`
        : `Upload rejected: ${error.message}`;
      return res.status(status).json({ detail });
    }
    if (error instanceof ReportImportInputError) {
      cleanupTempUploads(req.files).catch(() => {});
      return res.status(400).json({ detail: error.message });
    }
    return next(error);
  });

  return router;
}

async function cleanupTempUploads(files) {
  const fs = require("node:fs/promises");
  await Promise.all((Array.isArray(files) ? files : [])
    .map((file) => file?.path)
    .filter(Boolean)
    .map((filePath) => fs.unlink(filePath).catch(() => {})));
}

module.exports = { createReportRouter };
