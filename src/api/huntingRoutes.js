const express = require("express");
const { ThreatHuntingService, HuntCancelledError } = require("../services/threatHuntingService");
const {
  DetectionEngineeringService,
  DetectionEngineeringInputError,
} = require("../services/detectionEngineeringService");
const {
  BehavioralHuntingService,
  BehavioralHuntingInputError,
} = require("../services/behavioralHuntingService");
const { successResponse } = require("../utils/response");

function createHuntingRouter({
  huntingService = new ThreatHuntingService(),
  detectionEngineeringService = new DetectionEngineeringService(),
  behavioralHuntingService = new BehavioralHuntingService(),
} = {}) {
  const router = express.Router();

  router.post("/hunting/stream", async (req, res) => {
    res.status(200);
    res.setHeader("Content-Type", "application/x-ndjson; charset=utf-8");
    res.setHeader("Cache-Control", "no-cache, no-transform");
    res.setHeader("X-Accel-Buffering", "no");
    res.flushHeaders?.();

    let disconnected = false;
    res.on("close", () => {
      if (!res.writableEnded) disconnected = true;
    });

    const writeEvent = async (event) => {
      if (disconnected || res.writableEnded) return;
      res.write(`${JSON.stringify(event)}\n`);
    };

    try {
      await huntingService.run({
        goal: req.body?.goal,
        maxSteps: req.body?.maxSteps,
        onEvent: writeEvent,
        shouldStop: () => disconnected,
      });
    } catch (error) {
      if (!(error instanceof HuntCancelledError)) {
        req.log?.error?.({ err: error }, "threat_hunt_failed");
        await writeEvent({
          type: "hunt_failed",
          error: String(error?.message || error || "Threat hunt failed").slice(0, 2000),
        });
      }
    } finally {
      if (!res.writableEnded) res.end();
    }
  });

  router.post("/hunting/detection-proposal", async (req, res) => {
    try {
      const data = await detectionEngineeringService.generateAndBacktest({
        goal: req.body?.goal,
        report: req.body?.report,
        days: req.body?.days,
      });
      return successResponse(res, data);
    } catch (error) {
      if (error instanceof DetectionEngineeringInputError) {
        return res.status(400).json({ detail: error.message });
      }
      req.log?.error?.({ err: error }, "detection_proposal_failed");
      return res.status(422).json({
        detail: "The detection proposal could not be generated or safely backtested",
      });
    }
  });

  router.get("/hunting/behavior/anomalies", async (req, res) => {
    try {
      const data = await behavioralHuntingService.scan({
        dimension: req.query.dimension,
        hours: req.query.hours,
        baselineDays: req.query.baselineDays,
        limit: req.query.limit,
      });
      return successResponse(res, data);
    } catch (error) {
      if (error instanceof BehavioralHuntingInputError) {
        return res.status(400).json({ detail: error.message });
      }
      req.log?.error?.({ err: error }, "behavioral_hunt_failed");
      return res.status(500).json({ detail: "Unable to calculate behavioral hunting signals" });
    }
  });

  return router;
}

module.exports = { createHuntingRouter };
