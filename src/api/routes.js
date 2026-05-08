const express = require("express");
const crypto = require("crypto");
const { settings } = require("../core/config");
const { IncidentAnalyzer } = require("../services/analyzer");

const router = express.Router();
const analyzer = new IncidentAnalyzer();

router.get("/health", (_, res) => {
  res.json({ status: "ok" });
});

router.post("/analyze-incident", async (req, res) => {
  const requestId = crypto.randomUUID();
  const payloadLength = Number(req.headers["content-length"] || 0);

  if (payloadLength > settings.maxPayloadSizeBytes) {
    return res.status(413).json({ detail: "Payload too large" });
  }

  req.log.info({ requestId, keys: Object.keys(req.body || {}).slice(0, 30) }, "incident_received");

  try {
    const response = await analyzer.analyzeIncident(req.body || {});
    req.log.info({ requestId }, "incident_analyzed");
    return res.json(response);
  } catch (error) {
    if (error?.name === "ZodError") {
      req.log.warn({ requestId, error: error.message }, "invalid_llm_output");
      return res.status(502).json({ detail: "Invalid model output" });
    }

    req.log.error({ requestId, err: error }, "analysis_failed");
    return res.status(500).json({ detail: "Internal error during analysis" });
  }
});

module.exports = { router };
