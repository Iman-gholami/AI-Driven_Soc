require("dotenv").config();
const express = require("express");
const rateLimit = require("express-rate-limit");
const pinoHttp = require("pino-http");
const { settings } = require("./core/config");
const { createLogger } = require("./core/logging");
const { router } = require("./api/routes");

const logger = createLogger(settings.logLevel);
const app = express();

app.use(express.json({ limit: `${settings.maxPayloadSizeBytes}b` }));
app.use(pinoHttp({ logger }));

if (settings.enableRateLimiting) {
  app.use(rateLimit({ windowMs: 60 * 1000, limit: 60 }));
}

app.use(router);

app.listen(settings.port, "0.0.0.0", () => {
  logger.info({ port: settings.port }, "API started");
});
