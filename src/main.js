require("dotenv").config();
const express = require("express");
const path = require("node:path");
const rateLimit = require("express-rate-limit");
const pinoHttp = require("pino-http");
var cors = require('cors');
const { settings } = require("./core/config");
const { createLogger } = require("./core/logging");
const { createAuthRouter } = require("./api/authRoutes");
const { createReportRouter } = require("./api/reportRoutes");
const { createRouter } = require("./api/routes");
const { requireAuth } = require("./middleware/requireAuth");
const { UnifiedCopilotService } = require("./services/unifiedCopilotService");
const { connectMongo, disconnectMongo } = require("./database/mongo");

const logger = createLogger(settings.logLevel);
const app = express();
const router = createRouter({ copilot: new UnifiedCopilotService() });

app.use(cors());
app.use('/uploads', express.static(path.join(__dirname, '../uploads')));
app.use(express.json({ limit: `${settings.maxPayloadSizeBytes}b` }));
app.use(pinoHttp({ logger }));

if (settings.enableRateLimiting) {
  app.use(rateLimit({ windowMs: 60 * 1000, limit: 60 }));
}

app.use("/auth", createAuthRouter());

// Serve the React shell publicly; the client router gates every workspace route behind sign-in.
app.use("/panel", express.static(path.join(__dirname, "../panel-ui/dist")));
app.get("/panel", (_req, res) => res.redirect("/panel/"));
app.get("/panel/*", (req, res, next) => {
  if (path.extname(req.path)) return next();
  return res.sendFile(path.join(__dirname, "../panel-ui/dist/index.html"));
});
app.get("/", (_req, res) => res.redirect("/panel/"));

// Keep health and SIEM ingestion reachable without a panel session. All analyst-facing APIs require auth.
app.use((req, res, next) => {
  if (req.path === "/health" || req.path === "/webhook-alert") return next();
  return requireAuth(req, res, next);
});

app.use(createReportRouter());
app.use(router);

connectMongo(logger).catch((error) => {
  logger.error({ err: error }, "MongoDB initialization failed; continuing without alert persistence");
});

const server = app.listen(settings.port, "0.0.0.0", () => {
  logger.info({ port: settings.port }, "API started");
});

async function shutdown(signal) {
  logger.info({ signal }, "API shutting down");
  await disconnectMongo(logger);
  server.close(() => process.exit(0));
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
