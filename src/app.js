const express = require('express');
const path = require('node:path');
const cors = require('cors');
const mongoose = require('mongoose');
const rateLimit = require('express-rate-limit');
const pino = require('pino');
const pinoHttp = require('pino-http');
const { settings } = require('./core/config');
const { createAuthRouter } = require('./api/authRoutes');
const { createReportRouter } = require('./api/reportRoutes');
const { createRouter } = require('./api/routes');
const { requireAuth } = require('./api/middleware/requireAuth');
const { errorHandler, notFoundHandler } = require('./api/middleware/errorHandler');

const PANEL_DIST = path.join(__dirname, '../panel-ui/dist');
const PUBLIC_API_PATHS = new Set(['/health', '/webhook-alert']);
const MONGO_STATES = ['disconnected', 'connected', 'connecting', 'disconnecting'];

// Builds the Express app without binding a port, so tests and alternative entry points
// can reuse the exact production middleware stack with injected dependencies.
function createApp({ logger, routerDeps = {}, reportRouterDeps = {} } = {}) {
  const app = express();

  // Controllers log through req.log, so always install it; callers without a logger get a silent one.
  app.use(pinoHttp({ logger: logger || pino({ level: 'silent' }) }));
  app.use(cors());
  app.use(express.json({ limit: `${settings.maxPayloadSizeBytes}b` }));

  if (settings.enableRateLimiting) {
    app.use(rateLimit({ windowMs: 60 * 1000, limit: 60 }));
  }

  app.get('/health', (_req, res) => {
    const database = MONGO_STATES[mongoose.connection.readyState] || 'unknown';
    const healthy = database === 'connected';
    res.status(healthy ? 200 : 503).json({ status: healthy ? 'ok' : 'degraded', database });
  });

  app.use('/auth', createAuthRouter());

  // Serve the React shell publicly; the client router gates every workspace route behind sign-in.
  app.use('/panel', express.static(PANEL_DIST));
  app.get('/panel', (_req, res) => res.redirect('/panel/'));
  app.get('/panel/*', (req, res, next) => {
    if (path.extname(req.path)) return next();
    return res.sendFile(path.join(PANEL_DIST, 'index.html'));
  });
  app.get('/', (_req, res) => res.redirect('/panel/'));

  // Keep health and SIEM ingestion reachable without a panel session. All analyst-facing APIs require auth.
  app.use((req, res, next) => {
    if (PUBLIC_API_PATHS.has(req.path)) return next();
    return requireAuth(req, res, next);
  });

  app.use(createReportRouter(reportRouterDeps));
  app.use(createRouter(routerDeps));

  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}

module.exports = { createApp };
