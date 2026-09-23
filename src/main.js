require('dotenv').config();
const { settings, assertValidConfig } = require('./core/config');
const { createLogger } = require('./core/logging');
const { connectMongo, disconnectMongo } = require('./database/mongo');
const { createApp } = require('./app');

const logger = createLogger(settings.logLevel);

try {
  assertValidConfig();
} catch (error) {
  logger.fatal(error.message);
  process.exit(1);
}

const app = createApp({ logger });

connectMongo(logger).catch((error) => {
  logger.error({ err: error }, 'MongoDB initialization failed; /health will report degraded');
});

const server = app.listen(settings.port, '0.0.0.0', () => {
  logger.info({ port: settings.port }, 'API started');
});

let shuttingDown = false;

async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  logger.info({ signal }, 'API shutting down');

  // Force exit if open connections keep the server from closing in time.
  const forceExit = setTimeout(() => {
    logger.warn({ timeoutMs: settings.shutdownTimeoutMs }, 'Shutdown timed out; forcing exit');
    process.exit(1);
  }, settings.shutdownTimeoutMs);
  forceExit.unref();

  await new Promise((resolve) => server.close(resolve));
  await disconnectMongo(logger);
  process.exit(0);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
