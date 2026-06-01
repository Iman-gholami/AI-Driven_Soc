const mongoose = require("mongoose");
const { settings } = require("../core/config");

let listenersRegistered = false;
let connectionPromise = null;

function registerConnectionLogging(logger) {
  if (listenersRegistered) return;

  mongoose.connection.on("connected", () => {
    logger.info("MongoDB connected");
  });

  mongoose.connection.on("disconnected", () => {
    logger.warn("MongoDB disconnected");
  });

  mongoose.connection.on("error", (error) => {
    logger.error({ err: error }, "MongoDB connection error");
  });

  listenersRegistered = true;
}

async function connectMongo(logger, options = {}) {
  const uri = options.uri !== undefined ? options.uri : settings.mongodbUri;
  const maxAttempts = options.maxAttempts || settings.mongodbMaxRetries;
  const retryDelayMs = options.retryDelayMs || settings.mongodbRetryDelayMs;

  registerConnectionLogging(logger);

  if (!uri) {
    logger.warn("MONGODB_URI is not configured; alert persistence is disabled");
    return false;
  }

  if (mongoose.connection.readyState === 1) return true;
  if (connectionPromise) return connectionPromise;

  connectionPromise = (async () => {
    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      try {
        await mongoose.connect(uri, {
          serverSelectionTimeoutMS: settings.mongodbServerSelectionTimeoutMs,
        });
        return true;
      } catch (error) {
        logger.error({ err: error, attempt, maxAttempts }, "MongoDB connection attempt failed");
        if (attempt < maxAttempts) {
          await new Promise((resolve) => setTimeout(resolve, retryDelayMs * attempt));
        }
      }
    }

    logger.error({ maxAttempts }, "MongoDB unavailable; continuing without alert persistence");
    return false;
  })().finally(() => {
    connectionPromise = null;
  });

  return connectionPromise;
}

async function disconnectMongo(logger) {
  try {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.disconnect();
    }
  } catch (error) {
    logger.error({ err: error }, "MongoDB disconnect failed");
  }
}

module.exports = { connectMongo, disconnectMongo };
