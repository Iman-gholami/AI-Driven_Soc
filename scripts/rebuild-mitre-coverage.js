require("dotenv").config();

const { connectMongo, disconnectMongo } = require("../src/database/mongo");
const { createLogger } = require("../src/core/logging");
const { MitreCoverageService } = require("../src/services/mitreCoverageService");

const logger = createLogger(process.env.LOG_LEVEL || "info");

async function main() {
  const connected = await connectMongo(logger);
  if (!connected) throw new Error("MongoDB connection is required");

  const service = new MitreCoverageService();
  const result = await service.rebuildAll({ enrich: true });

  logger.info(
    {
      preparation: result.preparation,
      snapshots: result.snapshots.map((snapshot) => ({
        tier: snapshot.scopeTier,
        rules: snapshot.summary?.rules,
        techniques: snapshot.summary?.techniques,
      })),
    },
    "mitre_coverage_rebuilt",
  );
}

main()
  .catch((error) => {
    logger.error({ err: error }, "mitre_coverage_rebuild_failed");
    process.exitCode = 1;
  })
  .finally(async () => {
    await disconnectMongo(logger);
  });
