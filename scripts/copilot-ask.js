require("dotenv").config();

const { settings } = require("../src/core/config");
const { createLogger } = require("../src/core/logging");
const { connectMongo, disconnectMongo } = require("../src/database/mongo");
const { CopilotService } = require("../src/services/copilotService");

const logger = createLogger(settings.logLevel);

async function main() {
  const question = process.argv.slice(2).join(" ").trim();
  if (!question) {
    throw new Error('Usage: npm run copilot:ask -- "your SOC question"');
  }

  const connected = await connectMongo(logger);
  if (!connected) {
    throw new Error("MongoDB is required for SOC Copilot");
  }

  const service = new CopilotService();
  const response = await service.query(question);

  process.stdout.write(JSON.stringify(response, null, 2) + "\n");
}

main()
  .catch((error) => {
    process.stderr.write(JSON.stringify({
      success: false,
      error: String(error?.message || error),
      cause: error?.cause ? String(error.cause?.message || error.cause) : undefined,
    }, null, 2) + "\n");
    process.exitCode = 1;
  })
  .finally(async () => {
    await disconnectMongo(logger);
  });
