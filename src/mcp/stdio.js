require("dotenv").config();
const readline = require("node:readline");
const { settings } = require("../core/config");
const { createLogger } = require("../core/logging");
const { connectMongo, disconnectMongo } = require("../database/mongo");
const { SocMcpServer } = require("./socMcpServer");

const logger = createLogger(settings.logLevel);
const server = new SocMcpServer();

async function main() {
  await connectMongo(logger);

  const input = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const line of input) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    let message;
    try {
      message = JSON.parse(trimmed);
    } catch (error) {
      process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }) + "\n");
      continue;
    }

    try {
      const response = await server.handleMessage(message);
      if (response) process.stdout.write(JSON.stringify(response) + "\n");
    } catch (error) {
      logger.error({ err: error }, "MCP stdio request failed");
      if (message?.id !== undefined) {
        process.stdout.write(JSON.stringify({
          jsonrpc: "2.0",
          id: message.id,
          error: { code: -32603, message: "Internal error" },
        }) + "\n");
      }
    }
  }

  await disconnectMongo(logger);
}

main().catch(async (error) => {
  logger.error({ err: error }, "MCP server failed");
  try { await disconnectMongo(logger); } catch (_) {}
  process.exitCode = 1;
});
