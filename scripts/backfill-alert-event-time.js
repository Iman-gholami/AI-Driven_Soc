require("dotenv").config();

const { settings } = require("../src/core/config");
const { createLogger } = require("../src/core/logging");
const { connectMongo, disconnectMongo } = require("../src/database/mongo");
const Alert = require("../src/models/Alert");
const { resolveAlertEventTime } = require("../src/services/eventTime");

const logger = createLogger(settings.logLevel);

async function main() {
  const connected = await connectMongo(logger);
  if (!connected) throw new Error("MongoDB connection is required");

  const cursor = Alert.find(
    {
      $or: [
        { eventTime: { $exists: false } },
        { eventTime: null },
      ],
    },
  )
    .select("_id rawEvent createdAt")
    .lean()
    .cursor();

  let processed = 0;
  let updated = 0;
  let batch = [];

  for await (const alert of cursor) {
    processed += 1;
    const eventTime = resolveAlertEventTime(alert.rawEvent || {}, alert.createdAt || new Date());

    batch.push({
      updateOne: {
        filter: { _id: alert._id },
        update: { $set: { eventTime } },
      },
    });

    if (batch.length >= 500) {
      const result = await Alert.bulkWrite(batch, { ordered: false });
      updated += Number(result.modifiedCount || 0);
      batch = [];
      process.stdout.write(`processed=${processed} updated=${updated}\n`);
    }
  }

  if (batch.length) {
    const result = await Alert.bulkWrite(batch, { ordered: false });
    updated += Number(result.modifiedCount || 0);
  }

  process.stdout.write(JSON.stringify({
    success: true,
    processed,
    updated,
  }, null, 2) + "\n");
}

main()
  .catch((error) => {
    process.stderr.write(JSON.stringify({
      success: false,
      error: String(error?.message || error),
    }, null, 2) + "\n");
    process.exitCode = 1;
  })
  .finally(async () => {
    await disconnectMongo(logger);
  });
