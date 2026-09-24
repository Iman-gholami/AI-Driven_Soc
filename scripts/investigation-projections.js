// Maintenance for Alert.triage, the projection of the investigation event log.
//
//   node scripts/investigation-projections.js backfill           give legacy alerts an explicit open projection
//   node scripts/investigation-projections.js rebuild             report projections that differ from a replay
//   node scripts/investigation-projections.js rebuild --apply     rewrite those projections from the event log
//
// Both commands are idempotent. Neither touches investigation events.
require('dotenv').config();

const { settings } = require('../src/core/config');
const { createLogger } = require('../src/core/logging');
const { connectMongo, disconnectMongo } = require('../src/database/mongo');
const Alert = require('../src/models/Alert');
const InvestigationEvent = require('../src/models/InvestigationEvent');
const { initialTriageState, projectionsEqual, reduceTriage } = require('../src/investigation/triageReducer');

const logger = createLogger(settings.logLevel);

// Optional: queries already treat a missing projection as open, but an explicit value lets the
// triage.status index serve the open filter without an $exists clause.
async function backfill() {
  const result = await Alert.updateMany(
    { $or: [{ triage: { $exists: false } }, { triage: null }] },
    { $set: { triage: initialTriageState() } },
    { timestamps: false },
  );
  return { command: 'backfill', matched: result.matchedCount, updated: result.modifiedCount };
}

async function rebuild({ apply }) {
  const summary = { command: 'rebuild', apply, alerts: 0, consistent: 0, drifted: 0, updated: 0, skipped: 0 };
  const alertRefs = await InvestigationEvent.distinct('alertRef');

  for (const alertRef of alertRefs) {
    summary.alerts += 1;
    const events = await InvestigationEvent.find({ alertRef }).sort({ sequence: 1 }).lean();
    const replayed = reduceTriage(events);
    const alert = await Alert.findById(alertRef).select('alertId triage').lean();
    if (!alert) {
      summary.skipped += 1;
      logger.warn({ alertRef: String(alertRef) }, 'investigation_events_without_alert');
      continue;
    }

    if (alert.triage && projectionsEqual(alert.triage, replayed)) {
      summary.consistent += 1;
      continue;
    }

    summary.drifted += 1;
    logger.warn(
      {
        alertId: alert.alertId,
        storedVersion: alert.triage?.version ?? null,
        replayedVersion: replayed.version,
      },
      'triage_projection_drift',
    );
    if (!apply) continue;

    // Never overwrite a projection that moved past this replay (a write landed meanwhile).
    const result = await Alert.updateOne(
      {
        _id: alertRef,
        $or: [
          { triage: { $exists: false } },
          { triage: null },
          { 'triage.version': { $lte: replayed.version } },
        ],
      },
      { $set: { triage: replayed } },
      { timestamps: false },
    );
    summary.updated += result.modifiedCount;
  }

  return summary;
}

async function main() {
  const [command] = process.argv.slice(2);
  if (!['backfill', 'rebuild'].includes(command)) {
    throw new Error('Usage: investigation-projections.js <backfill|rebuild> [--apply]');
  }
  const connected = await connectMongo(logger);
  if (!connected) throw new Error('MongoDB connection is required');

  const result =
    command === 'backfill' ? await backfill() : await rebuild({ apply: process.argv.includes('--apply') });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

if (require.main === module) {
  main()
    .catch((error) => {
      logger.error({ err: error }, 'investigation_projection_maintenance_failed');
      process.exitCode = 1;
    })
    .finally(() => disconnectMongo(logger));
}

module.exports = { backfill, rebuild };
