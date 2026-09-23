const mongoose = require('mongoose');
const Alert = require('../models/Alert');
const InvestigationEvent = require('../models/InvestigationEvent');
const { ServiceUnavailableError } = require('../core/errors');
const { analysisGuardToMongoFilter } = require('../investigation/analysisReference');

const ALERT_INVESTIGATION_FIELDS =
  '_id alertId aiStatus status analysis fullAnalysis llmProvider model ruleMatch triage createdAt';

class InvestigationRepository {
  constructor({
    connection = mongoose.connection,
    alertModel = Alert,
    eventModel = InvestigationEvent,
  } = {}) {
    this.connection = connection;
    this.alertModel = alertModel;
    this.eventModel = eventModel;
    this.transactionsSupported = null;
  }

  // Transactions need a replica set or sharded cluster; standalone MongoDB is rejected explicitly
  // rather than falling back to unprotected dual writes.
  async assertTransactionsSupported() {
    if (this.connection.readyState !== 1) {
      throw new ServiceUnavailableError('The database is unavailable; investigation changes cannot be saved');
    }
    if (this.transactionsSupported === null) {
      const hello = await this.connection.db.admin().command({ hello: 1 });
      this.transactionsSupported = Boolean(hello.setName) || hello.msg === 'isdbgrid';
    }
    if (!this.transactionsSupported) {
      throw new ServiceUnavailableError(
        'Investigation writes require MongoDB transactions (a replica set or sharded cluster); the connected MongoDB is standalone',
        { details: { reason: 'transactions_unavailable' } },
      );
    }
  }

  async transaction(work) {
    await this.assertTransactionsSupported();
    const session = await this.connection.startSession();
    try {
      let result;
      // withTransaction retries the whole unit on transient errors such as write conflicts, so `work`
      // must re-read everything it depends on.
      await session.withTransaction(
        async () => {
          result = await work(session);
        },
        { readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority' }, readPreference: 'primary' },
      );
      return result;
    } finally {
      await session.endSession();
    }
  }

  async findAlertByPublicId(alertId, session = null) {
    return this.alertModel
      .findOne({ alertId: String(alertId) })
      .select(ALERT_INVESTIGATION_FIELDS)
      .session(session)
      .lean()
      .exec();
  }

  async findEventByKey(alertRef, idempotencyKey, session = null) {
    return this.eventModel.findOne({ alertRef, idempotencyKey }).session(session).lean().exec();
  }

  async insertEvent(event, session = null) {
    const [created] = await this.eventModel.create([event], { session });
    return created.toObject();
  }

  // Applies the new projection only if the alert is still at the expected version and in the analysis
  // state the event was validated against. Returns false when another write got there first.
  async updateTriageProjection(alertRef, { expectedVersion, guard }, triage, session = null) {
    const versionFilter =
      expectedVersion === 0
        ? { $or: [{ triage: { $exists: false } }, { triage: null }, { 'triage.version': 0 }] }
        : { 'triage.version': expectedVersion };
    const result = await this.alertModel
      .updateOne(
        { _id: alertRef, ...versionFilter, ...analysisGuardToMongoFilter(guard) },
        { $set: { triage } },
        { session, timestamps: false },
      )
      .exec();
    return result.matchedCount === 1;
  }

  async listEvents(alertRef, session = null) {
    return this.eventModel.find({ alertRef }).sort({ sequence: 1 }).session(session).lean().exec();
  }
}

module.exports = { InvestigationRepository };
