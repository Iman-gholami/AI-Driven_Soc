const { ServiceUnavailableError } = require('../../src/core/errors');
const { matchesAnalysisGuard } = require('../../src/investigation/analysisReference');

function duplicateKeyError(keyPattern) {
  const error = new Error(`E11000 duplicate key error: ${Object.keys(keyPattern).join(', ')}`);
  error.code = 11000;
  error.keyPattern = keyPattern;
  return error;
}

// Test double for InvestigationRepository. `transaction` snapshots all state and restores it when the
// work throws, mirroring an aborted MongoDB transaction; unique indexes and the projection guard behave
// like the real collection. Real rollback behavior is verified separately in integration/.
class InMemoryInvestigationRepository {
  constructor({ alerts = [], events = [], transactionsSupported = true } = {}) {
    this.alerts = structuredClone(alerts);
    this.events = structuredClone(events);
    this.transactionsSupported = transactionsSupported;
    this.nextEventId = this.events.length + 1;
    this.hooks = {};
    this.transactionCount = 0;
  }

  async transaction(work) {
    if (!this.transactionsSupported) {
      throw new ServiceUnavailableError('Investigation writes require MongoDB transactions', {
        details: { reason: 'transactions_unavailable' },
      });
    }
    this.transactionCount += 1;
    const saved = structuredClone({
      alerts: this.alerts,
      events: this.events,
      nextEventId: this.nextEventId,
    });
    try {
      return await work({ inMemory: true });
    } catch (error) {
      this.alerts = saved.alerts;
      this.events = saved.events;
      this.nextEventId = saved.nextEventId;
      throw error;
    }
  }

  alert(alertId) {
    return this.alerts.find((alert) => alert.alertId === alertId);
  }

  async findAlertByPublicId(alertId) {
    const alert = this.alert(String(alertId));
    return alert ? structuredClone(alert) : null;
  }

  async findEventByKey(alertRef, idempotencyKey) {
    const event = this.events.find(
      (item) => item.alertRef === alertRef && item.idempotencyKey === idempotencyKey,
    );
    return event ? structuredClone(event) : null;
  }

  async insertEvent(event) {
    if (this.events.some((item) => item.alertRef === event.alertRef && item.sequence === event.sequence)) {
      throw duplicateKeyError({ alertRef: 1, sequence: 1 });
    }
    if (
      this.events.some(
        (item) => item.alertRef === event.alertRef && item.idempotencyKey === event.idempotencyKey,
      )
    ) {
      throw duplicateKeyError({ alertRef: 1, idempotencyKey: 1 });
    }
    const stored = { ...structuredClone(event), _id: `evt-${this.nextEventId}` };
    this.nextEventId += 1;
    this.events.push(stored);
    await this.hooks.afterInsert?.(this, stored);
    return structuredClone(stored);
  }

  async updateTriageProjection(alertRef, { expectedVersion, guard }, triage) {
    await this.hooks.beforeProjectionUpdate?.(this);
    const alert = this.alerts.find((item) => item._id === alertRef);
    if (!alert) return false;
    const version = alert.triage?.version ?? 0;
    if (version !== expectedVersion || !matchesAnalysisGuard(alert, guard)) return false;
    alert.triage = structuredClone(triage);
    return true;
  }

  async listEvents(alertRef) {
    return structuredClone(
      this.events.filter((item) => item.alertRef === alertRef).sort((a, b) => a.sequence - b.sequence),
    );
  }
}

module.exports = { InMemoryInvestigationRepository, duplicateKeyError };
