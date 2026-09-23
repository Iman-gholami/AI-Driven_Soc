const { CLOSING_ACTION_IDS } = require('../config/dispositionReasons');

// Pure projection of an alert's investigation events into its current triage state. The event log is
// authoritative; Alert.triage stores the output of this reducer and can be rebuilt by replaying events.

class TriageReplayError extends Error {
  constructor(message) {
    super(message);
    this.name = 'TriageReplayError';
  }
}

function initialTriageState() {
  return {
    status: 'open',
    version: 0,
    outcome: null,
    action: null,
    reasonCodes: [],
    reasonText: null,
    ticketNumber: null,
    closedAt: null,
    disposition: null,
    review: null,
    lastEvent: null,
    updatedAt: null,
    updatedBy: null,
  };
}

function toDate(value) {
  return value instanceof Date ? value : new Date(value);
}

function eventRef(event) {
  return {
    eventId: event._id === undefined || event._id === null ? null : String(event._id),
    sequence: event.sequence,
    type: event.type,
    at: toDate(event.createdAt),
  };
}

function clearDisposition(state) {
  return {
    ...state,
    outcome: null,
    action: null,
    reasonCodes: [],
    reasonText: null,
    ticketNumber: null,
    closedAt: null,
    disposition: null,
  };
}

function applyEvent(state, event) {
  const expected = state.version + 1;
  if (event.sequence !== expected) {
    throw new TriageReplayError(`Expected event sequence ${expected} but received ${event.sequence}`);
  }

  const ref = eventRef(event);
  const at = ref.at;
  let next = {
    ...state,
    version: event.sequence,
    lastEvent: ref,
    updatedAt: at,
    updatedBy: event.actor ? { ...event.actor } : null,
  };

  switch (event.type) {
    case 'disposition': {
      const payload = event.payload;
      const closes = CLOSING_ACTION_IDS.includes(payload.action);
      next = {
        ...clearDisposition(next),
        status: closes ? 'closed' : 'open',
        outcome: payload.outcome,
        action: payload.action,
        reasonCodes: [...payload.reasonCodes],
        reasonText: payload.reasonText ?? null,
        ticketNumber: payload.ticketNumber ?? null,
        closedAt: closes ? at : null,
        disposition: {
          eventId: ref.eventId,
          sequence: ref.sequence,
          at,
          actor: event.actor ? { ...event.actor } : null,
          analysisRef: event.context?.analysisRef ?? null,
        },
      };
      break;
    }
    case 'reopened':
      next = { ...clearDisposition(next), status: 'open' };
      break;
    case 'ai_review':
      next.review = {
        eventId: ref.eventId,
        sequence: ref.sequence,
        at,
        actor: event.actor ? { ...event.actor } : null,
        analysisRef: event.context?.analysisRef ?? null,
        sections: { ...event.payload.sections },
        corrections: { ...(event.payload.corrections || {}) },
      };
      break;
    // Notes and reserved agent event types only advance the version and last-event reference.
    default:
      break;
  }

  return next;
}

function reduceTriage(events) {
  return [...events].sort((a, b) => a.sequence - b.sequence).reduce(applyEvent, initialTriageState());
}

// Alerts created before investigations existed have no projection; they are open with version 0.
function currentTriage(alert) {
  return alert?.triage && Number.isInteger(alert.triage.version) ? alert.triage : initialTriageState();
}

module.exports = {
  TriageReplayError,
  initialTriageState,
  applyEvent,
  reduceTriage,
  currentTriage,
};
