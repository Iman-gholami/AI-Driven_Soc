const { InvestigationRepository } = require('../repositories/InvestigationRepository');
const { ConflictError, InputError, NotFoundError, UnauthorizedError } = require('../core/errors');
const {
  EVENT_SCHEMA_VERSION,
  parseWriteRequest,
  parseEventPayload,
  parseIdempotencyKey,
  validateReviewAgainstSnapshot,
} = require('../investigation/eventSchemas');
const {
  canonicalJson,
  sha256,
  toIso,
  describeReviewableAnalysis,
  resolveAnalysisReference,
  ruleSnapshotFromAlert,
} = require('../investigation/analysisReference');
const { applyEvent, currentTriage, reduceTriage } = require('../investigation/triageReducer');
const { listDispositionVocabulary } = require('../config/dispositionReasons');

const DEFAULT_PAGE_SIZE = 50;
const MAX_PAGE_SIZE = 200;

// Records human investigation actions as append-only events and keeps Alert.triage in step, both inside
// one MongoDB transaction. It never calls the LLM and never decides anything on the analyst's behalf.
class InvestigationService {
  constructor({ repository = new InvestigationRepository(), now = () => new Date() } = {}) {
    this.repository = repository;
    this.now = now;
  }

  listReasons() {
    return listDispositionVocabulary();
  }

  async getInvestigation(publicAlertId, { limit, before } = {}) {
    const pageSize = parsePositiveInt(limit, 'limit', DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE);
    const beforeSequence = parsePositiveInt(before, 'before', null, Number.MAX_SAFE_INTEGER);

    const alert = await this.repository.findAlertByPublicId(publicAlertId);
    if (!alert) throw new NotFoundError('Alert not found');

    // State always comes from the complete history, not from the returned page.
    const events = await this.repository.listEvents(alert._id);
    const state = reduceTriage(events);
    const reviewable = describeReviewableAnalysis(alert);
    const reviews = events.filter((event) => event.type === 'ai_review');

    const filtered = beforeSequence ? events.filter((event) => event.sequence < beforeSequence) : events;
    const page = filtered.slice(-pageSize).reverse();
    const oldestOnPage = page.length ? page[page.length - 1].sequence : null;

    return {
      alert: { alertId: alert.alertId, alertRef: String(alert._id), aiStatus: alert.aiStatus || null },
      state,
      version: state.version,
      projectionConsistent: currentTriage(alert).version === state.version,
      reviewableAnalysis: {
        status: reviewable.status,
        reason: reviewable.reason,
        analysisRef: reviewable.ref,
        snapshot: reviewable.snapshot ? omitRef(reviewable.snapshot) : null,
      },
      latestAnalysisReviewed:
        reviewable.status === 'available' ? reviews.some((event) => refersTo(event, reviewable.ref)) : null,
      analyses: (Array.isArray(alert.analysis) ? alert.analysis : []).map((entry, analysisIndex, all) => ({
        analysisIndex,
        analyzedAt: toIso(entry?.analyzedAt),
        verdict: entry?.verdict ?? null,
        severity: entry?.severity ?? null,
        summary: entry?.summary ?? null,
        isLatest: analysisIndex === all.length - 1,
        reviewCount: reviews.filter((event) =>
          refersTo(event, { analysisIndex, analyzedAt: toIso(entry?.analyzedAt) }),
        ).length,
      })),
      events: page.map(presentEvent),
      pagination: {
        limit: pageSize,
        total: events.length,
        nextBefore: oldestOnPage && filtered.length > page.length ? oldestOnPage : null,
      },
    };
  }

  recordReview(publicAlertId, body, context) {
    return this.record('ai_review', publicAlertId, body, context);
  }

  recordDisposition(publicAlertId, body, context) {
    return this.record('disposition', publicAlertId, body, context);
  }

  recordNote(publicAlertId, body, context) {
    return this.record('note', publicAlertId, body, context);
  }

  reopen(publicAlertId, body, context) {
    return this.record('reopened', publicAlertId, body, context);
  }

  async record(type, publicAlertId, body, { idempotencyKey, user } = {}) {
    const actor = humanActor(user);
    const key = parseIdempotencyKey(idempotencyKey);
    const request = parseWriteRequest(type, body);
    // The actor is part of the hash so another analyst reusing a key never receives someone else's result.
    const requestHash = sha256(canonicalJson({ type, actorId: actor.id, request }));

    try {
      return await this.repository.transaction((session) =>
        this.recordInSession(session, { type, publicAlertId, request, key, requestHash, actor }),
      );
    } catch (error) {
      if (isDuplicateKey(error, 'idempotencyKey')) {
        // A concurrent identical request committed first; answer from the stored event.
        const alert = await this.repository.findAlertByPublicId(publicAlertId);
        const existing = alert && (await this.repository.findEventByKey(alert._id, key));
        if (existing) return replay(existing, requestHash, alert);
      }
      if (isDuplicateKey(error, 'sequence')) {
        throw staleVersion(null);
      }
      throw error;
    }
  }

  async recordInSession(session, { type, publicAlertId, request, key, requestHash, actor }) {
    const { repository } = this;
    const alert = await repository.findAlertByPublicId(publicAlertId, session);
    if (!alert) throw new NotFoundError('Alert not found');

    // An identical retry wins over every other check, including a version that has since moved on.
    const existing = await repository.findEventByKey(alert._id, key, session);
    if (existing) return replay(existing, requestHash, alert);

    const state = currentTriage(alert);
    if (request.expectedVersion !== undefined && request.expectedVersion !== state.version) {
      throw staleVersion(state);
    }

    let reference = { ref: null, snapshot: null, guard: null };
    let rule = null;
    if (type === 'ai_review') {
      reference = resolveAnalysisReference(alert, request.analysisRef, { requireAnalysis: true });
      validateReviewAgainstSnapshot(request.payload, reference.snapshot);
      rule = reference.snapshot.rule;
    } else if (type === 'disposition') {
      reference = resolveAnalysisReference(alert, request.analysisRef, { requireAnalysis: false });
      rule = ruleSnapshotFromAlert(alert);
    } else if (type === 'reopened' && state.status !== 'closed') {
      throw new ConflictError('The alert is already open', {
        details: { reason: 'already_open', currentVersion: state.version },
      });
    }

    const inserted = await repository.insertEvent(
      {
        alertRef: alert._id,
        alertId: alert.alertId,
        schemaVersion: EVENT_SCHEMA_VERSION,
        type,
        sequence: state.version + 1,
        createdAt: this.now(),
        actor,
        payload: parseEventPayload(type, request.payload),
        context: {
          analysisRef: reference.ref
            ? { ...reference.ref, analyzedAt: new Date(reference.ref.analyzedAt) }
            : null,
          analysisSnapshot: reference.snapshot ? omitRef(reference.snapshot) : null,
          rule,
        },
        idempotencyKey: key,
        requestHash,
      },
      session,
    );

    const nextState = applyEvent(state, inserted);
    const applied = await repository.updateTriageProjection(
      alert._id,
      { expectedVersion: state.version, guard: reference.guard },
      nextState,
      session,
    );
    if (!applied) {
      // Throwing aborts the transaction, so the event inserted above is rolled back.
      throw new ConflictError('The alert changed while saving; refresh and try again', {
        details: { reason: 'concurrent_change', refresh: true },
      });
    }

    return { event: presentEvent(inserted), state: nextState, version: nextState.version, replayed: false };
  }
}

function humanActor(user) {
  const username = typeof user?.username === 'string' ? user.username.trim() : '';
  if (!username) {
    throw new UnauthorizedError(
      'An authenticated analyst identity is required to record investigation events',
    );
  }
  const displayName =
    typeof user.displayName === 'string' && user.displayName.trim() ? user.displayName.trim() : username;
  return { kind: 'human', id: username.slice(0, 200), displayName: displayName.slice(0, 200) };
}

function replay(existing, requestHash, alert) {
  if (existing.requestHash !== requestHash) {
    throw new ConflictError('This Idempotency-Key was already used for a different request', {
      details: { reason: 'idempotency_key_reused' },
    });
  }
  const state = currentTriage(alert);
  return { event: presentEvent(existing), state, version: state.version, replayed: true };
}

function staleVersion(state) {
  return new ConflictError('The investigation changed since it was loaded; refresh before saving', {
    details: {
      reason: 'stale_version',
      refresh: true,
      currentVersion: state ? state.version : null,
      state: state || null,
    },
  });
}

function isDuplicateKey(error, field) {
  if (error?.code !== 11000) return false;
  const fields = Object.keys(error.keyPattern || error.keyValue || {});
  return fields.includes(field);
}

function refersTo(event, ref) {
  const eventRef = event.context?.analysisRef;
  return (
    Boolean(eventRef && ref) &&
    eventRef.analysisIndex === ref.analysisIndex &&
    toIso(eventRef.analyzedAt) === toIso(ref.analyzedAt)
  );
}

function omitRef(snapshot) {
  return Object.fromEntries(Object.entries(snapshot).filter(([key]) => key !== 'analysisRef'));
}

function presentEvent(event) {
  return {
    id: String(event._id),
    alertId: event.alertId,
    sequence: event.sequence,
    type: event.type,
    schemaVersion: event.schemaVersion,
    createdAt: event.createdAt,
    actor: event.actor,
    payload: event.payload,
    context: {
      analysisRef: event.context?.analysisRef ?? null,
      analysisSnapshot: event.context?.analysisSnapshot ?? null,
      rule: event.context?.rule ?? null,
    },
  };
}

function parsePositiveInt(value, name, fallback, max) {
  if (value === undefined || value === null || value === '') return fallback;
  const number = Number(value);
  if (!Number.isInteger(number) || number < 1 || number > max) {
    throw new InputError(`${name} must be an integer between 1 and ${max}`);
  }
  return number;
}

module.exports = { InvestigationService, humanActor, presentEvent };
