const test = require('node:test');
const assert = require('node:assert/strict');
const {
  parseWriteRequest,
  parseEventPayload,
  parseIdempotencyKey,
  validateReviewAgainstSnapshot,
  TOOL_INPUT_SCHEMAS,
} = require('../src/investigation/eventSchemas');
const { SOC_MCP_TOOL_NAMES } = require('../src/mcp/toolDefinitions');
const { listDispositionVocabulary } = require('../src/config/dispositionReasons');

const ref = { analysisIndex: 1, analyzedAt: '2026-09-02T10:00:00.000Z', fingerprint: 'a'.repeat(64) };

function issuesOf(fn) {
  try {
    fn();
  } catch (error) {
    assert.equal(error.status, 422);
    return error.details.issues.map((issue) => `${issue.path}: ${issue.message}`);
  }
  assert.fail('Expected a 422 validation error');
}

test('review defaults every section to not_reviewed and requires at least one reviewed section', () => {
  const issues = issuesOf(() =>
    parseWriteRequest('ai_review', { expectedVersion: 0, analysisRef: ref, payload: { sections: {} } }),
  );
  assert.deepEqual(issues, ['payload.sections: At least one section must be reviewed']);

  const parsed = parseWriteRequest('ai_review', {
    expectedVersion: 0,
    analysisRef: ref,
    payload: { sections: { mitre: 'partially_agree' } },
  });
  assert.deepEqual(parsed.payload.sections, {
    verdict: 'not_reviewed',
    severity: 'not_reviewed',
    mitre: 'partially_agree',
    recommendations: 'not_reviewed',
  });
});

test('review requires corrections exactly when verdict or severity is disagree', () => {
  const missing = issuesOf(() =>
    parseWriteRequest('ai_review', {
      expectedVersion: 0,
      analysisRef: ref,
      payload: { sections: { verdict: 'disagree', severity: 'disagree' } },
    }),
  );
  assert.deepEqual(missing.sort(), [
    'payload.corrections.severity: A corrected severity is required when severity is disagree',
    'payload.corrections.verdict: A corrected verdict is required when verdict is disagree',
  ]);

  const unexpected = issuesOf(() =>
    parseWriteRequest('ai_review', {
      expectedVersion: 0,
      analysisRef: ref,
      payload: { sections: { verdict: 'agree' }, corrections: { verdict: 'BENIGN' } },
    }),
  );
  assert.equal(unexpected.length, 1);

  const invalidEnum = issuesOf(() =>
    parseWriteRequest('ai_review', {
      expectedVersion: 0,
      analysisRef: ref,
      payload: { sections: { verdict: 'disagree' }, corrections: { verdict: 'EVIL' } },
    }),
  );
  assert.match(invalidEnum[0], /corrections\.verdict/);
});

test('corrections must differ from the reviewed AI values', () => {
  const review = {
    sections: { verdict: 'disagree', severity: 'disagree' },
    corrections: { verdict: 'MALICIOUS', severity: 'low' },
  };
  const issues = issuesOf(() =>
    validateReviewAgainstSnapshot(review, { verdict: 'MALICIOUS', severity: 'high' }),
  );
  assert.deepEqual(issues, [
    'payload.corrections.verdict: Corrected verdict must differ from the AI verdict',
  ]);
  validateReviewAgainstSnapshot(review, { verdict: 'BENIGN', severity: 'high' });
});

test('disposition validates reason compatibility and conditional reason text', () => {
  const base = { expectedVersion: 0, analysisRef: null };
  const incompatible = issuesOf(() =>
    parseWriteRequest('disposition', {
      ...base,
      payload: { outcome: 'true_positive', action: 'escalated', reasonCodes: ['insufficient_evidence'] },
    }),
  );
  assert.deepEqual(incompatible, [
    'payload.reasonCodes.0: Reason insufficient_evidence is not valid for outcome true_positive',
  ]);

  const unknown = issuesOf(() =>
    parseWriteRequest('disposition', {
      ...base,
      payload: { outcome: 'false_positive', action: 'closed_no_action', reasonCodes: ['made_up'] },
    }),
  );
  assert.deepEqual(unknown, ['payload.reasonCodes.0: Unknown reason code: made_up']);

  const blankOther = issuesOf(() =>
    parseWriteRequest('disposition', {
      ...base,
      payload: {
        outcome: 'false_positive',
        action: 'closed_no_action',
        reasonCodes: ['other'],
        reasonText: '   ',
      },
    }),
  );
  assert.deepEqual(blankOther, ['payload.reasonText: Reason text is required when "other" is selected']);

  const empty = issuesOf(() =>
    parseWriteRequest('disposition', {
      ...base,
      payload: { outcome: 'false_positive', action: 'closed_no_action', reasonCodes: [] },
    }),
  );
  assert.equal(empty.length, 1);

  const valid = parseWriteRequest('disposition', {
    ...base,
    payload: {
      outcome: 'benign_true_positive',
      action: 'ticket_created',
      reasonCodes: ['authorized_internal_scanner', 'duplicate_existing_ticket'],
      reasonText: '  ',
      ticketNumber: ' SOC-42 ',
    },
  });
  assert.equal(valid.payload.reasonText, undefined);
  assert.equal(valid.payload.ticketNumber, 'SOC-42');
});

test('outcome is never inferred: the same reason can support several outcomes', () => {
  for (const outcome of ['true_positive', 'benign_true_positive', 'false_positive', 'inconclusive']) {
    const parsed = parseWriteRequest('disposition', {
      expectedVersion: 0,
      analysisRef: null,
      payload: { outcome, action: 'closed_no_action', reasonCodes: ['duplicate_existing_ticket'] },
    });
    assert.equal(parsed.payload.outcome, outcome);
  }
});

test('bounded strings and nonblank notes are enforced', () => {
  assert.equal(issuesOf(() => parseWriteRequest('note', { payload: { text: '   ' } })).length, 1);
  assert.equal(issuesOf(() => parseWriteRequest('note', { payload: { text: 'x'.repeat(4001) } })).length, 1);
  assert.equal(
    parseWriteRequest('note', { payload: { text: '  checked VPN logs ' } }).payload.text,
    'checked VPN logs',
  );
  assert.equal(
    issuesOf(() => parseWriteRequest('reopened', { expectedVersion: 1, payload: { reason: '' } })).length,
    1,
  );
  assert.equal(
    issuesOf(() =>
      parseWriteRequest('disposition', {
        expectedVersion: 0,
        analysisRef: null,
        payload: {
          outcome: 'false_positive',
          action: 'closed_no_action',
          reasonCodes: ['rule_too_broad'],
          ticketNumber: 'x'.repeat(129),
        },
      }),
    ).length,
    1,
  );
});

test('request bodies reject actor, timestamp, sequence and model fields', () => {
  for (const field of ['actor', 'createdAt', 'sequence', 'model', 'llmProvider', 'type']) {
    const issues = issuesOf(() => parseWriteRequest('note', { payload: { text: 'hello' }, [field]: 'x' }));
    assert.match(issues[0], /Unrecognized key/);
  }
  const nested = issuesOf(() =>
    parseWriteRequest('note', {
      payload: { text: 'hello', actor: { kind: 'ai', id: 'agent', displayName: 'Agent' } },
    }),
  );
  assert.match(nested[0], /Unrecognized key/);
});

test('reserved event types validate against the shared MCP tool vocabulary', () => {
  assert.deepEqual(Object.keys(TOOL_INPUT_SCHEMAS).sort(), [...SOC_MCP_TOOL_NAMES].sort());

  const run = parseEventPayload('query_run', {
    toolName: 'query_soc_data',
    toolInput: { dataset: 'alerts', operation: 'count' },
    resultSummary: '42 alerts',
    evidenceRefs: [{ kind: 'alert', id: 'splunk-1' }],
  });
  assert.equal(run.toolName, 'query_soc_data');

  assert.equal(
    issuesOf(() =>
      parseEventPayload('query_run', { toolName: 'drop_database', toolInput: {}, resultSummary: 'x' }),
    ).length,
    1,
  );
  const badInput = issuesOf(() =>
    parseEventPayload('query_run', {
      toolName: 'query_soc_data',
      toolInput: { dataset: 'users' },
      resultSummary: 'x',
    }),
  );
  assert.ok(badInput.every((issue) => issue.startsWith('toolInput')));

  const marked = parseEventPayload('evidence_marked', {
    evidence: { kind: 'ip', id: '10.0.0.5' },
    relation: 'contradicts',
    assessment: 'ai_verdict',
    source: { toolName: 'get_soc_entity_context', toolInput: { entityType: 'ip', id: '10.0.0.5' } },
  });
  assert.equal(marked.relation, 'contradicts');
  assert.equal(
    issuesOf(() =>
      parseEventPayload('evidence_marked', {
        evidence: { kind: 'ip', id: 'x' },
        relation: 'proves',
        assessment: 'ai_verdict',
      }),
    ).length,
    1,
  );
});

test('reserved event types have no write request schema', () => {
  assert.throws(
    () => parseWriteRequest('query_run', {}),
    (error) => error.status === 422,
  );
  assert.throws(
    () => parseWriteRequest('evidence_marked', {}),
    (error) => error.status === 422,
  );
});

test('idempotency keys are required and bounded', () => {
  assert.equal(
    parseIdempotencyKey('0f4c8a9e-1b2c-4d5e-8f90-123456789abc'),
    '0f4c8a9e-1b2c-4d5e-8f90-123456789abc',
  );
  for (const bad of [undefined, '', 'short', 'x'.repeat(129), 'has spaces in it']) {
    assert.throws(
      () => parseIdempotencyKey(bad),
      (error) => error.status === 422,
    );
  }
});

test('reason vocabulary exposes stable ids with English and Persian labels', () => {
  const vocabulary = listDispositionVocabulary();
  const ids = vocabulary.reasons.map((reason) => reason.id);
  for (const id of [
    'authorized_internal_scanner',
    'known_benign_service',
    'rule_too_broad',
    'duplicate_existing_ticket',
    'remediated_previous_report',
    'confirmed_malicious_activity',
    'insufficient_evidence',
    'other',
  ]) {
    assert.ok(ids.includes(id), id);
  }
  assert.equal(new Set(ids).size, ids.length);
  assert.ok(
    vocabulary.reasons.every((reason) => reason.labelEn && reason.labelFa && reason.outcomes.length > 0),
  );
  assert.deepEqual(
    vocabulary.outcomes.map((outcome) => outcome.id),
    ['true_positive', 'benign_true_positive', 'false_positive', 'inconclusive'],
  );
  assert.deepEqual(
    vocabulary.actions.filter((action) => action.closesTriage).map((action) => action.id),
    ['ticket_created', 'escalated', 'closed_no_action'],
  );
});
