const { z } = require('zod');
const { verdictSchema, severitySchema } = require('../models/incidentSchema');
const { SOC_MCP_TOOLS, SOC_MCP_TOOL_NAMES } = require('../mcp/toolDefinitions');
const {
  socQueryPlanSchema,
  batchQuerySchema,
  metricAnalysisArgumentsSchema,
  entityContextToolSelectionSchema,
  correlationToolSelectionSchema,
} = require('../copilot/querySchema');
const {
  OUTCOME_IDS,
  ACTION_IDS,
  getDispositionReason,
  isReasonAllowedForOutcome,
} = require('../config/dispositionReasons');
const { UnprocessableError } = require('../core/errors');

const EVENT_SCHEMA_VERSION = 1;
const WRITABLE_EVENT_TYPES = Object.freeze(['ai_review', 'disposition', 'note', 'reopened']);
// Reserved for future agent workflows: validated by the model, but no endpoint or UI writes them in V1.
const RESERVED_EVENT_TYPES = Object.freeze(['query_run', 'evidence_marked']);
const EVENT_TYPES = Object.freeze([...WRITABLE_EVENT_TYPES, ...RESERVED_EVENT_TYPES]);
const ACTOR_KINDS = Object.freeze(['human', 'ai']);

const REVIEW_SECTIONS = Object.freeze(['verdict', 'severity', 'mitre', 'recommendations']);
const REVIEW_STATUSES = Object.freeze(['agree', 'partially_agree', 'disagree', 'not_reviewed']);
const EVIDENCE_KINDS = Object.freeze([
  'alert',
  'investigation_event',
  'ip',
  'rule',
  'report',
  'mitre_technique',
  'dataset_record',
]);
const EVIDENCE_RELATIONS = Object.freeze(['supports', 'contradicts', 'context']);
const EVIDENCE_ASSESSMENTS = Object.freeze([
  'ai_verdict',
  'ai_severity',
  'ai_mitre',
  'ai_recommendations',
  'disposition',
]);
const MAX_TOOL_INPUT_CHARS = 20000;

function requiredText(max) {
  return z.string().trim().min(1, 'Must not be blank').max(max);
}

// Blank optional text is stored as absent rather than as an empty string.
function optionalText(max) {
  return z.preprocess(
    (value) => (typeof value === 'string' ? value.trim() || undefined : value),
    z.string().max(max).optional(),
  );
}

const describeSchemaDatasets = SOC_MCP_TOOLS.find((tool) => tool.name === 'describe_soc_schema').inputSchema
  .properties.dataset.enum;

// Input validators for each MCP tool, reusing the Copilot planner schemas so the vocabulary stays single-sourced.
const TOOL_INPUT_SCHEMAS = Object.freeze({
  describe_soc_schema: z.object({ dataset: z.enum(describeSchemaDatasets).optional() }).strict(),
  query_soc_data: socQueryPlanSchema,
  correlate_soc_entities: correlationToolSelectionSchema.shape.arguments,
  analyze_soc_metric: metricAnalysisArgumentsSchema,
  get_soc_entity_context: entityContextToolSelectionSchema.shape.arguments,
  query_soc_data_batch: batchQuerySchema,
});

const missingToolSchemas = SOC_MCP_TOOL_NAMES.filter((name) => !TOOL_INPUT_SCHEMAS[name]);
const unknownToolSchemas = Object.keys(TOOL_INPUT_SCHEMAS).filter(
  (name) => !SOC_MCP_TOOL_NAMES.includes(name),
);
if (missingToolSchemas.length || unknownToolSchemas.length) {
  throw new Error(
    `Investigation tool schemas are out of sync with the MCP server (missing: ${missingToolSchemas.join(', ') || 'none'}; unknown: ${unknownToolSchemas.join(', ') || 'none'})`,
  );
}

const actorSchema = z
  .object({
    kind: z.enum(ACTOR_KINDS),
    id: requiredText(200),
    displayName: requiredText(200),
  })
  .strict();

const analysisRefSchema = z
  .object({
    analysisIndex: z.number().int().min(0).max(100000),
    analyzedAt: z.string().datetime({ offset: true }),
    fingerprint: z.string().regex(/^[a-f0-9]{64}$/, 'Must be a SHA-256 hex digest'),
  })
  .strict();

const reviewStatusSchema = z.enum(REVIEW_STATUSES);

const aiReviewPayloadSchema = z
  .object({
    sections: z
      .object({
        verdict: reviewStatusSchema.default('not_reviewed'),
        severity: reviewStatusSchema.default('not_reviewed'),
        mitre: reviewStatusSchema.default('not_reviewed'),
        recommendations: reviewStatusSchema.default('not_reviewed'),
      })
      .strict(),
    corrections: z
      .object({
        verdict: verdictSchema.optional(),
        severity: severitySchema.optional(),
      })
      .strict()
      .default({}),
    comment: optionalText(2000),
  })
  .strict()
  .superRefine((review, ctx) => {
    if (REVIEW_SECTIONS.every((section) => review.sections[section] === 'not_reviewed')) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['sections'],
        message: 'At least one section must be reviewed',
      });
    }

    for (const section of ['verdict', 'severity']) {
      const disagrees = review.sections[section] === 'disagree';
      const corrected = review.corrections[section];
      if (disagrees && corrected === undefined) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['corrections', section],
          message: `A corrected ${section} is required when ${section} is disagree`,
        });
      }
      if (!disagrees && corrected !== undefined) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['corrections', section],
          message: `A corrected ${section} is only allowed when ${section} is disagree`,
        });
      }
    }
  });

const dispositionPayloadSchema = z
  .object({
    outcome: z.enum(OUTCOME_IDS),
    action: z.enum(ACTION_IDS),
    reasonCodes: z.array(z.string().max(64)).min(1).max(8),
    reasonText: optionalText(2000),
    ticketNumber: optionalText(128),
  })
  .strict()
  .superRefine((disposition, ctx) => {
    const seen = new Set();
    disposition.reasonCodes.forEach((code, index) => {
      if (seen.has(code)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['reasonCodes', index],
          message: 'Duplicate reason',
        });
      }
      seen.add(code);

      const reason = getDispositionReason(code);
      if (!reason || reason.retired) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['reasonCodes', index],
          message: `Unknown reason code: ${code}`,
        });
      } else if (!isReasonAllowedForOutcome(code, disposition.outcome)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['reasonCodes', index],
          message: `Reason ${code} is not valid for outcome ${disposition.outcome}`,
        });
      }
    });

    const needsText = disposition.reasonCodes.some((code) => getDispositionReason(code)?.requiresText);
    if (needsText && !disposition.reasonText) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['reasonText'],
        message: 'Reason text is required when "other" is selected',
      });
    }
  });

const notePayloadSchema = z.object({ text: requiredText(4000) }).strict();

const reopenedPayloadSchema = z.object({ reason: requiredText(2000) }).strict();

const evidenceRefSchema = z
  .object({
    kind: z.enum(EVIDENCE_KINDS),
    id: requiredText(500),
    label: optionalText(200),
  })
  .strict();

function toolSourceSchema({ requireSummary }) {
  return z
    .object({
      toolName: z.enum(SOC_MCP_TOOL_NAMES),
      toolInput: z.record(z.unknown()),
      resultSummary: requireSummary ? requiredText(4000) : optionalText(4000),
      evidenceRefs: z.array(evidenceRefSchema).max(50).default([]),
    })
    .strict()
    .superRefine((source, ctx) => {
      if (JSON.stringify(source.toolInput).length > MAX_TOOL_INPUT_CHARS) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['toolInput'],
          message: `Tool input must serialize to at most ${MAX_TOOL_INPUT_CHARS} characters`,
        });
        return;
      }
      const result = TOOL_INPUT_SCHEMAS[source.toolName].safeParse(source.toolInput);
      if (!result.success) {
        for (const issue of result.error.issues) {
          ctx.addIssue({ ...issue, path: ['toolInput', ...issue.path] });
        }
      }
    });
}

const queryRunPayloadSchema = toolSourceSchema({ requireSummary: true });

const evidenceMarkedPayloadSchema = z
  .object({
    evidence: evidenceRefSchema,
    relation: z.enum(EVIDENCE_RELATIONS),
    assessment: z.enum(EVIDENCE_ASSESSMENTS),
    source: toolSourceSchema({ requireSummary: false }).optional(),
    note: optionalText(2000),
  })
  .strict();

const PAYLOAD_SCHEMAS = Object.freeze({
  ai_review: aiReviewPayloadSchema,
  disposition: dispositionPayloadSchema,
  note: notePayloadSchema,
  reopened: reopenedPayloadSchema,
  query_run: queryRunPayloadSchema,
  evidence_marked: evidenceMarkedPayloadSchema,
});

const expectedVersionSchema = z.number().int().min(0);

// Request bodies accepted by the write endpoints. They are strict, so actor identity, timestamps,
// sequence numbers or model metadata in a body are rejected instead of silently ignored.
const WRITE_REQUEST_SCHEMAS = Object.freeze({
  ai_review: z
    .object({
      expectedVersion: expectedVersionSchema,
      analysisRef: analysisRefSchema,
      payload: aiReviewPayloadSchema,
    })
    .strict(),
  disposition: z
    .object({
      expectedVersion: expectedVersionSchema,
      analysisRef: analysisRefSchema.nullable(),
      payload: dispositionPayloadSchema,
    })
    .strict(),
  note: z.object({ expectedVersion: expectedVersionSchema.optional(), payload: notePayloadSchema }).strict(),
  reopened: z.object({ expectedVersion: expectedVersionSchema, payload: reopenedPayloadSchema }).strict(),
});

const idempotencyKeySchema = z
  .string()
  .regex(/^[A-Za-z0-9._:-]{8,128}$/, 'Idempotency-Key must be 8-128 characters of [A-Za-z0-9._:-]');

function toIssues(error) {
  return error.issues.map((issue) => ({ path: issue.path.join('.'), message: issue.message }));
}

function parseOrThrow(schema, value, message) {
  const result = schema.safeParse(value);
  if (!result.success) {
    throw new UnprocessableError(message, {
      details: { reason: 'invalid_payload', issues: toIssues(result.error) },
    });
  }
  return result.data;
}

function parseWriteRequest(type, body) {
  const schema = WRITE_REQUEST_SCHEMAS[type];
  if (!schema) throw new UnprocessableError(`Event type ${type} cannot be written through the API`);
  return parseOrThrow(schema, body, 'Invalid investigation request');
}

function parseEventPayload(type, payload) {
  const schema = PAYLOAD_SCHEMAS[type];
  if (!schema) throw new UnprocessableError(`Unknown investigation event type: ${type}`);
  return parseOrThrow(schema, payload, `Invalid ${type} payload`);
}

function parseIdempotencyKey(value) {
  return parseOrThrow(idempotencyKeySchema, value, 'A valid Idempotency-Key header is required');
}

// A correction must name a different value than the one the AI produced.
function validateReviewAgainstSnapshot(review, snapshot) {
  const issues = [];
  if (review.corrections.verdict !== undefined && review.corrections.verdict === snapshot?.verdict) {
    issues.push({
      path: 'payload.corrections.verdict',
      message: 'Corrected verdict must differ from the AI verdict',
    });
  }
  if (review.corrections.severity !== undefined && review.corrections.severity === snapshot?.severity) {
    issues.push({
      path: 'payload.corrections.severity',
      message: 'Corrected severity must differ from the AI severity',
    });
  }
  if (issues.length > 0) {
    throw new UnprocessableError('Invalid review corrections', {
      details: { reason: 'invalid_payload', issues },
    });
  }
}

module.exports = {
  EVENT_SCHEMA_VERSION,
  EVENT_TYPES,
  WRITABLE_EVENT_TYPES,
  RESERVED_EVENT_TYPES,
  ACTOR_KINDS,
  REVIEW_SECTIONS,
  REVIEW_STATUSES,
  EVIDENCE_KINDS,
  EVIDENCE_RELATIONS,
  EVIDENCE_ASSESSMENTS,
  TOOL_INPUT_SCHEMAS,
  PAYLOAD_SCHEMAS,
  WRITE_REQUEST_SCHEMAS,
  actorSchema,
  analysisRefSchema,
  parseWriteRequest,
  parseEventPayload,
  parseIdempotencyKey,
  validateReviewAgainstSnapshot,
};
