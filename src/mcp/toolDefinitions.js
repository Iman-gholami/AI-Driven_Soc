// Tool names and input schemas for the SOC MCP server. Kept free of service dependencies so other
// modules (for example investigation event validation) can share the same tool vocabulary.
const QUERY_INPUT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['dataset', 'operation'],
  properties: {
    dataset: {
      type: 'string',
      enum: [
        'alerts',
        'detection_rules',
        'ip_assets',
        'threat_intelligence',
        'dataset_states',
        'mitre_coverage_snapshots',
        'mitre_techniques',
      ],
    },
    operation: { type: 'string', enum: ['count', 'aggregate', 'list', 'distinct'] },
    timeRange: {
      type: 'object',
      additionalProperties: false,
      properties: {
        type: {
          type: 'string',
          enum: [
            'all',
            'today',
            'yesterday',
            'last_n_hours',
            'last_n_days',
            'this_week',
            'previous_week',
            'between',
          ],
        },
        value: { type: 'integer', minimum: 1, maximum: 3650 },
        from: { type: 'string' },
        to: { type: 'string' },
        field: { type: 'string' },
      },
      required: ['type'],
    },
    filters: {
      type: 'array',
      maxItems: 20,
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['field', 'operator'],
        properties: {
          field: { type: 'string' },
          operator: {
            type: 'string',
            enum: ['eq', 'neq', 'contains', 'in', 'exists', 'gt', 'gte', 'lt', 'lte'],
          },
          value: {},
        },
      },
    },
    groupBy: { type: 'array', maxItems: 4, items: { type: 'string' } },
    metrics: {
      type: 'array',
      maxItems: 8,
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['type'],
        properties: {
          type: { type: 'string', enum: ['count', 'sum', 'avg', 'min', 'max'] },
          field: { type: 'string' },
          alias: { type: 'string', pattern: '^[A-Za-z_][A-Za-z0-9_]{0,63}$' },
        },
      },
    },
    select: { type: 'array', maxItems: 20, items: { type: 'string' } },
    sort: {
      type: 'array',
      maxItems: 4,
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['field', 'direction'],
        properties: {
          field: { type: 'string' },
          direction: { type: 'string', enum: ['asc', 'desc'] },
        },
      },
    },
    limit: { type: 'integer', minimum: 1, maximum: 100 },
  },
};

const BATCH_INPUT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['queries'],
  properties: {
    queries: {
      type: 'array',
      minItems: 2,
      maxItems: 5,
      items: QUERY_INPUT_SCHEMA,
    },
  },
};

const ENTITY_CONTEXT_INPUT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['entityType', 'id'],
  properties: {
    entityType: {
      type: 'string',
      enum: ['alert', 'ip', 'organization', 'rule', 'mitre_technique'],
    },
    id: { type: 'string', minLength: 1, maxLength: 500 },
  },
};

const METRIC_ANALYSIS_INPUT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['operation'],
  properties: {
    operation: { type: 'string', enum: ['compare', 'percentage', 'trend'] },
    left: { type: 'object' },
    right: { type: 'object' },
    numerator: { type: 'object' },
    denominator: { type: 'object' },
    query: QUERY_INPUT_SCHEMA,
    timeRange: QUERY_INPUT_SCHEMA.properties.timeRange,
    bucket: { type: 'string', enum: ['hour', 'day'] },
  },
};

const CORRELATION_INPUT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['relationship'],
  properties: {
    relationship: {
      type: 'string',
      enum: [
        'alert_source_ip_to_threat_source',
        'alert_destination_ip_to_asset',
        'alert_rule_to_detection_rule',
        'detection_rule_to_mitre_technique',
        'alert_ip_to_organization',
      ],
    },
    timeRange: QUERY_INPUT_SCHEMA.properties.timeRange,
    limit: { type: 'integer', minimum: 1, maximum: 100 },
  },
};

const SOC_MCP_TOOLS = [
  {
    name: 'describe_soc_schema',
    description:
      'Describe approved SOC datasets and fields. Use this before querying when field or dataset semantics are uncertain.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        dataset: {
          type: 'string',
          enum: [
            'alerts',
            'detection_rules',
            'ip_assets',
            'threat_intelligence',
            'dataset_states',
            'mitre_coverage_snapshots',
            'mitre_techniques',
          ],
        },
      },
    },
    annotations: {
      title: 'Describe SOC schema',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: 'query_soc_data',
    description:
      'Run a validated read-only query against approved SOC datasets. Never accepts raw MongoDB or JavaScript.',
    inputSchema: QUERY_INPUT_SCHEMA,
    annotations: {
      title: 'Query SOC data',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: 'correlate_soc_entities',
    description:
      'Execute an allowlisted deterministic relationship correlation between SOC entities using the relationship catalog.',
    inputSchema: CORRELATION_INPUT_SCHEMA,
    annotations: {
      title: 'Correlate SOC entities',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: 'analyze_soc_metric',
    description:
      'Calculate deterministic SOC comparisons, percentages, or time trends from validated count queries. Use this instead of asking the language model to calculate statistics.',
    inputSchema: METRIC_ANALYSIS_INPUT_SCHEMA,
    annotations: {
      title: 'Analyze SOC metric',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: 'get_soc_entity_context',
    description:
      'Get a grounded investigation context for a focused SOC entity such as an alert, IP, organization, rule, or MITRE technique. Use this for follow-up questions like summarize it, why is it malicious, what should we do, or what do we know about this IP.',
    inputSchema: ENTITY_CONTEXT_INPUT_SCHEMA,
    annotations: {
      title: 'Get SOC entity context',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: 'query_soc_data_batch',
    description:
      'Run 2 to 5 independent validated read-only SOC queries when one analyst question requires multiple datasets or comparisons.',
    inputSchema: BATCH_INPUT_SCHEMA,
    annotations: {
      title: 'Batch query SOC data',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
];

const SOC_MCP_TOOL_NAMES = Object.freeze(SOC_MCP_TOOLS.map((tool) => tool.name));

module.exports = {
  QUERY_INPUT_SCHEMA,
  BATCH_INPUT_SCHEMA,
  ENTITY_CONTEXT_INPUT_SCHEMA,
  METRIC_ANALYSIS_INPUT_SCHEMA,
  CORRELATION_INPUT_SCHEMA,
  SOC_MCP_TOOLS,
  SOC_MCP_TOOL_NAMES,
};
