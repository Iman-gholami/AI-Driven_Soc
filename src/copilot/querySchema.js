const { z } = require("zod");

const timeRangeSchema = z.object({
  type: z.enum([
    "all",
    "today",
    "yesterday",
    "last_n_hours",
    "last_n_days",
    "this_week",
    "previous_week",
    "between",
  ]),
  value: z.number().int().positive().max(3650).optional(),
  from: z.string().optional(),
  to: z.string().optional(),
  field: z.string().min(1).optional(),
}).strict();

const filterSchema = z.object({
  field: z.string().min(1),
  operator: z.enum(["eq", "neq", "contains", "in", "exists", "gt", "gte", "lt", "lte"]),
  value: z.any().optional(),
}).strict();

const metricSchema = z.object({
  type: z.enum(["count", "sum", "avg", "min", "max"]),
  field: z.string().min(1).optional(),
  alias: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,63}$/).optional(),
}).strict();

const sortSchema = z.object({
  field: z.string().min(1),
  direction: z.enum(["asc", "desc"]).default("desc"),
}).strict();

const socQueryPlanSchema = z.object({
  dataset: z.string().min(1),
  operation: z.enum(["count", "aggregate", "list", "distinct"]),
  timeRange: timeRangeSchema.optional(),
  filters: z.array(filterSchema).max(20).default([]),
  groupBy: z.array(z.string().min(1)).max(4).default([]),
  metrics: z.array(metricSchema).max(8).default([]),
  select: z.array(z.string().min(1)).max(20).default([]),
  sort: z.array(sortSchema).max(4).default([]),
  limit: z.number().int().positive().max(100).default(20),
}).strict();

const toolSelectionSchema = z.object({
  tool: z.enum(["query_soc_data"]),
  arguments: socQueryPlanSchema,
}).strict();

module.exports = {
  timeRangeSchema,
  filterSchema,
  metricSchema,
  sortSchema,
  socQueryPlanSchema,
  toolSelectionSchema,
};
