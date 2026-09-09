const { getDatasetSchema, getFieldSchema } = require("./schemaCatalog");

function compileSocQuery(plan, {
  resolvedTimeRange,
  baseMatch = {},
} = {}) {
  const dataset = getDatasetSchema(plan.dataset);
  if (!dataset) throw new Error(`Unknown dataset: ${plan.dataset}`);

  validatePlanFields(plan, dataset);

  const unwindPaths = getRequiredUnwinds(plan, dataset);
  const preUnwindFilters = [];
  const postUnwindFilters = [];

  for (const filter of plan.filters || []) {
    const metadata = getFieldSchema(plan.dataset, filter.field);
    if (metadata?.unwind && unwindPaths.includes(metadata.unwind)) {
      postUnwindFilters.push(filter);
    } else {
      preUnwindFilters.push(filter);
    }
  }

  const matchClauses = [];
  if (baseMatch && Object.keys(baseMatch).length) matchClauses.push(baseMatch);

  if (resolvedTimeRange?.from || resolvedTimeRange?.to) {
    const timeField = plan.timeRange?.field || dataset.defaultTimeField;
    const timeSchema = getFieldSchema(plan.dataset, timeField);
    if (!timeSchema || timeSchema.type !== "date" || !timeSchema.filterable) {
      throw new Error(`Invalid time field: ${timeField}`);
    }

    const bounds = {};
    if (resolvedTimeRange.from) bounds.$gte = resolvedTimeRange.from;
    if (resolvedTimeRange.to) bounds.$lt = resolvedTimeRange.to;
    matchClauses.push(buildTimeRangeMatch(plan.dataset, timeField, timeSchema, bounds));
  }

  matchClauses.push(...buildFilterClauses(preUnwindFilters, dataset));

  const pipeline = [];
  if (matchClauses.length === 1) pipeline.push({ $match: matchClauses[0] });
  if (matchClauses.length > 1) pipeline.push({ $match: { $and: matchClauses } });

  for (const path of unwindPaths) {
    pipeline.push({ $unwind: { path: "$" + path, preserveNullAndEmptyArrays: false } });
  }

  if (postUnwindFilters.length) {
    const postMatch = postUnwindFilters.map((filter) =>
      buildFilter(getFieldSchema(plan.dataset, filter.field), filter)
    );
    pipeline.push({
      $match: postMatch.length === 1 ? postMatch[0] : { $and: postMatch },
    });
  }

  if (plan.operation === "count") {
    pipeline.push({ $count: "count" });
    return { pipeline, resultShape: "count" };
  }

  if (plan.operation === "list") {
    const usesEventTimeFallback = plan.dataset === "alerts"
      && (plan.sort || []).some((item) => item.field === "eventTime");

    if (usesEventTimeFallback) {
      pipeline.push({
        $set: {
          __socEventTime: { $ifNull: ["$eventTime", "$createdAt"] },
        },
      });
    }

    const sort = buildDocumentSort(plan);
    if (Object.keys(sort).length) pipeline.push({ $sort: sort });

    if (plan.select?.length) {
      const projection = { _id: 0 };
      const selectedFields = withIdentityField(plan.dataset, plan.select);
      for (const fieldName of selectedFields) {
        const metadata = getFieldSchema(plan.dataset, fieldName);
        if (plan.dataset === "alerts" && fieldName === "eventTime") {
          projection.eventTime = { $ifNull: ["$eventTime", "$createdAt"] };
        } else {
          projection[metadata.path] = 1;
        }
      }
      pipeline.push({ $project: projection });
    }

    pipeline.push({ $limit: Math.min(plan.limit || 20, 100) });
    return { pipeline, resultShape: "rows" };
  }

  if (plan.operation === "distinct") {
    if (plan.groupBy.length !== 1) {
      throw new Error("distinct requires exactly one groupBy field");
    }
    const metadata = getFieldSchema(plan.dataset, plan.groupBy[0]);
    pipeline.push({ $group: { _id: `$${metadata.path}` } });
    pipeline.push({ $match: { _id: { $ne: null } } });
    pipeline.push({ $sort: { _id: 1 } });
    pipeline.push({ $limit: Math.min(plan.limit || 20, 100) });
    pipeline.push({ $project: { _id: 0, value: "$_id" } });
    return { pipeline, resultShape: "distinct" };
  }

  if (plan.operation === "aggregate") {
    const groupFields = plan.groupBy || [];
    const metrics = normalizeMetrics(plan.metrics);
    if (unwindPaths.length > 0 && metrics.every((metric) => metric.type === "count")) {
      pipeline.push(...buildDistinctDocumentCountStages(plan.dataset, groupFields, metrics));
    } else {
      const group = { _id: buildGroupId(plan.dataset, groupFields) };

      for (const metric of metrics) {
        const alias = metric.alias || defaultMetricAlias(metric);
        if (metric.type === "count") {
          group[alias] = { $sum: 1 };
        } else {
          const metadata = getFieldSchema(plan.dataset, metric.field);
          const operator = {
            sum: "$sum",
            avg: "$avg",
            min: "$min",
            max: "$max",
          }[metric.type];
          group[alias] = { [operator]: "$" + metadata.path };
        }
      }

      pipeline.push({ $group: group });
    }

    const projection = { _id: 0 };
    if (groupFields.length === 1) {
      projection[outputFieldName(groupFields[0])] = "$_id";
    } else {
      for (const fieldName of groupFields) {
        projection[outputFieldName(fieldName)] = `$_id.${safeGroupKey(fieldName)}`;
      }
    }
    for (const metric of metrics) {
      const alias = metric.alias || defaultMetricAlias(metric);
      projection[alias] = 1;
    }
    pipeline.push({ $project: projection });

    const sort = buildAggregateSort(plan, groupFields, metrics);
    if (Object.keys(sort).length) pipeline.push({ $sort: sort });
    pipeline.push({ $limit: Math.min(plan.limit || 20, 100) });

    return { pipeline, resultShape: "aggregate" };
  }

  throw new Error(`Unsupported operation: ${plan.operation}`);
}

function validatePlanFields(plan, dataset) {
  const requireField = (fieldName, capability) => {
    const metadata = getFieldSchema(dataset.name, fieldName);
    if (!metadata) throw new Error(`Field "${fieldName}" is not allowed for dataset "${dataset.name}"`);
    if (capability && !metadata[capability]) {
      throw new Error(`Field "${fieldName}" does not support ${capability}`);
    }
    return metadata;
  };

  for (const filter of plan.filters || []) {
    const metadata = requireField(filter.field, "filterable");
    if (!metadata.operators.includes(filter.operator)) {
      throw new Error(`Operator "${filter.operator}" is not allowed for field "${filter.field}"`);
    }
    if (filter.operator === "in" && !Array.isArray(filter.value)) {
      throw new Error(`Operator "in" requires an array for field "${filter.field}"`);
    }
    if (filter.operator !== "exists" && filter.value === undefined) {
      throw new Error(`Filter value is required for "${filter.field}"`);
    }
  }

  for (const fieldName of plan.groupBy || []) requireField(fieldName, "groupable");
  for (const fieldName of plan.select || []) requireField(fieldName, "selectable");

  for (const metric of plan.metrics || []) {
    if (metric.type !== "count") {
      const metadata = requireField(metric.field, "selectable");
      if (metadata.type !== "number" && !["min", "max"].includes(metric.type)) {
        throw new Error(`Metric "${metric.type}" requires a numeric field`);
      }
    }
  }

  if (plan.timeRange?.field) {
    const metadata = requireField(plan.timeRange.field, "filterable");
    if (metadata.type !== "date") throw new Error("timeRange.field must be a date field");
  }

  if (plan.operation === "aggregate" && !(plan.groupBy?.length || plan.metrics?.length)) {
    throw new Error("aggregate requires groupBy or metrics");
  }

  if (plan.operation === "count" && (
    plan.groupBy?.length || plan.metrics?.length || plan.select?.length || plan.sort?.length
  )) {
    throw new Error("count does not accept groupBy, metrics, select, or sort");
  }

  if (plan.operation === "list" && (plan.groupBy?.length || plan.metrics?.length)) {
    throw new Error("list does not accept groupBy or metrics");
  }

  if (plan.operation === "list" && !plan.select?.length) {
    throw new Error("list requires at least one selected field");
  }

  if (plan.operation === "aggregate" && plan.select?.length) {
    throw new Error("aggregate does not accept select");
  }

  if (plan.operation === "distinct" && plan.groupBy?.length !== 1) {
    throw new Error("distinct requires exactly one groupBy field");
  }

  if (plan.operation === "distinct" && (plan.metrics?.length || plan.select?.length || plan.sort?.length)) {
    throw new Error("distinct does not accept metrics, select, or sort");
  }

  if (getRequiredUnwinds(plan, dataset).length > 1) {
    throw new Error("A single query cannot aggregate across multiple independent array scopes");
  }
}

function buildFilterClauses(filters, dataset) {
  const plain = [];
  const arrayGroups = new Map();

  for (const filter of filters || []) {
    const metadata = getFieldSchema(dataset.name, filter.field);
    const root = metadata?.unwind;
    const nestedInArray = root && metadata.path.startsWith(root + ".");

    if (!nestedInArray) {
      plain.push(buildFilter(metadata, filter));
      continue;
    }

    if (!arrayGroups.has(root)) arrayGroups.set(root, []);
    arrayGroups.get(root).push({ metadata, filter });
  }

  for (const [root, entries] of arrayGroups.entries()) {
    const elementConditions = [];
    for (const { metadata, filter } of entries) {
      const relativePath = metadata.path.slice(root.length + 1);
      elementConditions.push(buildFilter(metadata, filter, relativePath));
    }
    plain.push({
      [root]: {
        $elemMatch: elementConditions.length === 1
          ? elementConditions[0]
          : { $and: elementConditions },
      },
    });
  }

  return plain;
}

function buildFilter(metadata, filter, pathOverride) {
  const path = pathOverride || metadata.path;
  const value = coerceFilterValue(metadata.type, filter.value);

  switch (filter.operator) {
    case "eq": return { [path]: value };
    case "neq": return { [path]: { $ne: value } };
    case "contains":
      return { [path]: { $regex: escapeRegex(String(value)), $options: "i" } };
    case "in":
      return { [path]: { $in: value.map((item) => coerceFilterValue(metadata.type, item)) } };
    case "exists": return { [path]: { $exists: Boolean(filter.value ?? true) } };
    case "gt": return { [path]: { $gt: value } };
    case "gte": return { [path]: { $gte: value } };
    case "lt": return { [path]: { $lt: value } };
    case "lte": return { [path]: { $lte: value } };
    default: throw new Error(`Unsupported filter operator: ${filter.operator}`);
  }
}

function coerceFilterValue(type, value) {
  if (type === "number") {
    const numeric = Number(value);
    if (!Number.isFinite(numeric)) throw new Error(`Expected numeric filter value, got "${value}"`);
    return numeric;
  }
  if (type === "boolean") {
    if (typeof value === "boolean") return value;
    if (String(value).toLowerCase() === "true") return true;
    if (String(value).toLowerCase() === "false") return false;
    throw new Error(`Expected boolean filter value, got "${value}"`);
  }
  if (type === "date") {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) throw new Error(`Expected date filter value, got "${value}"`);
    return date;
  }
  if (type === "mixed") return value;
  return String(value);
}

function getRequiredUnwinds(plan, dataset) {
  const paths = new Set();

  const addForField = (fieldName) => {
    const unwind = getFieldSchema(dataset.name, fieldName)?.unwind;
    if (unwind) paths.add(unwind);
  };

  for (const fieldName of plan.groupBy || []) addForField(fieldName);
  for (const fieldName of plan.select || []) addForField(fieldName);
  for (const metric of plan.metrics || []) if (metric.field) addForField(metric.field);

  return [...paths].sort((a, b) => a.split(".").length - b.split(".").length);
}

function buildGroupId(datasetName, fields) {
  if (!fields.length) return null;
  if (fields.length === 1) {
    return `$${getFieldSchema(datasetName, fields[0]).path}`;
  }

  const id = {};
  for (const fieldName of fields) {
    id[safeGroupKey(fieldName)] = `$${getFieldSchema(datasetName, fieldName).path}`;
  }
  return id;
}

function buildDistinctDocumentCountStages(datasetName, groupFields, metrics) {
  const firstId = { __document: "$_id" };

  if (groupFields.length === 1) {
    firstId.__group = "$" + getFieldSchema(datasetName, groupFields[0]).path;
  } else {
    for (const fieldName of groupFields) {
      firstId[safeGroupKey(fieldName)] = "$" + getFieldSchema(datasetName, fieldName).path;
    }
  }

  const secondId = groupFields.length === 1
    ? "$_id.__group"
    : Object.fromEntries(
      groupFields.map((fieldName) => [
        safeGroupKey(fieldName),
        "$_id." + safeGroupKey(fieldName),
      ]),
    );

  const secondGroup = { _id: secondId };
  for (const metric of metrics) {
    secondGroup[metric.alias || defaultMetricAlias(metric)] = { $sum: 1 };
  }

  return [
    { $group: { _id: firstId } },
    { $group: secondGroup },
  ];
}

function normalizeMetrics(metrics) {
  return metrics?.length ? metrics : [{ type: "count", alias: "count" }];
}

function defaultMetricAlias(metric) {
  if (metric.type === "count") return "count";
  return `${metric.type}_${safeGroupKey(metric.field)}`;
}

function safeGroupKey(value) {
  return String(value).replace(/[^A-Za-z0-9_]/g, "_");
}

function outputFieldName(value) {
  const text = String(value);
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(text) ? text : safeGroupKey(text);
}

function identityFieldForDataset(datasetName) {
  return {
    alerts: "alertId",
    detection_rules: "ruleId",
    ip_assets: "ip",
    mitre_techniques: "techniqueId",
  }[String(datasetName || "")] || null;
}

function withIdentityField(datasetName, selectedFields = []) {
  const identityField = identityFieldForDataset(datasetName);
  const fields = [...new Set((selectedFields || []).map((item) => String(item)))];
  if (identityField && !fields.includes(identityField)) fields.unshift(identityField);
  return fields;
}

function buildDocumentSort(plan) {
  const sort = {};
  for (const item of plan.sort || []) {
    const metadata = getFieldSchema(plan.dataset, item.field);
    if (!metadata?.sortable) throw new Error(`Invalid sort field: ${item.field}`);
    const path = plan.dataset === "alerts" && item.field === "eventTime"
      ? "__socEventTime"
      : metadata.path;
    sort[path] = item.direction === "asc" ? 1 : -1;
  }
  return sort;
}

function buildTimeRangeMatch(datasetName, timeField, timeSchema, bounds) {
  if (datasetName === "alerts" && timeField === "eventTime") {
    const effectiveTime = { $ifNull: ["$eventTime", "$createdAt"] };
    const clauses = [];
    if (bounds.$gte) clauses.push({ $gte: [effectiveTime, bounds.$gte] });
    if (bounds.$lt) clauses.push({ $lt: [effectiveTime, bounds.$lt] });
    if (bounds.$lte) clauses.push({ $lte: [effectiveTime, bounds.$lte] });
    return clauses.length === 1
      ? { $expr: clauses[0] }
      : { $expr: { $and: clauses } };
  }

  return { [timeSchema.path]: bounds };
}

function buildAggregateSort(plan, groupFields, metrics) {
  const allowed = new Set(groupFields);
  for (const metric of metrics) allowed.add(metric.alias || defaultMetricAlias(metric));

  const sort = {};
  for (const item of plan.sort || []) {
    if (!allowed.has(item.field)) {
      throw new Error(`Aggregate sort field "${item.field}" is not a group or metric output`);
    }
    const output = groupFields.includes(item.field) ? outputFieldName(item.field) : item.field;
    sort[output] = item.direction === "asc" ? 1 : -1;
  }

  if (!Object.keys(sort).length && metrics.length) {
    const primary = metrics[0].alias || defaultMetricAlias(metrics[0]);
    sort[primary] = -1;
  }

  return sort;
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

module.exports = {
  compileSocQuery,
  validatePlanFields,
  buildFilter,
  buildFilterClauses,
  buildDistinctDocumentCountStages,
  buildTimeRangeMatch,
  identityFieldForDataset,
  withIdentityField,
  outputFieldName,
};
