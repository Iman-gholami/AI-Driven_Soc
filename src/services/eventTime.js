const EVENT_TIME_FIELDS = [
  "eventTime",
  "event_time",
  "timestamp",
  "@timestamp",
  "_time",
  "time",
];

function resolveAlertEventTime(rawEvent, fallback = new Date()) {
  for (const field of EVENT_TIME_FIELDS) {
    const value = getPathValue(rawEvent, field);
    const parsed = parseEventTimeValue(value);
    if (parsed) return parsed;
  }

  const safeFallback = fallback instanceof Date ? fallback : new Date(fallback);
  return Number.isNaN(safeFallback.getTime()) ? new Date() : safeFallback;
}

function parseEventTimeValue(value) {
  if (value === null || value === undefined || value === "") return null;

  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? null : value;
  }

  if (typeof value === "number") {
    return parseEpoch(value);
  }

  const text = String(value).trim();
  if (!text) return null;

  if (/^-?\d+(?:\.\d+)?$/.test(text)) {
    const numeric = Number(text);
    return Number.isFinite(numeric) ? parseEpoch(numeric) : null;
  }

  const parsed = new Date(text);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function parseEpoch(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return null;

  const absolute = Math.abs(numeric);
  const milliseconds = absolute >= 1e12
    ? numeric
    : numeric * 1000;

  const parsed = new Date(milliseconds);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function getPathValue(object, path) {
  if (!object || typeof object !== "object") return undefined;
  if (Object.prototype.hasOwnProperty.call(object, path)) return object[path];

  let current = object;
  for (const segment of String(path).split(".")) {
    if (!current || typeof current !== "object") return undefined;
    current = current[segment];
  }
  return current;
}

module.exports = {
  EVENT_TIME_FIELDS,
  resolveAlertEventTime,
  parseEventTimeValue,
};
