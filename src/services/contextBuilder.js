const { settings } = require("../core/config");
const { sanitizeText } = require("../core/logging");

const RELEVANT_FIELDS = [
  "rule_name", "severity", "host", "user", "process_name", "command_line",
  "parent_process", "raw_log", "timestamp",
];

function toStringValue(value) {
  if (value === null || value === undefined) return null;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function buildContext(rawIncident) {
  const context = {};

  for (const field of RELEVANT_FIELDS) {
    const val = rawIncident[field];
    let textVal = toStringValue(val);
    if (textVal) textVal = sanitizeText(textVal);
    if (field === "raw_log" && textVal) textVal = textVal.slice(0, settings.maxRawLogChars);
    context[field] = textVal;
  }

  return context;
}

module.exports = { buildContext };
