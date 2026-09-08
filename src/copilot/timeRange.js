const { settings } = require("../core/config");

function resolveTimeRange(range, {
  now = new Date(),
  timezone = settings.socTimezone || "Asia/Tehran",
  weekStart = settings.socWeekStart || "saturday",
} = {}) {
  if (!range || range.type === "all") {
    return { from: null, to: null, timezone, label: "all time" };
  }

  if (!(now instanceof Date) || Number.isNaN(now.getTime())) {
    throw new Error("Invalid current time");
  }

  if (range.type === "last_n_hours") {
    const value = requirePositiveValue(range.value, "last_n_hours");
    return {
      from: new Date(now.getTime() - value * 60 * 60 * 1000),
      to: now,
      timezone,
      label: `last ${value} hours`,
    };
  }

  if (range.type === "last_n_days") {
    const value = requirePositiveValue(range.value, "last_n_days");
    return {
      from: new Date(now.getTime() - value * 24 * 60 * 60 * 1000),
      to: now,
      timezone,
      label: `last ${value} days`,
    };
  }

  if (range.type === "between") {
    const from = parseDate(range.from, "from");
    const to = parseDate(range.to, "to");
    if (from >= to) throw new Error("timeRange.from must be before timeRange.to");
    return { from, to, timezone, label: "custom range" };
  }

  const today = getLocalDateParts(now, timezone);
  const todayStart = localMidnightToUtc(today, timezone);

  if (range.type === "today") {
    return { from: todayStart, to: now, timezone, label: "today" };
  }

  if (range.type === "yesterday") {
    const previous = shiftLocalDate(today, -1);
    return {
      from: localMidnightToUtc(previous, timezone),
      to: todayStart,
      timezone,
      label: "yesterday",
    };
  }

  const weekday = localWeekday(today);
  const weekStartIndex = getWeekStartIndex(weekStart);
  const daysSinceWeekStart = (weekday - weekStartIndex + 7) % 7;
  const weekStartDate = shiftLocalDate(today, -daysSinceWeekStart);
  const thisWeekStart = localMidnightToUtc(weekStartDate, timezone);

  if (range.type === "this_week") {
    return { from: thisWeekStart, to: now, timezone, label: "this week" };
  }

  if (range.type === "previous_week") {
    const previousWeekStart = shiftLocalDate(weekStartDate, -7);
    return {
      from: localMidnightToUtc(previousWeekStart, timezone),
      to: thisWeekStart,
      timezone,
      label: "previous week",
    };
  }

  throw new Error(`Unsupported time range: ${range.type}`);
}

function requirePositiveValue(value, type) {
  const numeric = Number(value);
  if (!Number.isInteger(numeric) || numeric <= 0) {
    throw new Error(`${type} requires a positive integer value`);
  }
  return numeric;
}

function parseDate(value, label) {
  const date = new Date(value);
  if (!value || Number.isNaN(date.getTime())) {
    throw new Error(`Invalid timeRange.${label}`);
  }
  return date;
}

function getLocalDateParts(date, timezone) {
  const formatter = new Intl.DateTimeFormat("en-CA", {
    timeZone: timezone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  });

  const parts = Object.fromEntries(
    formatter.formatToParts(date)
      .filter((part) => part.type !== "literal")
      .map((part) => [part.type, Number(part.value)]),
  );

  return { year: parts.year, month: parts.month, day: parts.day };
}

function localMidnightToUtc(parts, timezone) {
  const targetUtc = Date.UTC(parts.year, parts.month - 1, parts.day, 0, 0, 0);
  let candidate = targetUtc;

  for (let attempt = 0; attempt < 3; attempt += 1) {
    const offset = getTimezoneOffsetMs(new Date(candidate), timezone);
    candidate = targetUtc - offset;
  }

  return new Date(candidate);
}

function getTimezoneOffsetMs(date, timezone) {
  const formatter = new Intl.DateTimeFormat("en-US", {
    timeZone: timezone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  });

  const values = Object.fromEntries(
    formatter.formatToParts(date)
      .filter((part) => part.type !== "literal")
      .map((part) => [part.type, Number(part.value)]),
  );

  const asUtc = Date.UTC(
    values.year,
    values.month - 1,
    values.day,
    values.hour,
    values.minute,
    values.second,
  );

  return asUtc - Math.floor(date.getTime() / 1000) * 1000;
}

function shiftLocalDate(parts, days) {
  const date = new Date(Date.UTC(parts.year, parts.month - 1, parts.day + days));
  return {
    year: date.getUTCFullYear(),
    month: date.getUTCMonth() + 1,
    day: date.getUTCDate(),
  };
}

function localWeekday(parts) {
  return new Date(Date.UTC(parts.year, parts.month - 1, parts.day)).getUTCDay();
}

function getWeekStartIndex(value) {
  const normalized = String(value || "saturday").trim().toLowerCase();
  const days = {
    sunday: 0,
    monday: 1,
    tuesday: 2,
    wednesday: 3,
    thursday: 4,
    friday: 5,
    saturday: 6,
  };
  if (!(normalized in days)) throw new Error("Unsupported SOC_WEEK_START: " + value);
  return days[normalized];
}

module.exports = {
  resolveTimeRange,
  getLocalDateParts,
  localMidnightToUtc,
  getWeekStartIndex,
};
