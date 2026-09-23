const crypto = require('node:crypto');

// Accepts the payload shapes Splunk and other SIEMs send: a single alert, an array,
// or an envelope with `alerts` / `results`.
function normalizeAlertPayload(payload) {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.alerts)) return payload.alerts;
  if (Array.isArray(payload?.results)) return payload.results;
  if (payload && typeof payload === 'object') return [payload];
  return [];
}

function getAlertId(payload) {
  return String(
    payload?.alertId ||
      payload?.alert_id ||
      payload?.event_id ||
      payload?.sid ||
      payload?.id ||
      crypto.randomUUID(),
  );
}

function getAlertSource(payload) {
  return String(
    payload?.source ||
      payload?.sourcetype ||
      payload?.index ||
      payload?.app ||
      'splunk',
  );
}

function getAlertSeverity(payload) {
  return payload?.severity ? String(payload.severity).toLowerCase() : undefined;
}

module.exports = {
  normalizeAlertPayload,
  getAlertId,
  getAlertSource,
  getAlertSeverity,
};
