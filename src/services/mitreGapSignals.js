const GAP_SIGNAL_VERSION = 1;

const GAP_SIGNALS = [
  signal("T1056.001", "keylogging-title-v1", 0.99, (ctx) =>
    /\bkeylog(?:ger|ging)?\b|\bkeystroke(?:s)?\b/i.test(ctx.title)),

  signal("T1003.001", "lsass-credential-dump-title-v1", 0.99, (ctx) =>
    /\blsass(?:\.exe)?\b/i.test(ctx.title)
      && /\b(?:dump|memory|credential|mimikatz|sekurlsa)\b/i.test(ctx.title)),

  signal("T1003.002", "sam-credential-dump-title-v1", 0.99, (ctx) =>
    /\bSAM\b/.test(ctx.title)
      && /\b(?:dump|credential|hash|secret|secrets)\b/i.test(ctx.title)),

  signal("T1003.003", "ntds-credential-dump-title-v1", 0.99, (ctx) =>
    /\bNTDS(?:\.dit)?\b/i.test(ctx.title)),

  signal("T1003.004", "lsa-secrets-title-v1", 0.99, (ctx) =>
    /\bLSA\s+Secrets?\b/i.test(ctx.title)),

  signal("T1003.005", "cached-domain-credentials-title-v1", 0.99, (ctx) =>
    /\b(?:cached domain credentials?|mscash|dcc2)\b/i.test(ctx.title)),

  signal("T1003.006", "dcsync-title-v1", 0.99, (ctx) =>
    /\bdcsync\b/i.test(ctx.title)),

  signal("T1003.008", "unix-password-file-title-v1", 0.99, (ctx) =>
    /\/etc\/(?:passwd|shadow)\b/i.test(ctx.title)),

  signal("T1047", "wmi-execution-title-v1", 0.97, (ctx) =>
    /\b(?:WMI|WMIC)\b/i.test(ctx.title)
      && /\b(?:exec(?:ute|ution)?|process|command|remote|spawn)\b/i.test(ctx.title)),

  signal("T1053.003", "cron-title-v1", 0.98, (ctx) =>
    /\b(?:cron|crontab)\b/i.test(ctx.title)
      && /\b(?:job|task|schedule|scheduled|command|persistence)\b/i.test(ctx.title)),

  signal("T1053.005", "scheduled-task-title-v1", 0.99, (ctx) =>
    /\bschtasks(?:\.exe)?\b|\bscheduled tasks?\b/i.test(ctx.title)),

  signal("T1055.001", "dll-injection-title-v1", 0.99, (ctx) =>
    /\b(?:DLL|dynamic[- ]link library) injection\b/i.test(ctx.title)),

  signal("T1055.002", "pe-injection-title-v1", 0.99, (ctx) =>
    /\b(?:PE|portable executable) injection\b/i.test(ctx.title)),

  signal("T1055.003", "thread-execution-hijack-title-v1", 0.99, (ctx) =>
    /\bthread execution hijack(?:ing)?\b/i.test(ctx.title)),

  signal("T1055.004", "apc-injection-title-v1", 0.99, (ctx) =>
    /\bAPC injection\b/i.test(ctx.title)),

  signal("T1055.013", "process-doppelganging-title-v1", 0.99, (ctx) =>
    /\bprocess doppelg(?:a|ä)nging\b/i.test(ctx.title)),

  signal("T1055.015", "listplanting-title-v1", 0.99, (ctx) =>
    /\blistplanting\b/i.test(ctx.title)),

  signal("T1016.001", "internet-connection-discovery-title-v1", 0.98, (ctx) =>
    /\bwhat(?:\s+is|s)?\s*my\s*ip\b|\bwhatismyip\b|\bipify\b|\bip-api\.com\b|\bifconfig\.me\b|\bicanhazip\b|\bcheckip\.amazonaws\.com\b/i.test(ctx.title)),

  signal("T1027.006", "html-smuggling-title-v1", 0.99, (ctx) =>
    /\bHTML smuggling\b/i.test(ctx.title)),

  signal("T1027.017", "svg-smuggling-title-v1", 0.99, (ctx) =>
    /\bSVG smuggling\b/i.test(ctx.title)),

  signal("T1027.018", "invisible-unicode-title-v1", 0.99, (ctx) =>
    /\binvisible unicode\b/i.test(ctx.title)),

  signal("T1036.002", "rtl-override-title-v1", 0.99, (ctx) =>
    /\b(?:right[- ]to[- ]left override|RLO character)\b/i.test(ctx.title)),

  signal("T1036.006", "space-after-filename-title-v1", 0.99, (ctx) =>
    /\bspace after filename\b/i.test(ctx.title)),

  signal("T1036.007", "double-extension-title-v1", 0.99, (ctx) =>
    /\bdouble (?:file )?extension\b/i.test(ctx.title)),

  signal("T1036.012", "browser-fingerprint-title-v1", 0.98, (ctx) =>
    /\bbrowser fingerprint(?:ing)?\b/i.test(ctx.title)),
];

function signal(techniqueId, signalId, confidence, predicate) {
  return { techniqueId, signalId, confidence, predicate };
}

function findGapSignals(rule = {}, uncoveredTechniqueIds = null) {
  const allowed = uncoveredTechniqueIds instanceof Set ? uncoveredTechniqueIds : null;
  const ctx = {
    title: String(rule.title || ""),
    sourceFile: String(rule.sourceFile || "").toLowerCase(),
    classtype: String(rule.classtype || "").toLowerCase(),
    protocol: String(rule.protocol || "").toLowerCase(),
    metadata: String(rule.parsedRule?.metadata || ""),
    references: Array.isArray(rule.parsedRule?.references)
      ? rule.parsedRule.references.map(String)
      : [],
  };

  return GAP_SIGNALS
    .filter((entry) => !allowed || allowed.has(entry.techniqueId))
    .filter((entry) => entry.predicate(ctx))
    .map((entry) => ({
      techniqueId: entry.techniqueId,
      signalId: entry.signalId,
      confidence: entry.confidence,
      evidence: ["title=explicit-technique-indicator"],
    }));
}

module.exports = {
  GAP_SIGNAL_VERSION,
  GAP_SIGNALS,
  findGapSignals,
};
