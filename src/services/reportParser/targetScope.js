const STAGE_VERSION = "docx-v9";


function enhanceReportRecordV9(report) {
  if (!report || typeof report !== "object") return report;

  const target = report.target || {};
  const rawOrganization = clean(target.rawOrganization || target.organization);
  const rawIp = clean(target.rawIp);
  const tableReference = extractTableReference(rawIp) || extractTableReference(rawOrganization);
  const scope = classifyScope(rawOrganization);
  const assets = normalizedAssets(report.affectedSystems);
  const assetOrganizations = unique(assets.map((item) => item.organization));
  const assetIps = unique(assets.map((item) => item.ip));
  const completePairs = uniquePairs(assets.filter((item) => item.organization && item.ip));
  const warnings = new Set(report.extraction?.warnings || []);

  const nextTarget = {
    mode: inferDefaultMode(target),
    scopeType: null,
    scopeName: null,
    organization: target.organization || null,
    ip: target.ip || null,
    rawOrganization: rawOrganization || null,
    rawIp: target.rawIp || null,
    tableReference: tableReference || null,
  };

  if (tableReference) {
    if (completePairs.length === 1 && assetOrganizations.length === 1 && assetIps.length === 1) {
      nextTarget.mode = "single";
      nextTarget.organization = completePairs[0].organization;
      nextTarget.ip = completePairs[0].ip;
      warnings.add("target_resolved_from_table");
      clearExpectedTableWarnings(warnings);
    } else if (assets.length > 0) {
      nextTarget.mode = scope.type ? "scope" : "multi_target";
      nextTarget.scopeType = scope.type;
      nextTarget.scopeName = scope.type ? rawOrganization : null;
      nextTarget.organization = null;
      nextTarget.ip = null;
      warnings.add(scope.type ? "scope_target_detected" : "multi_target_report");
      warnings.add("target_assets_resolved_from_table");
      clearExpectedTableWarnings(warnings);
    } else {
      nextTarget.mode = scope.type ? "scope" : "multi_target";
      nextTarget.scopeType = scope.type;
      nextTarget.scopeName = scope.type ? rawOrganization : null;
      nextTarget.organization = null;
      nextTarget.ip = null;
      warnings.add(scope.type ? "scope_target_detected" : "multi_target_report");
      warnings.add("target_table_reference_unresolved");
      warnings.delete("invalid_or_masked_target_ip");
      warnings.delete("target_ip_referenced_in_table");
      if (scope.type) warnings.delete("missing_target_ip");
    }
  }

  report.target = nextTarget;
  report.extraction = {
    ...(report.extraction || {}),
    parserVersion: STAGE_VERSION,
    warnings: [...warnings],
    organizationMismatch: tableReference && nextTarget.mode !== "single"
      ? false
      : Boolean(report.extraction?.organizationMismatch),
    ipMismatch: tableReference && nextTarget.mode !== "single"
      ? false
      : Boolean(report.extraction?.ipMismatch),
  };

  return report;
}

function clearExpectedTableWarnings(warnings) {
  warnings.delete("invalid_or_masked_target_ip");
  warnings.delete("target_ip_referenced_in_table");
  warnings.delete("missing_target_ip");
  warnings.delete("missing_target_organization");
  warnings.delete("target_organization_differs_from_affected_system");
  warnings.delete("target_ip_differs_from_affected_system");
  warnings.delete("target_ip_derived_from_affected_system");
}

function inferDefaultMode(target = {}) {
  return target.organization || target.ip ? "single" : "unknown";
}

function extractTableReference(value) {
  const text = normalize(value);
  if (!text) return null;
  const match = text.match(/(?:^|\s)(جدول\s*(?:شماره\s*)?[0-9]+)(?:\s|$)/);
  return match ? match[1].replace(/\s+/g, " ").trim() : null;
}

function classifyScope(value) {
  const text = normalize(value);
  if (!text) return { type: null };
  if (/(?:^|\s)حوزه(?:\s|$)/.test(text)) return { type: "sector" };
  if (/(?:دستگاه(?:‌|\s)*(?:های|ها)|سازمان(?:‌|\s)*(?:های|ها)|مجموعه(?:‌|\s)*(?:های|ها)|شرکت(?:‌|\s)*(?:های|ها)).*(?:اجرایی|تابعه|مرتبط|هدف)?/.test(text)) {
    return { type: "organization_group" };
  }
  if (/^(?:استان|شهرستان|منطقه)\s+/.test(text)) return { type: "geographic" };
  return { type: null };
}

function normalizedAssets(value) {
  return (Array.isArray(value) ? value : [])
    .map((item) => ({
      organization: clean(item?.organization),
      ip: clean(item?.ip),
    }))
    .filter((item) => item.organization || item.ip);
}

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function uniquePairs(values) {
  const map = new Map();
  for (const item of values) {
    const key = `${item.organization}|${item.ip}`;
    if (!map.has(key)) map.set(key, item);
  }
  return [...map.values()];
}

function clean(value) {
  const text = String(value || "").replace(/\s+/g, " ").trim();
  return text || null;
}

function normalize(value) {
  return String(value || "")
    .replace(/[۰-۹]/g, (digit) => String("۰۱۲۳۴۵۶۷۸۹".indexOf(digit)))
    .replace(/ي/g, "ی")
    .replace(/ك/g, "ک")
    .replace(/[‌\u200c\u200f\u202a-\u202e]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

module.exports = {
  STAGE_VERSION,
  enhanceReportRecordV9,
  extractTableReference,
  classifyScope,
};
