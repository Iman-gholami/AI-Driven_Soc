const base = require("./docxBase");

const STAGE_VERSION = "docx-v4";


function enhanceReportRecord(report, parsed = {}) {
  const tables = Array.isArray(parsed.tables) ? parsed.tables : [];
  const combinedText = [report.title, report.description, report.fullText].filter(Boolean).join("\n");

  if (!report.finding || report.finding.type === "unknown") {
    report.finding = classifyFindingV4(combinedText);
    report.vulnerability = vulnerabilityFromFindingV4(report.finding);
  }

  const improvedSystems = extractAffectedSystemsV4(tables);
  if (improvedSystems.length > (report.affectedSystems || []).length) {
    report.affectedSystems = improvedSystems;
  }

  const tableRecommendations = extractRecommendationsFromTables(tables);
  report.recommendations = uniqueText([
    ...(Array.isArray(report.recommendations) ? report.recommendations : []),
    ...tableRecommendations,
  ]);

  const phishingInfrastructure = extractPhishingInfrastructure(tables);
  report.phishingInfrastructure = phishingInfrastructure;
  report.indicators = buildIndicators(phishingInfrastructure);

  report.affectedCves = [...new Set(
    (report.affectedSystems || []).flatMap((item) => Array.isArray(item.cves) ? item.cves : []),
  )];

  const affectedIps = [...new Set((report.affectedSystems || []).map((item) => item.ip).filter(Boolean))];
  const warnings = new Set(report.extraction?.warnings || []);

  if (!report.target?.ip && affectedIps.length === 1) {
    report.target.ip = affectedIps[0];
    warnings.add("target_ip_derived_from_affected_system");
    warnings.delete("missing_target_ip");
  }

  if (/^جدول\s*\d+$/i.test(String(report.target?.rawIp || "").trim())) {
    warnings.delete("invalid_or_masked_target_ip");
    warnings.add("target_ip_referenced_in_table");
  }

  if (report.finding?.type !== "unknown") warnings.delete("unknown_finding_type");

  report.extraction = {
    ...(report.extraction || {}),
    parserVersion: STAGE_VERSION,
    warnings: [...warnings],
  };

  return report;
}

function classifyFindingV4(value) {
  const text = normalize(value).toLowerCase();
  const catalog = [
    {
      pattern: /phishing|فیشینگ|تله\s*گذاری/,
      type: "phishing",
      name: "Phishing",
      category: "social_engineering",
      cwe: null,
    },
    {
      pattern: /web\s*[- ]?shell|وب\s*شل|بارگذاری\s+وب\s*شل/,
      type: "webshell_compromise",
      name: "Web Shell Compromise",
      category: "web_intrusion",
      cwe: null,
    },
    {
      pattern: /\b(?:zbot|zeus)\b/,
      type: "malware_zeus",
      name: "Zbot / Zeus",
      category: "malware",
      cwe: null,
    },
    {
      pattern: /اخذ\s+دسترسی[\s\S]{0,80}اجرای\s+(?:دستور|کد)[\s\S]{0,40}راه\s*دور|arbitrary\s+remote\s+code\s+execution|remote\s+(?:command|code)\s+execution/,
      type: "remote_access_command_execution",
      name: "Remote Access and Command Execution",
      category: "intrusion",
      cwe: null,
    },
  ];

  return catalog.find((item) => item.pattern.test(text)) || {
    type: "unknown",
    name: null,
    category: "unknown",
    cwe: null,
  };
}

function vulnerabilityFromFindingV4(finding) {
  if (!finding || finding.type === "unknown") {
    return { name: null, normalizedName: "unknown", category: "unknown", cwe: null };
  }
  return { name: null, normalizedName: "unknown", category: "unknown", cwe: null };
}

function extractAffectedSystemsV4(tables) {
  const output = [];

  for (const table of tables || []) {
    if (!Array.isArray(table) || table.length < 2) continue;
    const headerIndex = findHeaderRow(table, { allowPhishing: false });
    if (headerIndex < 0) continue;

    const headerRow = table[headerIndex];
    const headers = headerRow.map(normalizeHeaderV4);
    if (headers.some((key) => key && key.startsWith("phishing_"))) continue;

    for (const row of table.slice(headerIndex + 1)) {
      if (!Array.isArray(row) || !row.some(Boolean)) continue;
      const normalizedHeaders = row.map(normalizeHeaderV4);
      if (normalizedHeaders.filter(Boolean).length >= 2) continue;

      const rowText = row.join(" ");
      const urls = extractUrls(rowText);
      if (urls.length && row.length <= 2 && output.length) {
        const previous = output[output.length - 1];
        previous.additionalUrls = [...new Set([...(previous.additionalUrls || []), ...urls])];
        continue;
      }

      const item = {};
      headers.forEach((key, index) => {
        if (!key || row[index] === undefined) return;
        item[key] = clean(row[index]) || null;
      });

      if (item.ip) item.rawIp = item.ip;
      item.ip = base.normalizeFirstIp(item.ip || rowText);
      if (!item.url && urls.length) item.url = urls[0];
      if (item.url && !item.domain) item.domain = domainFromUrl(item.url);
      if (item.port) item.port = base.parsePort(item.port);
      if (!item.port && item.service) item.port = base.parsePort(item.service);
      if (item.packetCount) item.packetCount = base.parseInteger(item.packetCount);
      if (item.participantIpCount) item.participantIpCount = base.parseInteger(item.participantIpCount);
      if (item.trafficVolumeRaw) item.trafficVolumeBytes = base.parseTrafficBytes(item.trafficVolumeRaw);

      const eventDate = base.parseJalaliDate(item.eventDateRaw);
      const cves = base.extractCves([item.reportedFinding, rowText].filter(Boolean).join("\n"));

      const normalizedItem = {
        method: item.method || null,
        parameter: item.parameter || null,
        url: item.url || null,
        additionalUrls: [],
        domain: item.domain || null,
        organization: item.organization || null,
        ip: item.ip || null,
        rawIp: item.rawIp || null,
        port: item.port || null,
        service: item.service || null,
        packetCount: item.packetCount || null,
        participantIpCount: item.participantIpCount || null,
        trafficVolumeRaw: item.trafficVolumeRaw || null,
        trafficVolumeBytes: item.trafficVolumeBytes || null,
        eventDateRaw: item.eventDateRaw || null,
        eventYear: eventDate.year || null,
        eventMonth: eventDate.month || null,
        eventDay: eventDate.day || null,
        timeRange: item.timeRange || null,
        softwareVersion: item.softwareVersion || null,
        reportedFinding: item.reportedFinding || null,
        cves,
      };

      const meaningful = Object.entries(normalizedItem).some(([key, value]) => {
        if (key === "additionalUrls" || key === "cves") return Array.isArray(value) && value.length > 0;
        return Boolean(value);
      });
      if (meaningful) output.push(normalizedItem);
    }
  }

  return output;
}

function extractRecommendationsFromTables(tables) {
  const recommendations = [];
  for (const table of tables || []) {
    const cells = table.flat().map(clean).filter(Boolean);
    const start = cells.findIndex((cell) => /^راهکار/.test(normalize(cell)));
    if (start < 0) continue;

    for (const cell of cells.slice(start + 1)) {
      const normalized = normalize(cell);
      if (/^منابع$/.test(normalized)) break;
      if (/^(جدول|شکل)\s*\d*/.test(normalized)) continue;
      if (/^(راهکار|v|o)$/.test(normalized)) continue;
      const cleaned = cleanBullet(cell);
      if (cleaned.length >= 8) recommendations.push(cleaned);
    }
  }
  return uniqueText(recommendations);
}

function extractPhishingInfrastructure(tables) {
  const output = [];

  for (const table of tables || []) {
    const headerIndex = findHeaderRow(table, { allowPhishing: true, requirePhishing: true });
    if (headerIndex < 0) continue;
    const headers = table[headerIndex].map(normalizeHeaderV4);

    for (const row of table.slice(headerIndex + 1)) {
      if (!Array.isArray(row) || !row.some(Boolean)) continue;
      const item = {};
      headers.forEach((key, index) => {
        if (!key || !key.startsWith("phishing_") || row[index] === undefined) return;
        item[key] = clean(row[index]);
      });

      const rawUrl = item.phishing_url || null;
      const rawIp = item.phishing_ip || null;
      const ip = base.normalizeFirstIp(rawIp);
      let url = rawUrl;
      let domain = null;
      if (rawUrl) {
        const extracted = extractUrls(rawUrl);
        if (extracted.length) {
          url = extracted[0];
          domain = domainFromUrl(url);
        } else if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(rawUrl.trim())) {
          domain = rawUrl.trim().toLowerCase();
        }
      }

      if (url || domain || ip || item.phishing_title) {
        output.push({
          url: url || null,
          domain,
          ip,
          rawIp: rawIp || null,
          pageTitle: item.phishing_title || null,
        });
      }
    }
  }

  return output;
}

function buildIndicators(phishingInfrastructure) {
  const rows = [];
  for (const item of phishingInfrastructure || []) {
    if (item.url) rows.push({ type: "url", role: "phishing", value: item.url });
    if (item.domain) rows.push({ type: "domain", role: "phishing", value: item.domain });
    if (item.ip) rows.push({ type: "ip", role: "phishing", value: item.ip });
  }
  const seen = new Set();
  return rows.filter((item) => {
    const key = `${item.type}|${item.role}|${item.value}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function findHeaderRow(table, { allowPhishing = true, requirePhishing = false } = {}) {
  let best = { index: -1, score: -1, phishing: false };
  table.forEach((row, index) => {
    const keys = row.map(normalizeHeaderV4).filter(Boolean);
    const phishing = keys.some((key) => key.startsWith("phishing_"));
    const assetIdentity = keys.some((key) => ["ip", "organization", "domain", "url"].includes(key));
    const score = keys.length;
    if (requirePhishing && !phishing) return;
    if (!allowPhishing && phishing) return;
    if (!requirePhishing && !assetIdentity) return;
    if (score >= 2 && score > best.score) best = { index, score, phishing };
  });
  return best.index;
}

function normalizeHeaderV4(value) {
  const text = normalize(value);
  if (!text) return null;
  if (/فیشینگ/.test(text)) {
    if (/domain|url|دامنه|آدرس/.test(text)) return "phishing_url";
    if (/\bip\b|آی\s*پی/.test(text)) return "phishing_ip";
    if (/عنوان|title/.test(text)) return "phishing_title";
  }
  if (/^(متد|method)$/.test(text)) return "method";
  if (/پارامتر|parameter/.test(text)) return "parameter";
  if (/مسیر.*(بهره|دسترسی|وب\s*شل)|url|آدرس.*وب|نشانی.*وب|webmail/.test(text)) return "url";
  if (/دامنه|domain/.test(text)) return "domain";
  if (/نام.*سازمان|organization/.test(text)) return "organization";
  if (/آدرس.*سازمان|آدرس.*ip|آدرس.*آی|ip\s*سازمان|آدرس\s*سازمانی|^ip$/.test(text)) return "ip";
  if (/^پورت$|port/.test(text)) return "port";
  if (/نسخه.*(routeros|نرم|سرویس|آسیب)|software.*version|^نسخه$/.test(text)) return "softwareVersion";
  if (/^(سرویس(?: udp)?|service)$/.test(text)) return "service";
  if (/مجموع.*بسته|تعداد.*بسته|packet/.test(text)) return "packetCount";
  if (/تعداد.*ip.*(شرکت|مشارکت)|participant.*ip/.test(text)) return "participantIpCount";
  if (/حجم.*ترافیک|traffic.*volume/.test(text)) return "trafficVolumeRaw";
  if (/^تاریخ$|تاریخ.*رخداد|^زمان$|event.*date/.test(text)) return "eventDateRaw";
  if (/بازه.*زمان|time.*range/.test(text)) return "timeRange";
  if (/نوع.*آسیب|نمونه.*آسیب|نمونه.*شناسه|شناسه.*آسیب|آسیب پذیری|finding/.test(text)) return "reportedFinding";
  return null;
}

function extractUrls(value) {
  const matches = String(value || "").match(/https?:\/\/[^\s<>"']+/gi) || [];
  return [...new Set(matches.map((item) => item.replace(/[),.;]+$/, "")))];
}

function domainFromUrl(value) {
  try {
    return new URL(String(value)).hostname || null;
  } catch (_) {
    return null;
  }
}

function cleanBullet(value) {
  return clean(value)
    .replace(/^[•▪◦\-–—]+\s*/, "")
    .replace(/^[vo]\s+/i, "")
    .trim();
}

function uniqueText(values) {
  const seen = new Set();
  const output = [];
  for (const value of values || []) {
    const cleaned = clean(value);
    const key = normalize(cleaned);
    if (!cleaned || seen.has(key)) continue;
    seen.add(key);
    output.push(cleaned);
  }
  return output;
}

function normalize(value) {
  return base.normalizeLabel(String(value || ""));
}

function clean(value) {
  return base.normalizeWhitespace(String(value || ""));
}

module.exports = {
  STAGE_VERSION,
  enhanceReportRecord,
  classifyFindingV4,
  extractAffectedSystemsV4,
  extractRecommendationsFromTables,
  extractPhishingInfrastructure,
  buildIndicators,
  normalizeHeaderV4,
};
