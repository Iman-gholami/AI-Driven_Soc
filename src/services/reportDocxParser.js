const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const path = require("node:path");
const { execFile } = require("node:child_process");
const { promisify } = require("node:util");
const { normalizeIpv4 } = require("./ipExtractor");

const execFileAsync = promisify(execFile);
const PARSER_VERSION = "docx-v3";

async function parseDocxReport(filePath, { yearHint } = {}) {
  const absolutePath = path.resolve(filePath);
  if (path.extname(absolutePath).toLowerCase() !== ".docx") {
    throw new Error("Only .docx files are supported");
  }

  const [stat, buffer, xml] = await Promise.all([
    fs.stat(absolutePath),
    fs.readFile(absolutePath),
    extractDocumentXml(absolutePath),
  ]);

  const parsed = parseWordXml(xml);
  const report = extractReportRecord(parsed, { yearHint });
  const sha256 = crypto.createHash("sha256").update(buffer).digest("hex");

  return {
    ...report,
    source: {
      filename: path.basename(absolutePath),
      relativePath: path.basename(absolutePath),
      sha256,
      sizeBytes: stat.size,
      importedAt: new Date(),
    },
  };
}

async function extractDocumentXml(filePath) {
  try {
    const { stdout } = await execFileAsync(
      "unzip",
      ["-p", filePath, "word/document.xml"],
      { maxBuffer: 32 * 1024 * 1024, encoding: "utf8" },
    );
    if (!stdout || !stdout.includes("<w:document")) {
      throw new Error("word/document.xml is missing or invalid");
    }
    return stdout;
  } catch (error) {
    const detail = error?.code === "ENOENT"
      ? "The local 'unzip' command is required to parse DOCX files"
      : String(error?.message || error);
    throw new Error(`Unable to read DOCX: ${detail}`);
  }
}

function parseWordXml(xml) {
  const documentXml = String(xml || "");
  const tables = [...documentXml.matchAll(/<w:tbl\b[\s\S]*?<\/w:tbl>/g)]
    .map((match) => parseTableXml(match[0]))
    .filter((table) => table.length);

  const withoutTables = documentXml.replace(/<w:tbl\b[\s\S]*?<\/w:tbl>/g, " ");
  const paragraphs = [...withoutTables.matchAll(/<w:p\b[\s\S]*?<\/w:p>/g)]
    .map((match) => normalizeWhitespace(extractText(match[0])))
    .filter(Boolean);

  return { paragraphs, tables };
}

function parseTableXml(tableXml) {
  return [...String(tableXml || "").matchAll(/<w:tr\b[\s\S]*?<\/w:tr>/g)]
    .map((rowMatch) => [...rowMatch[0].matchAll(/<w:tc\b[\s\S]*?<\/w:tc>/g)]
      .map((cellMatch) => normalizeWhitespace(extractText(cellMatch[0])))
      .filter((value, index, cells) => value || cells.length > 1))
    .filter((cells) => cells.length);
}

function extractText(fragment) {
  const pieces = [];
  const tokenRegex = /<w:t(?:\s[^>]*)?>([\s\S]*?)<\/w:t>|<w:tab\s*\/\s*>|<w:br(?:\s[^>]*)?\/\s*>/g;
  let match;
  while ((match = tokenRegex.exec(String(fragment || "")))) {
    if (match[1] !== undefined) pieces.push(decodeXml(match[1]));
    else pieces.push(" ");
  }
  return pieces.join("");
}

function extractReportRecord(parsed, { yearHint } = {}) {
  const paragraphs = Array.isArray(parsed?.paragraphs) ? parsed.paragraphs : [];
  const tables = Array.isArray(parsed?.tables) ? parsed.tables : [];
  const fieldMap = collectFieldMap(tables);
  const flatText = buildFlatText(paragraphs, tables);
  const warnings = [];

  const title = paragraphs[0] || firstUsefulTableText(tables) || "Untitled report";
  const reportDateRaw = firstField(fieldMap, flatText, ["تاریخ ارائه گزارش", "تاریخ گزارش"]);
  const reportNumber = firstField(fieldMap, flatText, ["شماره گزارش"]);
  const provider = firstField(fieldMap, flatText, ["ارائه کننده گزارش", "ارائه‌کننده گزارش"]);
  const contact = firstField(fieldMap, flatText, ["اطلاعات تماس", "شماره تماس"]);
  const targetOrganization = firstField(fieldMap, flatText, ["سازمان هدف", "نام سازمان هدف"]);
  const targetIpRaw = firstField(fieldMap, flatText, ["آدرس IP", "آدرس آی پی", "آدرس آی‌پی"]);
  let targetIp = normalizeFirstIp(targetIpRaw);
  const severityRaw = firstField(fieldMap, flatText, ["شدت رخداد", "شدت حادثه", "امتیاز شدت"]);
  const severityScore = parseScore(severityRaw);
  const urgencyRaw = firstField(fieldMap, flatText, ["فوریت اقدام", "فوریت رخداد", "فوریت حادثه"]);
  const effect = firstField(fieldMap, flatText, ["اثر رخداد", "اثر حادثه"]);

  const date = parseJalaliDate(reportDateRaw, yearHint);
  if (!date.year && yearHint) date.year = Number(yearHint);
  if (yearHint && date.year && Number(yearHint) !== date.year) {
    warnings.push(`report_year_mismatch:${date.year}:${Number(yearHint)}`);
  }

  const affectedSystems = extractAffectedSystems(tables);
  const affectedIps = [...new Set(affectedSystems.map((item) => item.ip).filter(Boolean))];
  if (!targetIp && affectedIps.length === 1) {
    targetIp = affectedIps[0];
    warnings.push("target_ip_derived_from_affected_system");
  } else if (targetIpRaw && !targetIp) {
    warnings.push("invalid_or_masked_target_ip");
  }

  const description = extractSectionByHeadings(
    paragraphs,
    ["شرح رخداد", "شرح حادثه"],
    [/^جمع\s*بندی$/, /^راهکار/, /^منابع$/],
  );
  const conclusion = extractSectionByHeadings(
    paragraphs,
    ["جمع‌بندی", "جمع بندی"],
    [/^راهکار/, /^منابع$/],
  );
  const recommendations = extractRecommendations(paragraphs);
  const titleFinding = classifyFinding(title);
  const finding = titleFinding.type !== "unknown" ? titleFinding : classifyFinding(description);
  const vulnerability = vulnerabilityFromFinding(finding);
  const severityLevel = scoreToSeverity(severityScore);
  const urgency = normalizeUrgency(urgencyRaw);
  const reportType = classifyReportType(title);
  const cves = extractCves(flatText);
  const affectedCves = [...new Set(affectedSystems.flatMap((item) => item.cves || []))];

  const affectedOrganizations = [...new Set(affectedSystems.map((item) => item.organization).filter(Boolean))];
  const organizationMismatch = Boolean(
    targetOrganization
      && affectedOrganizations.length
      && affectedOrganizations.some((value) => !sameLooseText(value, targetOrganization)),
  );
  const ipMismatch = Boolean(
    targetIp
      && affectedIps.length
      && affectedIps.some((value) => value !== targetIp),
  );

  if (organizationMismatch) warnings.push("target_organization_differs_from_affected_system");
  if (ipMismatch) warnings.push("target_ip_differs_from_affected_system");
  if (!reportNumber) warnings.push("missing_report_number");
  if (!targetOrganization) warnings.push("missing_target_organization");
  if (!targetIp) warnings.push("missing_target_ip");
  if (!reportDateRaw) warnings.push("missing_report_date");
  if (finding.type === "unknown") warnings.push("unknown_finding_type");

  const year = date.year || Number(yearHint);
  if (!Number.isInteger(year)) throw new Error("Unable to determine report year");

  const documentKey = String(reportNumber || "").trim() || `sha-pending-${year}`;

  return {
    documentKey,
    reportNumber: reportNumber || null,
    reportDateRaw: reportDateRaw || null,
    year,
    month: date.month,
    day: date.day,
    title,
    reportType,
    provider: provider || null,
    contact: contact || null,
    effect: effect || null,
    target: {
      organization: targetOrganization || null,
      ip: targetIp || null,
      rawIp: targetIpRaw || null,
    },
    severity: {
      raw: severityRaw || null,
      score: severityScore,
      level: severityLevel,
    },
    urgency: {
      raw: urgencyRaw || null,
      normalized: urgency,
    },
    finding,
    vulnerability,
    cves,
    affectedCves,
    description,
    conclusion,
    recommendations,
    affectedSystems,
    fullText: flatText.slice(0, 120000),
    extraction: {
      parserVersion: PARSER_VERSION,
      paragraphCount: paragraphs.length,
      tableCount: tables.length,
      warnings,
      organizationMismatch,
      ipMismatch,
    },
  };
}

function collectFieldMap(tables) {
  const map = new Map();
  for (const table of tables) {
    for (const row of table) {
      if (!Array.isArray(row) || row.length < 2) continue;
      for (let index = 0; index + 1 < row.length; index += 2) {
        const label = normalizeLabel(row[index]);
        const value = normalizeWhitespace(row[index + 1]);
        if (label && value && looksLikeLabel(label) && !map.has(label)) map.set(label, value);
      }
    }
  }
  return map;
}

function firstField(fieldMap, flatText, labels) {
  for (const label of labels) {
    const normalized = normalizeLabel(label);
    if (fieldMap.has(normalized)) return fieldMap.get(normalized);
  }

  for (const label of labels) {
    const escaped = escapeRegExp(label).replace(/[یي]/g, "[یي]").replace(/[کك]/g, "[کك]");
    const regex = new RegExp(`${escaped}\\s*[:：]?\\s*([^\\n\\t]{1,250})`, "i");
    const match = normalizePersianCharacters(flatText).match(regex);
    if (match?.[1]) return normalizeWhitespace(match[1]);
  }
  return null;
}

function extractAffectedSystems(tables) {
  const output = [];
  for (const table of tables) {
    if (!Array.isArray(table) || table.length < 2) continue;
    const headers = table[0].map(normalizeHeader);
    const recognized = headers.filter(Boolean).length;
    const hasAssetIdentity = headers.some((key) => [
      "ip",
      "organization",
      "domain",
      "url",
    ].includes(key));
    if (recognized < 2 || !hasAssetIdentity) continue;

    for (const row of table.slice(1)) {
      const rowText = row.join(" ");
      const rowUrls = extractUrls(rowText);
      const isUrlContinuation = rowUrls.length > 0 && row.length <= 2 && headers.length >= 4 && output.length > 0;
      if (isUrlContinuation) {
        const previous = output[output.length - 1];
        previous.additionalUrls = [...new Set([...(previous.additionalUrls || []), ...rowUrls])];
        continue;
      }

      const item = {};
      headers.forEach((key, index) => {
        if (!key || row[index] === undefined) return;
        item[key] = normalizeWhitespace(row[index]) || null;
      });

      const rawIp = item.ip || extractMaskedIp(rowText);
      if (item.ip) item.ip = normalizeFirstIp(item.ip);
      if (!item.url && rowUrls.length) item.url = rowUrls[0];
      if (item.url && !item.domain) item.domain = domainFromUrl(item.url);
      if (!item.ip) item.ip = normalizeFirstIp(rowText);
      if (item.port) item.port = parsePort(item.port);
      if (!item.port && item.service) item.port = parsePort(item.service);
      if (item.packetCount) item.packetCount = parseInteger(item.packetCount);
      if (item.participantIpCount) item.participantIpCount = parseInteger(item.participantIpCount);
      if (item.trafficVolumeRaw) item.trafficVolumeBytes = parseTrafficBytes(item.trafficVolumeRaw);

      const eventDate = parseJalaliDate(item.eventDateRaw);
      const rowCves = extractCves([item.reportedFinding, item.url, rowText].filter(Boolean).join("\n"));

      const normalizedItem = {
        method: item.method || null,
        parameter: item.parameter || null,
        url: item.url || null,
        additionalUrls: [],
        domain: item.domain || null,
        organization: item.organization || null,
        ip: item.ip || null,
        rawIp: rawIp || null,
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
        cves: rowCves,
      };

      if (Object.values(normalizedItem).some((value) => Array.isArray(value) ? value.length : Boolean(value))) {
        output.push(normalizedItem);
      }
    }
  }
  return output;
}

function normalizeHeader(value) {
  const text = normalizeLabel(value);
  if (!text) return null;
  if (/^(متد|method)$/.test(text)) return "method";
  if (/پارامتر|parameter/.test(text)) return "parameter";
  if (/مسیر.*(بهره|دسترسی)|url|آدرس.*وب|نشانی.*وب|webmail|آدرس.*mail/.test(text)) return "url";
  if (/دامنه|domain/.test(text)) return "domain";
  if (/نام.*سازمان|organization/.test(text)) return "organization";
  if (/آدرس.*سازمان|آدرس.*ip|آدرس.*آی|ip سازمانی|ip address|^ip$/.test(text)) return "ip";
  if (/^پورت$|port/.test(text)) return "port";
  if (/نسخه.*(routeros|نرم|سرویس|آسیب|تحت تاثیر|تحت تأثیر)|software.*version|^نسخه$/.test(text)) return "softwareVersion";
  if (/^(سرویس(?: udp)?|service)$/.test(text)) return "service";
  if (/مجموع.*بسته|تعداد.*بسته|packet/.test(text)) return "packetCount";
  if (/تعداد.*ip.*(شرکت|مشارکت)|participant.*ip/.test(text)) return "participantIpCount";
  if (/حجم.*ترافیک|traffic.*volume/.test(text)) return "trafficVolumeRaw";
  if (/^تاریخ$|تاریخ.*رخداد|event.*date/.test(text)) return "eventDateRaw";
  if (/بازه.*زمان|time.*range/.test(text)) return "timeRange";
  if (/نوع.*آسیب|نمونه.*آسیب|نمونه.*شناسه|شناسه.*آسیب|آسیب پذیری|finding/.test(text)) return "reportedFinding";
  return null;
}

function extractSectionByHeadings(paragraphs, startHeadings, endMatchers = []) {
  const starts = startHeadings.map(normalizeLabel);
  const startIndex = paragraphs.findIndex((value) => starts.includes(normalizeLabel(value)));
  if (startIndex < 0) return "";
  let endIndex = paragraphs.length;
  for (let index = startIndex + 1; index < paragraphs.length; index += 1) {
    const normalized = normalizeLabel(paragraphs[index]);
    if (endMatchers.some((matcher) => matcher instanceof RegExp ? matcher.test(normalized) : normalizeLabel(matcher) === normalized)) {
      endIndex = index;
      break;
    }
  }
  return paragraphs
    .slice(startIndex + 1, endIndex)
    .filter((value) => !/^(جدول|شکل)\s*[0-9۰-۹٠-٩]*\s*[-–—:]?/.test(value))
    .join("\n")
    .trim();
}

function extractSection(paragraphs, startHeading, endHeadings) {
  return extractSectionByHeadings(paragraphs, [startHeading], endHeadings);
}

function extractRecommendations(paragraphs) {
  const startIndex = paragraphs.findIndex((value) => /^راهکار/.test(normalizeLabel(value)));
  if (startIndex < 0) return [];
  const output = [];
  for (const raw of paragraphs.slice(startIndex + 1)) {
    const normalized = normalizeLabel(raw);
    if (/^منابع$/.test(normalized)) break;
    if (/^(جدول|شکل)\s/.test(normalized)) continue;
    const cleaned = normalizeWhitespace(
      raw
        .replace(/^[•▪◦\-–—]+\s*/, "")
        .replace(/^[vo]\s+/i, "")
        .replace(/^\|+\s*/, ""),
    );
    if (cleaned) output.push(cleaned);
  }
  return output;
}

function classifyFinding(value) {
  const text = normalizePersianCharacters(String(value || "")).toLowerCase();
  const catalog = [
    { pattern: /phpmyadmin/, type: "vulnerable_phpmyadmin", name: "Vulnerable phpMyAdmin", category: "vulnerable_software", cwe: null },
    { pattern: /roundcube/, type: "vulnerable_roundcube", name: "Vulnerable Roundcube", category: "vulnerable_software", cwe: null },
    { pattern: /mikrotik\s+routeros|routeros/, type: "vulnerable_routeros", name: "Vulnerable MikroTik RouterOS", category: "vulnerable_software", cwe: null },
    { pattern: /dependency\s+confusion|dependency\s+hijack/, type: "dependency_confusion", name: "Dependency Confusion", category: "software_supply_chain", cwe: null },
    { pattern: /udp\s+amplification/, type: "udp_amplification", name: "UDP Amplification", category: "denial_of_service", cwe: null },
    { pattern: /(?:tcp\s+)?syn\s+flood|tcp\s+flood/, type: "tcp_syn_flood", name: "TCP SYN Flood", category: "denial_of_service", cwe: null },
    { pattern: /ترافیک.*ناهنجار|traffic\s+anomal/, type: "traffic_anomaly", name: "Traffic Anomaly", category: "network_anomaly", cwe: null },
    { pattern: /cross[-\s]?site scripting|\bxss\b/, type: "xss", name: "Cross-Site Scripting", category: "web", cwe: "CWE-79" },
    { pattern: /sql injection|\bsqli\b|تزریق\s+sql/, type: "sql_injection", name: "SQL Injection", category: "web", cwe: "CWE-89" },
    { pattern: /server[-\s]?side request forgery|\bssrf\b/, type: "ssrf", name: "Server-Side Request Forgery", category: "web", cwe: "CWE-918" },
    { pattern: /cross[-\s]?site request forgery|\bcsrf\b/, type: "csrf", name: "Cross-Site Request Forgery", category: "web", cwe: "CWE-352" },
    { pattern: /remote code execution|\brce\b|اجرای کد از راه دور/, type: "rce", name: "Remote Code Execution", category: "code_execution", cwe: null },
    { pattern: /directory traversal|path traversal|پیمایش مسیر/, type: "path_traversal", name: "Path Traversal", category: "web", cwe: "CWE-22" },
    { pattern: /xml external entity|\bxxe\b/, type: "xxe", name: "XML External Entity", category: "web", cwe: "CWE-611" },
    { pattern: /open redirect|unvalidated redirect|تغییر مسیر/, type: "open_redirect", name: "Open Redirect", category: "web", cwe: "CWE-601" },
    { pattern: /weak tls|tls\s*1\.0|tls\s*1\.1|ssl\s*v?3|پروتکل.*ضعیف/, type: "weak_tls", name: "Weak TLS/SSL", category: "crypto", cwe: null },
  ];
  return catalog.find((item) => item.pattern.test(text)) || {
    type: "unknown",
    name: null,
    category: "unknown",
    cwe: null,
  };
}

function vulnerabilityFromFinding(finding) {
  const vulnerabilityTypes = new Set([
    "xss",
    "dependency_confusion",
    "sql_injection",
    "ssrf",
    "csrf",
    "rce",
    "path_traversal",
    "xxe",
    "open_redirect",
    "weak_tls",
    "vulnerable_routeros",
    "vulnerable_phpmyadmin",
    "vulnerable_roundcube",
  ]);
  if (!finding || !vulnerabilityTypes.has(finding.type)) {
    return { name: null, normalizedName: "unknown", category: "unknown", cwe: null };
  }
  return {
    name: finding.name,
    normalizedName: finding.type,
    category: finding.category,
    cwe: finding.cwe,
  };
}

function classifyVulnerability(value) {
  return vulnerabilityFromFinding(classifyFinding(value));
}

function classifyReportType(title) {
  const text = normalizePersianCharacters(String(title || ""))
    .replace(/[‌\u200c]/g, " ")
    .replace(/\s+/g, " ")
    .toLowerCase();
  if (/پیکربندی.*نامناسب|misconfigur/.test(text)) return "misconfiguration";
  if (/بدافزار|malware|botnet|\bc2\b/.test(text)) return "malware";
  if (/حادثه|رخداد|حمله|attack|منع سرویس|flood|amplification|ترافیک.*ناهنجار/.test(text)) return "incident";
  if (/آسیب[\s-]*پذیری|vulnerabil/.test(text)) return "vulnerability";
  return "other";
}

function parseJalaliDate(value, yearHint) {
  const normalized = toAsciiDigits(String(value || ""));
  const match = normalized.match(/(\d{1,4})\s*[\/\-.]\s*(\d{1,2})\s*[\/\-.]\s*(\d{1,4})/);
  if (!match) return { year: Number(yearHint) || null, month: null, day: null };
  const parts = match.slice(1).map(Number);
  if (parts[0] >= 1300) return { year: parts[0], month: parts[1], day: parts[2] };
  return { day: parts[0], month: parts[1], year: parts[2] };
}

function parseScore(value) {
  if (value === null || value === undefined) return null;
  const normalized = toAsciiDigits(String(value)).replace(",", ".").trim();
  if (!/^\d{1,2}(?:\.\d+)?$/.test(normalized)) return null;
  const score = Number(normalized);
  if (!Number.isFinite(score) || score < 0 || score > 10) return null;
  return score;
}

function scoreToSeverity(score) {
  if (!Number.isFinite(score)) return "unknown";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "none";
}

function normalizeUrgency(value) {
  const text = normalizePersianCharacters(String(value || "")).toLowerCase();
  if (!text) return "unknown";
  if (/جهت\s*اطلاع|اطلاع رسان|informational|for information/.test(text)) return "informational";
  if (/فوری|immediate|urgent/.test(text)) return "immediate";
  if (/نیازمند\s*اقدام|action required/.test(text)) return "action_required";
  if (/بالا|high/.test(text)) return "high";
  if (/عادی|normal|معمول/.test(text)) return "normal";
  if (/کم|low/.test(text)) return "low";
  return "other";
}

function normalizeFirstIp(value) {
  const normalized = toAsciiDigits(String(value || ""));
  for (const candidate of normalized.match(/(?:\d{1,3}\.){3}\d{1,3}/g) || []) {
    const ip = normalizeIpv4(candidate);
    if (ip) return ip;
  }
  return null;
}

function extractMaskedIp(value) {
  const match = String(value || "").match(/\b[xX](?:\.[xX]){3}\b/);
  return match?.[0] || null;
}

function parseInteger(value) {
  const normalized = toAsciiDigits(String(value || "")).replace(/[,_\s]/g, "");
  const match = normalized.match(/\d+/);
  if (!match) return null;
  const number = Number(match[0]);
  return Number.isSafeInteger(number) ? number : null;
}

function parsePort(value) {
  const normalized = toAsciiDigits(String(value || ""));
  const portMatch = normalized.match(/(?:port\s*)?(\d{1,5})/i);
  if (!portMatch) return null;
  const port = Number(portMatch[1]);
  return Number.isInteger(port) && port >= 0 && port <= 65535 ? port : null;
}

function parseTrafficBytes(value) {
  const normalized = toAsciiDigits(String(value || "")).replace(/,/g, "").trim();
  const match = normalized.match(/(\d+(?:\.\d+)?)\s*(b|kb|mb|gb|tb)\b/i);
  if (!match) return null;
  const amount = Number(match[1]);
  const unit = match[2].toUpperCase();
  const multipliers = { B: 1, KB: 1024, MB: 1024 ** 2, GB: 1024 ** 3, TB: 1024 ** 4 };
  return Math.round(amount * multipliers[unit]);
}

function extractCves(value) {
  const matches = String(value || "").toUpperCase().match(/CVE-\d{4}-\d{4,7}/g) || [];
  return [...new Set(matches)];
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

function buildFlatText(paragraphs, tables) {
  const tableLines = tables.flatMap((table) => table.map((row) => row.join("\t")));
  return [...paragraphs, ...tableLines].filter(Boolean).join("\n");
}

function firstUsefulTableText(tables) {
  return tables.flat(2).find((value) => normalizeWhitespace(value)) || null;
}

function normalizeLabel(value) {
  return normalizePersianCharacters(normalizeWhitespace(value))
    .replace(/[：:]\s*$/, "")
    .replace(/[‌\u200c]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

function normalizePersianCharacters(value) {
  return String(value || "")
    .replace(/ي/g, "ی")
    .replace(/ك/g, "ک")
    .replace(/ۀ/g, "ه")
    .replace(/ة/g, "ه");
}

function normalizeWhitespace(value) {
  return String(value || "").replace(/[\t\r\n ]+/g, " ").trim();
}

function toAsciiDigits(value) {
  return String(value || "")
    .replace(/[۰-۹]/g, (char) => String("۰۱۲۳۴۵۶۷۸۹".indexOf(char)))
    .replace(/[٠-٩]/g, (char) => String("٠١٢٣٤٥٦٧٨٩".indexOf(char)));
}

function decodeXml(value) {
  return String(value || "")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&")
    .replace(/&#(\d+);/g, (_match, code) => String.fromCodePoint(Number(code)))
    .replace(/&#x([0-9a-f]+);/gi, (_match, code) => String.fromCodePoint(parseInt(code, 16)));
}

function looksLikeLabel(value) {
  return /(گزارش|سازمان|آدرس|شدت|فوریت|تماس|ارائه|اثر)/.test(value);
}

function sameLooseText(left, right) {
  const normalize = (value) => normalizeLabel(value).replace(/[^\p{L}\p{N}]+/gu, "");
  const a = normalize(left);
  const b = normalize(right);
  if (!a || !b) return false;
  return a === b || a.includes(b) || b.includes(a);
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

module.exports = {
  PARSER_VERSION,
  parseDocxReport,
  extractDocumentXml,
  parseWordXml,
  extractReportRecord,
  collectFieldMap,
  extractAffectedSystems,
  extractSection,
  extractSectionByHeadings,
  extractRecommendations,
  classifyFinding,
  classifyVulnerability,
  classifyReportType,
  parseJalaliDate,
  parseScore,
  scoreToSeverity,
  normalizeUrgency,
  normalizeFirstIp,
  extractMaskedIp,
  parseInteger,
  parsePort,
  parseTrafficBytes,
  extractCves,
  extractUrls,
  normalizeLabel,
  normalizePersianCharacters,
  normalizeWhitespace,
  toAsciiDigits,
};
