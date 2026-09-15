const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const path = require("node:path");
const { execFile } = require("node:child_process");
const { promisify } = require("node:util");
const { normalizeIpv4 } = require("./ipExtractor");

const execFileAsync = promisify(execFile);
const PARSER_VERSION = "docx-v1";

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
  const contact = firstField(fieldMap, flatText, ["اطلاعات تماس"]);
  const targetOrganization = firstField(fieldMap, flatText, ["سازمان هدف", "نام سازمان هدف"]);
  const targetIp = normalizeFirstIp(firstField(fieldMap, flatText, ["آدرس IP", "آدرس آی پی", "آدرس آی‌پی"]));
  const severityScore = parseScore(firstField(fieldMap, flatText, ["شدت رخداد", "امتیاز شدت"]));
  const urgencyRaw = firstField(fieldMap, flatText, ["فوریت اقدام"]);

  const date = parseJalaliDate(reportDateRaw, yearHint);
  if (!date.year && yearHint) date.year = Number(yearHint);
  if (yearHint && date.year && Number(yearHint) !== date.year) {
    warnings.push(`report_year_mismatch:${date.year}:${Number(yearHint)}`);
  }

  const affectedSystems = extractAffectedSystems(tables);
  const description = extractSection(paragraphs, "شرح رخداد", ["راهکار", "راه کار"]);
  const recommendations = extractRecommendations(paragraphs);
  const vulnerability = classifyVulnerability(`${title}\n${description}`);
  const severityLevel = scoreToSeverity(severityScore);
  const urgency = normalizeUrgency(urgencyRaw);
  const reportType = classifyReportType(title);

  const affectedOrganizations = [...new Set(affectedSystems.map((item) => item.organization).filter(Boolean))];
  const affectedIps = [...new Set(affectedSystems.map((item) => item.ip).filter(Boolean))];
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
    target: {
      organization: targetOrganization || null,
      ip: targetIp || null,
    },
    severity: {
      score: severityScore,
      level: severityLevel,
    },
    urgency: {
      raw: urgencyRaw || null,
      normalized: urgency,
    },
    vulnerability,
    description,
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
    if (recognized < 3) continue;

    for (const row of table.slice(1)) {
      const item = {};
      headers.forEach((key, index) => {
        if (!key || row[index] === undefined) return;
        item[key] = normalizeWhitespace(row[index]) || null;
      });
      if (item.ip) item.ip = normalizeFirstIp(item.ip);
      if (item.url && !item.domain) item.domain = domainFromUrl(item.url);
      if (!item.ip) item.ip = normalizeFirstIp(row.join(" "));
      if (Object.values(item).some(Boolean)) {
        output.push({
          method: item.method || null,
          parameter: item.parameter || null,
          url: item.url || null,
          domain: item.domain || null,
          organization: item.organization || null,
          ip: item.ip || null,
        });
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
  if (/مسیر.*بهره|url|آدرس.*وب|نشانی.*وب/.test(text)) return "url";
  if (/دامنه|domain/.test(text)) return "domain";
  if (/نام.*سازمان|organization/.test(text)) return "organization";
  if (/آدرس.*سازمان|آدرس.*ip|آدرس.*آی|ip address|^ip$/.test(text)) return "ip";
  return null;
}

function extractSection(paragraphs, startHeading, endHeadings) {
  const normalizedStart = normalizeLabel(startHeading);
  const startIndex = paragraphs.findIndex((value) => normalizeLabel(value) === normalizedStart);
  if (startIndex < 0) return "";
  const normalizedEnds = endHeadings.map(normalizeLabel);
  let endIndex = paragraphs.length;
  for (let index = startIndex + 1; index < paragraphs.length; index += 1) {
    if (normalizedEnds.includes(normalizeLabel(paragraphs[index]))) {
      endIndex = index;
      break;
    }
  }
  return paragraphs
    .slice(startIndex + 1, endIndex)
    .filter((value) => !/^(جدول|شکل)\s*[0-9۰-۹٠-٩]*\s*[-–—]/.test(value))
    .join("\n")
    .trim();
}

function extractRecommendations(paragraphs) {
  const startIndex = paragraphs.findIndex((value) => /^(راهکار|راه کار)$/.test(normalizeLabel(value)));
  if (startIndex < 0) return [];
  return paragraphs
    .slice(startIndex + 1)
    .map((value) => normalizeWhitespace(value.replace(/^[•▪◦\-–—]+\s*/, "")))
    .filter((value) => value && !/^(جدول|شکل)\s/.test(value));
}

function classifyVulnerability(value) {
  const text = normalizePersianCharacters(String(value || "")).toLowerCase();
  const catalog = [
    { pattern: /cross[-\s]?site scripting|\bxss\b/, normalizedName: "xss", name: "Cross-Site Scripting", category: "web", cwe: "CWE-79" },
    { pattern: /sql injection|\bsqli\b|تزریق\s+sql/, normalizedName: "sql_injection", name: "SQL Injection", category: "web", cwe: "CWE-89" },
    { pattern: /server[-\s]?side request forgery|\bssrf\b/, normalizedName: "ssrf", name: "Server-Side Request Forgery", category: "web", cwe: "CWE-918" },
    { pattern: /cross[-\s]?site request forgery|\bcsrf\b/, normalizedName: "csrf", name: "Cross-Site Request Forgery", category: "web", cwe: "CWE-352" },
    { pattern: /remote code execution|\brce\b|اجرای کد از راه دور/, normalizedName: "rce", name: "Remote Code Execution", category: "code_execution", cwe: null },
    { pattern: /directory traversal|path traversal|پیمایش مسیر/, normalizedName: "path_traversal", name: "Path Traversal", category: "web", cwe: "CWE-22" },
    { pattern: /xml external entity|\bxxe\b/, normalizedName: "xxe", name: "XML External Entity", category: "web", cwe: "CWE-611" },
    { pattern: /open redirect|unvalidated redirect|تغییر مسیر/, normalizedName: "open_redirect", name: "Open Redirect", category: "web", cwe: "CWE-601" },
    { pattern: /weak tls|tls\s*1\.0|tls\s*1\.1|ssl\s*v?3|پروتکل.*ضعیف/, normalizedName: "weak_tls", name: "Weak TLS/SSL", category: "crypto", cwe: null },
  ];
  const match = catalog.find((item) => item.pattern.test(text));
  return match || {
    name: null,
    normalizedName: "unknown",
    category: "unknown",
    cwe: null,
  };
}

function classifyReportType(title) {
  const text = normalizePersianCharacters(String(title || "")).toLowerCase();
  if (/آسیب پذیری|vulnerabil/.test(text)) return "vulnerability";
  if (/بدافزار|malware|botnet|c2/.test(text)) return "malware";
  if (/حمله|attack|رخداد/.test(text)) return "incident";
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
  const normalized = toAsciiDigits(String(value)).replace(",", ".");
  const match = normalized.match(/\d+(?:\.\d+)?/);
  if (!match) return null;
  const score = Number(match[0]);
  return Number.isFinite(score) ? score : null;
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
  if (/فوری|immediate|urgent/.test(text)) return "immediate";
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
  return /(گزارش|سازمان|آدرس|شدت|فوریت|تماس|ارائه)/.test(value);
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
  extractRecommendations,
  classifyVulnerability,
  classifyReportType,
  parseJalaliDate,
  parseScore,
  scoreToSeverity,
  normalizeUrgency,
  normalizeFirstIp,
  normalizeLabel,
  normalizePersianCharacters,
  normalizeWhitespace,
  toAsciiDigits,
};
