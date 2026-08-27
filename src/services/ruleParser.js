function normalizeTitle(value) {
  return String(value || "")
    .normalize("NFKC")
    .trim()
    .replace(/\s+/g, " ")
    .toLowerCase();
}

function splitRuleOptions(rawRule) {
  const text = String(rawRule || "");
  const open = text.indexOf("(");
  const close = text.lastIndexOf(")");
  if (open < 0 || close <= open) return [];

  const body = text.slice(open + 1, close);
  const tokens = [];
  let current = "";
  let inQuote = false;
  let escaped = false;

  for (const char of body) {
    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }

    if (char === "\\") {
      current += char;
      escaped = true;
      continue;
    }

    if (char === '"') {
      current += char;
      inQuote = !inQuote;
      continue;
    }

    if (char === ";" && !inQuote) {
      const token = current.trim();
      if (token) tokens.push(token);
      current = "";
      continue;
    }

    current += char;
  }

  const tail = current.trim();
  if (tail) tokens.push(tail);
  return tokens;
}

function parseOptionToken(token) {
  const index = token.indexOf(":");
  if (index < 0) {
    return { keyword: token.trim().toLowerCase(), value: null, raw: token };
  }

  return {
    keyword: token.slice(0, index).trim().toLowerCase(),
    value: token.slice(index + 1).trim(),
    raw: token,
  };
}

function unquote(value) {
  if (typeof value !== "string") return value;
  const trimmed = value.trim();
  if (trimmed.length >= 2 && trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function parseContentValue(value) {
  const raw = String(value || "").trim();
  const negative = raw.startsWith("!");
  const withoutNegation = negative ? raw.slice(1).trim() : raw;
  return {
    value: unquote(withoutNegation),
    negative,
  };
}

function parseRawRule(rawRule) {
  const tokens = splitRuleOptions(rawRule);
  const options = tokens.map(parseOptionToken);
  const contents = [];
  const pcre = [];
  const references = [];
  const flow = [];
  let message;
  let classtype;
  let sid;
  let revision;
  let metadata;
  let activeContent = null;

  const contentModifierKeywords = new Set([
    "nocase", "distance", "within", "offset", "depth", "startswith", "endswith",
    "fast_pattern", "http_uri", "http_raw_uri", "http_header", "http_raw_header",
    "http_method", "http_cookie", "http_user_agent", "http_client_body", "file_data",
    "pkt_data", "rawbytes", "isdataat", "dsize", "byte_test", "byte_jump", "byte_extract",
  ]);

  for (const option of options) {
    if (option.keyword === "content") {
      const parsed = parseContentValue(option.value);
      activeContent = { ...parsed, modifiers: [] };
      contents.push(activeContent);
      continue;
    }

    if (activeContent && contentModifierKeywords.has(option.keyword)) {
      activeContent.modifiers.push({ keyword: option.keyword, value: option.value });
    } else if (!contentModifierKeywords.has(option.keyword)) {
      activeContent = null;
    }

    switch (option.keyword) {
      case "msg":
        message = unquote(option.value);
        break;
      case "pcre":
        pcre.push(unquote(option.value));
        break;
      case "reference":
        references.push(option.value);
        break;
      case "flow":
        flow.push(...String(option.value || "").split(",").map((part) => part.trim()).filter(Boolean));
        break;
      case "classtype":
        classtype = option.value;
        break;
      case "sid":
        sid = option.value;
        break;
      case "rev":
        revision = Number(option.value);
        break;
      case "metadata":
        metadata = option.value;
        break;
      default:
        break;
    }
  }

  // Some community rules contain an unescaped quote inside PCRE. Direct field
  // extraction keeps msg/sid/rev/content parsing reliable even when option
  // tokenization becomes ambiguous around that PCRE.
  const directMessage = String(rawRule || "").match(/\bmsg\s*:\s*"((?:\\.|[^"])*)"\s*;/i);
  const directSid = String(rawRule || "").match(/\bsid\s*:\s*(\d+)\s*;/i);
  const directRevision = String(rawRule || "").match(/\brev\s*:\s*(\d+)\s*;/i);
  const directContents = [];
  const contentRegex = /\bcontent\s*:\s*(!?)"((?:\\.|[^"])*)"\s*;/gi;
  let contentMatch;
  while ((contentMatch = contentRegex.exec(String(rawRule || ""))) !== null) {
    directContents.push({ value: contentMatch[2], negative: contentMatch[1] === "!", modifiers: [] });
  }

  const resolvedContents = directContents.length > 0
    ? directContents.map((item, index) => ({ ...item, modifiers: contents[index]?.modifiers || [] }))
    : contents;

  return {
    message: directMessage ? directMessage[1] : message,
    flow,
    contents: resolvedContents,
    pcre,
    references,
    classtype,
    sid: directSid ? directSid[1] : sid,
    revision: directRevision ? Number(directRevision[1]) : (Number.isFinite(revision) ? revision : undefined),
    metadata,
    options,
  };
}

function extractSearchableContent(value) {
  const text = String(value || "").trim();
  if (text.length < 3) return null;
  if (text.includes("|")) return null;
  if (/^[\W_]+$/.test(text)) return null;
  return text.toLowerCase();
}

module.exports = {
  normalizeTitle,
  splitRuleOptions,
  parseRawRule,
  extractSearchableContent,
};
