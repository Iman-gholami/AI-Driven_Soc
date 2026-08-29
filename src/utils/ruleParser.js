/**
 * Normalize title by removing special characters and converting to lowercase
 */
function normalizeTitle(title) {
  if (!title) return '';
  return String(title)
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Parse raw rule string into structured format
 */
function parseRawRule(rawRule) {
  if (!rawRule) return { pcre: [] };
  
  const parsed = {
    pcre: [],
    content: [],
    nocase: false,
    depth: null,
    offset: null,
    within: null,
    distance: null
  };

  // Extract PCRE patterns
  const pcreMatches = rawRule.match(/pcre:"([^"]*)"/g);
  if (pcreMatches) {
    parsed.pcre = pcreMatches.map(m => m.replace(/pcre:"|"$/g, ''));
  }

  // Extract content patterns
  const contentMatches = rawRule.match(/content:"([^"]*)"/g);
  if (contentMatches) {
    parsed.content = contentMatches.map(m => m.replace(/content:"|"$/g, ''));
  }

  // Check for nocase
  parsed.nocase = /nocase/i.test(rawRule);

  // Extract depth
  const depthMatch = rawRule.match(/depth:(\d+)/);
  if (depthMatch) {
    parsed.depth = parseInt(depthMatch[1], 10);
  }

  // Extract offset
  const offsetMatch = rawRule.match(/offset:(\d+)/);
  if (offsetMatch) {
    parsed.offset = parseInt(offsetMatch[1], 10);
  }

  return parsed;
}

/**
 * Transform raw rule data into structured format
 */
function mapSourceRule(source) {
  if (!source || typeof source !== 'object') {
    throw new Error('Rule record must be an object');
  }
  
  if (!source.rule_id || !source.title || !source.raw_rule) {
    throw new Error('Rule is missing rule_id, title, or raw_rule');
  }

  const revision = Number(source.rev || 0);
  const parsedRule = parseRawRule(source.raw_rule);
  
  // If PCRE is missing but source has pcre field, use it
  if ((!parsedRule.pcre || parsedRule.pcre.length === 0) && source.pcre) {
    parsedRule.pcre = [String(source.pcre)];
  }

  return {
    ruleId: String(source.rule_id),
    action: String(source.raw_rule).trim().split(/\s+/, 1)[0].toLowerCase(),
    revision: Number.isFinite(revision) ? revision : 0,
    title: String(source.title).trim(),
    normalizedTitle: normalizeTitle(source.title),
    classtype: source.classtype ? String(source.classtype) : undefined,
    protocol: source.protocol ? String(source.protocol).toLowerCase() : undefined,
    src: source.src ? String(source.src) : undefined,
    srcPort: source.src_port ? String(source.src_port) : undefined,
    direction: source.direction ? String(source.direction) : undefined,
    dst: source.dst ? String(source.dst) : undefined,
    dstPort: source.dst_port ? String(source.dst_port) : undefined,
    sourceContents: Array.isArray(source.contents) ? source.contents.map(String) : [],
    sourcePcre: source.pcre ? String(source.pcre) : undefined,
    rawRule: String(source.raw_rule),
    sourceFile: source.source_file ? String(source.source_file) : undefined,
    parsedRule,
  };
}

module.exports = {
  normalizeTitle,
  parseRawRule,
  mapSourceRule
};