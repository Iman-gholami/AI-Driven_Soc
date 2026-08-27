const assert = require("node:assert/strict");
const test = require("node:test");

const { normalizeTitle, parseRawRule } = require("../src/services/ruleParser");
const { RuleResolver } = require("../src/services/ruleResolver");

test("normalizeTitle makes signature lookup stable", () => {
  assert.equal(normalizeTitle("  Example   Signature  "), "example signature");
});

test("parseRawRule extracts all content options", () => {
  const parsed = parseRawRule('alert tcp any any -> any any (msg:"Example Signature"; flow:from_server,established; content:"marker-one"; nocase; content:"marker-two"; distance:0; sid:12345; rev:3;)');
  assert.equal(parsed.message, "Example Signature");
  assert.deepEqual(parsed.flow, ["from_server", "established"]);
  assert.deepEqual(parsed.contents.map((item) => item.value), ["marker-one", "marker-two"]);
  assert.equal(parsed.sid, "12345");
  assert.equal(parsed.revision, 3);
});

function createRepository(rules) {
  return {
    async findByExactTitle(title) {
      return rules.filter((rule) => rule.title === title);
    },
    async findByNormalizedTitle(title) {
      const normalized = normalizeTitle(title);
      return rules.filter((rule) => rule.normalizedTitle === normalized);
    },
  };
}

test("RuleResolver returns a unique exact signature match", async () => {
  const rule = {
    ruleId: "12345",
    revision: 3,
    title: "Example Signature",
    normalizedTitle: "example signature",
    protocol: "tcp",
    parsedRule: { contents: [{ value: "marker-one" }] },
  };
  const resolver = new RuleResolver({ detectionRuleRepository: createRepository([rule]) });
  const result = await resolver.resolve({ signature: rule.title });
  assert.equal(result.status, "matched");
  assert.equal(result.matchType, "exact_signature");
  assert.equal(result.rule.ruleId, "12345");
});

test("RuleResolver falls back to normalized title matching", async () => {
  const rule = {
    ruleId: "1",
    revision: 1,
    title: "Example Signature",
    normalizedTitle: "example signature",
    protocol: "tcp",
    parsedRule: { contents: [] },
  };
  const resolver = new RuleResolver({ detectionRuleRepository: createRepository([rule]) });
  const result = await resolver.resolve({ signature: " example   signature " });
  assert.equal(result.status, "matched");
  assert.equal(result.matchType, "normalized_signature");
});

test("RuleResolver keeps duplicate signatures ambiguous without enough evidence", async () => {
  const rules = [
    { ruleId: "1", revision: 1, title: "Duplicate", normalizedTitle: "duplicate", protocol: "tcp", parsedRule: { contents: [{ value: "alpha" }] } },
    { ruleId: "2", revision: 1, title: "Duplicate", normalizedTitle: "duplicate", protocol: "tcp", parsedRule: { contents: [{ value: "beta" }] } },
  ];
  const resolver = new RuleResolver({ detectionRuleRepository: createRepository(rules) });
  const result = await resolver.resolve({ signature: "Duplicate" });
  assert.equal(result.status, "ambiguous");
  assert.equal(result.candidateCount, 2);
});

test("RuleResolver disambiguates duplicate signatures with incident evidence", async () => {
  const rules = [
    { ruleId: "1", revision: 1, title: "Duplicate", normalizedTitle: "duplicate", protocol: "tcp", parsedRule: { contents: [{ value: "alpha.example" }] } },
    { ruleId: "2", revision: 1, title: "Duplicate", normalizedTitle: "duplicate", protocol: "tcp", parsedRule: { contents: [{ value: "beta.example" }] } },
  ];
  const resolver = new RuleResolver({ detectionRuleRepository: createRepository(rules) });
  const result = await resolver.resolve({ signature: "Duplicate", protocol: "tcp", domain: "beta.example" });
  assert.equal(result.status, "matched");
  assert.equal(result.rule.ruleId, "2");
  assert.match(result.matchType, /evidence$/);
});

test("RuleResolver selects the latest revision when all candidates share a rule id", async () => {
  const rules = [
    { ruleId: "10", revision: 1, title: "Versioned", normalizedTitle: "versioned", protocol: "tcp", parsedRule: { contents: [] } },
    { ruleId: "10", revision: 4, title: "Versioned", normalizedTitle: "versioned", protocol: "tcp", parsedRule: { contents: [] } },
  ];
  const resolver = new RuleResolver({ detectionRuleRepository: createRepository(rules) });
  const result = await resolver.resolve({ signature: "Versioned" });
  assert.equal(result.status, "matched");
  assert.equal(result.rule.revision, 4);
  assert.match(result.matchType, /latest_revision$/);
});
