const assert = require("node:assert/strict");
const test = require("node:test");

const { extractMitreMapping, inferRuleTier } = require("../src/services/mitreMapping");
const { mapSourceRule, parseRawRule } = require("../src/services/ruleParser");

test("extractMitreMapping reads explicit technique and tactic identifiers", () => {
  const mapping = extractMitreMapping({
    mitre_techniques: ["T1059.001", "T1105"],
    mitre_tactic_id: "TA0002",
  }, {});

  assert.deepEqual(mapping.techniqueIds, ["T1059.001", "T1105"]);
  assert.deepEqual(mapping.tacticIds, ["TA0002"]);
  assert.equal(mapping.mapped, true);
  assert.equal(mapping.mappings[0].source, "explicit");
  assert.equal(mapping.enrichmentVersion, 1);
});

test("extractMitreMapping reads ATT&CK references from parsed rules", () => {
  const parsed = parseRawRule(
    'alert tcp any any -> any any (msg:"Mapped rule"; reference:url,attack.mitre.org/techniques/T1210/; sid:900001; rev:1;)',
  );
  const mapping = extractMitreMapping({}, parsed);

  assert.deepEqual(mapping.techniqueIds, ["T1210"]);
  assert.equal(mapping.mappings[0].source, "reference");
});

test("extractMitreMapping preserves sub-technique IDs from ATT&CK URLs", () => {
  const parsed = parseRawRule(
    'alert tcp any any -> any any (msg:"Mapped sub-technique"; reference:url,attack.mitre.org/techniques/T1059/001/; sid:900003; rev:1;)',
  );
  const mapping = extractMitreMapping({}, parsed);

  assert.deepEqual(mapping.techniqueIds, ["T1059.001"]);
});

test("mapSourceRule stores deterministic MITRE mapping and tier", () => {
  const rule = mapSourceRule({
    rule_id: "900002",
    rev: 1,
    title: "PowerShell Example",
    protocol: "tcp",
    tier: "community",
    raw_rule: 'alert tcp any any -> any any (msg:"PowerShell Example"; metadata:mitre_technique_id T1059.001, mitre_tactic_id TA0002; sid:900002; rev:1;)',
  });

  assert.equal(rule.tier, "community");
  assert.equal(rule.mitre.mapped, true);
  assert.deepEqual(rule.mitre.techniqueIds, ["T1059.001"]);
  assert.deepEqual(rule.mitre.tacticIds, ["TA0002"]);
});

test("inferRuleTier does not invent native/community provenance", () => {
  assert.equal(inferRuleTier({}), "imported");
  assert.equal(inferRuleTier({ tier: "native" }), "native");
  assert.equal(inferRuleTier({ community: true }), "community");
});
