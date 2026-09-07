const assert = require("node:assert/strict");
const test = require("node:test");

const {
  normalizeTechniqueIds,
  resolveActiveTechnique,
} = require("../src/services/mitreNormalization");

function catalog(entries) {
  return new Map(entries.map((entry) => [entry.techniqueId, entry]));
}

test("normalizeTechniqueIds preserves active technique IDs", () => {
  const result = normalizeTechniqueIds(["T1059.001"], catalog([
    { techniqueId: "T1059.001", revoked: false, deprecated: false },
  ]));

  assert.deepEqual(result.techniqueIds, ["T1059.001"]);
  assert.deepEqual(result.legacyTechniqueIds, []);
  assert.deepEqual(result.replacements, []);
});

test("normalizeTechniqueIds follows revoked-by replacement chains", () => {
  const techniques = catalog([
    { techniqueId: "T1086", revoked: true, deprecated: false, replacementTechniqueId: "T1059.001" },
    { techniqueId: "T1059.001", revoked: false, deprecated: false },
  ]);

  const result = normalizeTechniqueIds(["T1086"], techniques);

  assert.deepEqual(result.rawTechniqueIds, ["T1086"]);
  assert.deepEqual(result.techniqueIds, ["T1059.001"]);
  assert.deepEqual(result.legacyTechniqueIds, []);
  assert.deepEqual(result.replacements, [{ from: "T1086", to: "T1059.001" }]);
});

test("normalizeTechniqueIds keeps deprecated techniques without replacements as legacy", () => {
  const techniques = catalog([
    { techniqueId: "T9999", revoked: false, deprecated: true },
  ]);

  const result = normalizeTechniqueIds(["T9999"], techniques);

  assert.deepEqual(result.techniqueIds, []);
  assert.deepEqual(result.legacyTechniqueIds, ["T9999"]);
});

test("resolveActiveTechnique protects against replacement cycles", () => {
  const techniques = catalog([
    { techniqueId: "T1000", revoked: true, deprecated: false, replacementTechniqueId: "T1001" },
    { techniqueId: "T1001", revoked: true, deprecated: false, replacementTechniqueId: "T1000" },
  ]);

  assert.equal(resolveActiveTechnique("T1000", techniques), null);
});
