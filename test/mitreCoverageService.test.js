const assert = require("node:assert/strict");
const test = require("node:test");

const {
  mappingSourcesExpression,
} = require("../src/services/mitreCoverageService");

test("MITRE provenance aggregation uses the scoped mapping variable", () => {
  assert.deepEqual(mappingSourcesExpression(), {
    $map: {
      input: { $ifNull: ["$mitre.mappings", []] },
      as: "mapping",
      in: "$$mapping.source",
    },
  });
});
