function normalizeTechniqueId(value) {
  const text = String(value || "").trim().toUpperCase();
  return /^T\d{4}(?:\.\d{3})?$/.test(text) ? text : null;
}

function normalizeTechniqueIds(rawTechniqueIds, catalog) {
  const rawIds = [...new Set(
    (Array.isArray(rawTechniqueIds) ? rawTechniqueIds : [])
      .map(normalizeTechniqueId)
      .filter(Boolean),
  )];

  const activeIds = [];
  const legacyIds = [];
  const replacements = [];

  for (const rawId of rawIds) {
    const resolved = resolveActiveTechnique(rawId, catalog);
    if (resolved && resolved !== rawId) {
      activeIds.push(resolved);
      replacements.push({ from: rawId, to: resolved });
      continue;
    }

    const technique = catalog.get(rawId);
    if (technique && !technique.revoked && !technique.deprecated) {
      activeIds.push(rawId);
    } else {
      legacyIds.push(rawId);
    }
  }

  return {
    rawTechniqueIds: rawIds,
    techniqueIds: [...new Set(activeIds)],
    legacyTechniqueIds: [...new Set(legacyIds)],
    replacements,
  };
}

function resolveActiveTechnique(techniqueId, catalog) {
  let currentId = techniqueId;
  const visited = new Set();

  while (currentId && !visited.has(currentId)) {
    visited.add(currentId);
    const technique = catalog.get(currentId);
    if (!technique) return null;

    if (!technique.revoked && !technique.deprecated) return currentId;

    if (technique.revoked && technique.replacementTechniqueId) {
      currentId = technique.replacementTechniqueId;
      continue;
    }

    return null;
  }

  return null;
}

module.exports = {
  normalizeTechniqueId,
  normalizeTechniqueIds,
  resolveActiveTechnique,
};
