require("dotenv").config();

const MitreTechnique = require("../src/models/MitreTechnique");
const { connectMongo, disconnectMongo } = require("../src/database/mongo");
const { createLogger } = require("../src/core/logging");

const logger = createLogger(process.env.LOG_LEVEL || "info");
const MITRE_URL = process.env.MITRE_ATTACK_URL
  || "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json";

async function main() {
  const connected = await connectMongo(logger);
  if (!connected) throw new Error("MongoDB connection is required");

  logger.info({ url: MITRE_URL }, "downloading_mitre_enterprise_attack");
  const response = await fetch(MITRE_URL, {
    headers: { "User-Agent": "AI-Driven-SOC-MITRE-Importer/1.0" },
  });
  if (!response.ok) {
    throw new Error(`MITRE download failed: HTTP ${response.status}`);
  }

  const bundle = await response.json();
  const objects = Array.isArray(bundle?.objects) ? bundle.objects : [];
  const tactics = buildTacticMap(objects);
  const parentByChild = buildSubTechniqueParents(objects);
  const techniques = objects
    .filter((obj) => obj?.type === "attack-pattern")
    .map((obj) => mapTechnique(obj, tactics, parentByChild))
    .filter(Boolean);

  if (!techniques.length) throw new Error("No Enterprise ATT&CK techniques were found");

  let upserted = 0;
  let modified = 0;

  for (let index = 0; index < techniques.length; index += 500) {
    const batch = techniques.slice(index, index + 500);
    const operations = batch.map((technique) => ({
      updateOne: {
        filter: { techniqueId: technique.techniqueId },
        update: { $set: technique },
        upsert: true,
      },
    }));
    const result = await MitreTechnique.bulkWrite(operations, { ordered: false });
    upserted += Number(result.upsertedCount || 0);
    modified += Number(result.modifiedCount || 0);
    logger.info(
      { batch: Math.floor(index / 500) + 1, processed: Math.min(index + 500, techniques.length) },
      "mitre_batch_imported",
    );
  }

  logger.info(
    {
      techniques: techniques.length,
      tactics: tactics.size,
      upserted,
      modified,
    },
    "mitre_enterprise_attack_imported",
  );
}

function buildTacticMap(objects) {
  const map = new Map();

  for (const obj of objects) {
    if (obj?.type !== "x-mitre-tactic") continue;
    const external = getMitreExternalReference(obj);
    if (!external?.external_id || !obj.x_mitre_shortname) continue;

    map.set(obj.x_mitre_shortname, {
      id: external.external_id,
      name: obj.name,
      shortName: obj.x_mitre_shortname,
    });
  }

  return map;
}

function buildSubTechniqueParents(objects) {
  const techniqueIdByStix = new Map();
  for (const obj of objects) {
    if (obj?.type !== "attack-pattern") continue;
    const external = getMitreExternalReference(obj);
    if (external?.external_id) techniqueIdByStix.set(obj.id, external.external_id);
  }

  const parentByChild = new Map();
  for (const obj of objects) {
    if (obj?.type !== "relationship" || obj.relationship_type !== "subtechnique-of") continue;
    const child = techniqueIdByStix.get(obj.source_ref);
    const parent = techniqueIdByStix.get(obj.target_ref);
    if (child && parent) parentByChild.set(child, parent);
  }
  return parentByChild;
}

function mapTechnique(obj, tacticMap, parentByChild) {
  const external = getMitreExternalReference(obj);
  const techniqueId = external?.external_id;
  if (!/^T\d{4}(?:\.\d{3})?$/.test(String(techniqueId || ""))) return null;

  const tactics = (Array.isArray(obj.kill_chain_phases) ? obj.kill_chain_phases : [])
    .map((phase) => tacticMap.get(phase.phase_name))
    .filter(Boolean);

  return {
    techniqueId,
    stixId: obj.id,
    name: obj.name,
    description: obj.description || "",
    tactics: uniqueBy(tactics, (item) => item.id),
    platforms: Array.isArray(obj.x_mitre_platforms) ? obj.x_mitre_platforms : [],
    dataSources: Array.isArray(obj.x_mitre_data_sources) ? obj.x_mitre_data_sources : [],
    isSubTechnique: Boolean(obj.x_mitre_is_subtechnique || techniqueId.includes(".")),
    parentTechniqueId: parentByChild.get(techniqueId),
    revoked: Boolean(obj.revoked),
    deprecated: Boolean(obj.x_mitre_deprecated),
    modified: obj.modified ? new Date(obj.modified) : undefined,
    attackVersion: obj.x_mitre_version ? String(obj.x_mitre_version) : undefined,
    sourceUrl: external?.url || undefined,
  };
}

function getMitreExternalReference(obj) {
  const refs = Array.isArray(obj?.external_references) ? obj.external_references : [];
  return refs.find((ref) => ref?.source_name === "mitre-attack")
    || refs.find((ref) => /^T(?:A)?\d+/.test(String(ref?.external_id || "")));
}

function uniqueBy(values, keyFn) {
  const seen = new Set();
  return values.filter((value) => {
    const key = keyFn(value);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

main()
  .catch((error) => {
    logger.error({ err: error }, "mitre_import_failed");
    process.exitCode = 1;
  })
  .finally(async () => {
    await disconnectMongo(logger);
  });
