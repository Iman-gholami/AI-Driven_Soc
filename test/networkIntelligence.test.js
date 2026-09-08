const assert = require("node:assert/strict");
const test = require("node:test");

const {
  extractIpIndicators,
  extractNetworkTuple,
  normalizeIpv4,
  classifyIpv4,
} = require("../src/services/ipExtractor");
const { mapThreatObservation } = require("../scripts/import-threat-intel");
const {
  NetworkIntelligenceService,
  summarizeThreatLookup,
} = require("../src/services/networkIntelligenceService");
const { parseJsonResponse } = require("../src/services/llmProviders");

test("IPv4 extractor resolves top-level and nested source/destination fields deterministically", () => {
  const event = {
    src_ip: "010.0.0.10",
    destination: { ip: "45.77.249.79", port: 6969 },
    protocol: "TCP",
  };

  assert.deepEqual(extractIpIndicators(event), [
    {
      ip: "10.0.0.10",
      roles: ["source"],
      fields: ["src_ip"],
      scope: "private",
    },
    {
      ip: "45.77.249.79",
      roles: ["destination"],
      fields: ["destination.ip"],
      scope: "public",
    },
  ]);

  assert.deepEqual(extractNetworkTuple(event), {
    sourceIp: "10.0.0.10",
    sourcePort: null,
    destinationIp: "45.77.249.79",
    destinationPort: 6969,
    protocol: "tcp",
  });
});

test("IPv4 normalization rejects malformed and non-IPv4 input", () => {
  assert.equal(normalizeIpv4("192.168.1.1"), "192.168.1.1");
  assert.equal(normalizeIpv4("256.1.1.1"), null);
  assert.equal(normalizeIpv4("2001:db8::1"), null);
  assert.equal(classifyIpv4("10.1.2.3"), "private");
  assert.equal(classifyIpv4("8.8.8.8"), "public");
});

test("threat feed mapper preserves source classification and destination relationship fields", () => {
  const mapped = mapThreatObservation({
    unique_id: "obs-1",
    "feed.provider": "Spamhaus",
    "classification.identifier": "mirai",
    "classification.taxonomy": "malicious-code",
    "classification.type": "infected-system",
    "malware.name": "elf.mirai",
    "protocol.transport": "tcp",
    "source.ip": "5.10.20.30",
    "source.port": 40000,
    "source.asn": 64500,
    "destination.ip": "45.77.249.79",
    "destination.port": 6969,
    "destination.fqdn": "example.invalid",
    "time.source": "2026-09-05T20:00:00Z",
    "time.observation": "2026-09-05T21:00:00Z",
  });

  assert.equal(mapped.uniqueId, "obs-1");
  assert.equal(mapped.source.ip, "5.10.20.30");
  assert.equal(mapped.destination.ip, "45.77.249.79");
  assert.equal(mapped.destination.port, 6969);
  assert.equal(mapped.classification.type, "infected-system");
  assert.equal(mapped.malwareName, "elf.mirai");
});

test("threat summary keeps direct and relationship matches separate", () => {
  const observation = {
    provider: "Spamhaus",
    malwareName: "elf.mirai",
    protocol: "tcp",
    classification: {
      identifier: "mirai",
      taxonomy: "malicious-code",
      type: "infected-system",
    },
    source: { ip: "5.10.20.30", port: 40000 },
    destination: { ip: "45.77.249.79", port: 6969 },
    sourceTime: new Date("2026-09-05T20:00:00Z"),
  };

  const summary = summarizeThreatLookup({
    status: "available",
    dataset: { importId: "dataset-1" },
    direct: { count: 2, evidence: [observation] },
    relationship: { count: 7, evidence: [observation] },
  });

  assert.equal(summary.directMatch, true);
  assert.equal(summary.relationshipMatch, true);
  assert.equal(summary.directObservationCount, 2);
  assert.equal(summary.relationshipObservationCount, 7);
  assert.equal(summary.direct.evidence[0].observedRole, "source");
  assert.equal(summary.relationship.evidence[0].observedRole, "destination");
});

test("network intelligence correlates an organizational asset with feed destination evidence", async () => {
  const observation = {
    provider: "Spamhaus",
    malwareName: "elf.mirai",
    protocol: "tcp",
    classification: {
      identifier: "mirai",
      taxonomy: "malicious-code",
      type: "infected-system",
    },
    source: { ip: "5.10.20.30", port: 40000 },
    destination: { ip: "45.77.249.79", port: 6969, fqdn: "example.invalid" },
    sourceTime: new Date("2026-09-05T20:00:00Z"),
  };

  const assetRepository = {
    async getActiveState() {
      return { activeImportId: "asset-v1", sourceFile: "assets.csv", recordCount: 250000 };
    },
    async findByIp(ip) {
      return ip === "10.0.0.10"
        ? { ip, bunit: "Organization A", category: "Critical Service", province: "Tehran" }
        : null;
    },
  };

  const threatRepository = {
    async getActiveState() {
      return { activeImportId: "ti-v1", sourceFile: "feed.jsonl", recordCount: 2000000 };
    },
    async lookupIp(ip) {
      if (ip === "45.77.249.79") {
        return {
          status: "available",
          dataset: { importId: "ti-v1" },
          direct: { count: 0, evidence: [] },
          relationship: { count: 5, evidence: [observation] },
        };
      }
      return {
        status: "available",
        dataset: { importId: "ti-v1" },
        direct: { count: 0, evidence: [] },
        relationship: { count: 0, evidence: [] },
      };
    },
    async findFlowMatches() {
      return [];
    },
  };

  const service = new NetworkIntelligenceService({
    assetRepository,
    threatRepository,
    ipMetadataService: {
      async lookup(ip) {
        return { status: "available", provider: "ipinfo-mmdb", matched: true, asn: 20473, ip };
      },
    },
  });

  const result = await service.enrich({
    src_ip: "10.0.0.10",
    dst_ip: "45.77.249.79",
    dst_port: 6969,
    protocol: "tcp",
  });

  const source = result.ips.find((item) => item.ip === "10.0.0.10");
  const destination = result.ips.find((item) => item.ip === "45.77.249.79");

  assert.equal(result.status, "complete");
  assert.equal(source.asset.owned, true);
  assert.equal(source.asset.organization, "Organization A");
  assert.equal(destination.threat.directMatch, false);
  assert.equal(destination.threat.relationshipMatch, true);
  assert.ok(result.correlations.some((item) =>
    item.type === "organizational_asset_to_threat_related_destination" &&
    item.strength === "high"
  ));
});

test("LLM JSON parser accepts fenced JSON for local model compatibility", () => {
  assert.deepEqual(
    parseJsonResponse("Here is the result:\n\`\`\`json\n{\"verdict\":\"UNKNOWN\"}\n\`\`\`"),
    { verdict: "UNKNOWN" },
  );
});
