const assert = require("node:assert/strict");
const test = require("node:test");

const {
  extractIpIndicators,
  extractNetworkTuple,
  normalizeIpv4,
  classifyIpv4,
  classifyNetworkZone,
  isNationalNetworkIpv4,
} = require("../src/services/ipExtractor");
const { mapThreatObservation } = require("../scripts/import-threat-intel");
const {
  NetworkIntelligenceService,
  summarizeThreatLookup,
} = require("../src/services/networkIntelligenceService");
const { parseJsonResponse } = require("../src/services/llmProviders");
const { normalizeMmdbRecord } = require("../src/services/ipMetadataService");
const { buildIncidentEvidence } = require("../src/services/contextBuilder");
const { normalizeAnalysisPayload } = require("../src/models/incidentSchema");
const {
  groundNetworkRelationshipAnalysis,
} = require("../src/services/analyzer");

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
      networkZone: "national_network",
      nationalNetwork: true,
    },
    {
      ip: "45.77.249.79",
      roles: ["destination"],
      fields: ["destination.ip"],
      scope: "public",
      networkZone: "national_network",
      nationalNetwork: true,
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
  assert.equal(classifyNetworkZone("10.1.2.3"), "national_network");
  assert.equal(classifyNetworkZone("8.8.8.8"), "national_network");
  assert.equal(classifyNetworkZone("192.168.1.1"), "private_non_national");
  assert.equal(isNationalNetworkIpv4("10.1.2.3"), true);
  assert.equal(isNationalNetworkIpv4("8.8.8.8"), true);
  assert.equal(isNationalNetworkIpv4("192.168.1.1"), false);
});

test("IPinfo Core MMDB records normalize flat fields and AS-prefixed ASN values", () => {
  assert.deepEqual(normalizeMmdbRecord({
    as_domain: "tci.ir",
    as_name: "Iran Telecommunication Company PJS",
    as_type: "isp",
    asn: "AS58224",
    city: "Golpāyegān",
    country: "Iran",
    country_code: "IR",
    region: "Isfahan",
    region_code: "28",
    timezone: "Asia/Tehran",
    latitude: 33.4537,
    longitude: 50.28836,
    is_anonymous: false,
    is_anycast: false,
    is_hosting: false,
    is_mobile: false,
    is_satellite: false,
  }), {
    asn: 58224,
    asName: "Iran Telecommunication Company PJS",
    asType: "isp",
    domain: "tci.ir",
    countryCode: "IR",
    country: "Iran",
    region: "Isfahan",
    regionCode: "28",
    city: "Golpāyegān",
    timezone: "Asia/Tehran",
    latitude: 33.4537,
    longitude: 50.28836,
    privacy: {
      anonymous: false,
      anycast: false,
      hosting: false,
      mobile: false,
      satellite: false,
    },
  });
});

test("incident context preserves current-alert domain and packet/body evidence with provenance", () => {
  const incident = buildIncidentEvidence({
    src_ip: "10.0.0.10",
    dst_ip: "45.77.249.79",
    http_host: "example.org",
    request_url: "https://example.org/admin",
    request_body: "username=admin&action=login",
  });

  assert.deepEqual(incident.communication_evidence.domains, [
    { field: "http_host", value: "example.org" },
  ]);
  assert.deepEqual(incident.communication_evidence.urls, [
    { field: "request_url", value: "https://example.org/admin" },
  ]);
  assert.deepEqual(incident.communication_evidence.packet_content, [
    { field: "request_body", snippet: "username=admin&action=login" },
  ]);
});

test("analysis normalization supplies a stable IP relationship shape for legacy model output", () => {
  const normalized = normalizeAnalysisPayload({
    verdict: "SUSPICIOUS",
    one_line_summary: "Example",
    risk_assessment: {},
  });

  assert.deepEqual(normalized.network_relationship_analysis, {
    assessment: "UNKNOWN",
    summary: "",
    source: { ip: "", organization: "", context: "" },
    destination: { ip: "", organization: "", context: "" },
    why_suspicious: [],
    current_alert_domains: [],
    current_alert_packet_evidence: [],
    threat_feed_context: [],
    limitations: "",
  });
});

test("relationship grounding replaces model-invented provenance with deterministic alert/feed evidence", () => {
  const normalized = normalizeAnalysisPayload({
    verdict: "MALICIOUS",
    one_line_summary: "Example",
    risk_assessment: {},
    network_relationship_analysis: {
      assessment: "MALICIOUS",
      summary: "Example relationship",
      source: { ip: "1.1.1.1", organization: "Invented Org", context: "model text" },
      destination: { ip: "2.2.2.2", organization: "Invented Destination", context: "model text" },
      current_alert_domains: ["hallucinated.example"],
      current_alert_packet_evidence: ["invented payload"],
      threat_feed_context: ["hallucinated feed domain"],
    },
  });

  const grounded = groundNetworkRelationshipAnalysis(
    normalized,
    {
      incident: {
        communication_evidence: {
          domains: [{ field: "http_host", value: "current.example" }],
          urls: [{ field: "request_url", value: "https://current.example/login" }],
          packet_content: [{ field: "request_body", snippet: "action=login" }],
        },
      },
    },
    {
      tuple: {
        sourceIp: "151.234.175.98",
        destinationIp: "10.0.0.190",
      },
      ips: [
        {
          ip: "151.234.175.98",
          roles: ["source"],
          asset: { owned: false, organization: null },
          threat: {
            direct: {
              evidence: [{
                provider: "Spamhaus",
                malware: "elf.mirai",
                classification: {
                  identifier: "mirai",
                  taxonomy: "malicious-code",
                  type: "infected-system",
                },
                destination: {
                  ip: "104.131.68.180",
                  port: 6969,
                  fqdn: "feed-only.example",
                },
              }],
            },
          },
        },
        {
          ip: "10.0.0.190",
          roles: ["destination"],
          asset: {
            owned: true,
            organization: "Organization A",
          },
          threat: {},
        },
      ],
    },
  );

  assert.equal(grounded.network_relationship_analysis.source.ip, "151.234.175.98");
  assert.equal(grounded.network_relationship_analysis.source.organization, "");
  assert.equal(grounded.network_relationship_analysis.destination.ip, "10.0.0.190");
  assert.equal(grounded.network_relationship_analysis.destination.organization, "Organization A");
  assert.deepEqual(grounded.network_relationship_analysis.current_alert_domains, [
    "current.example",
    "https://current.example/login",
  ]);
  assert.deepEqual(grounded.network_relationship_analysis.current_alert_packet_evidence, [
    "action=login",
  ]);
  assert.deepEqual(grounded.network_relationship_analysis.threat_feed_context, [
    "151.234.175.98 direct threat-feed evidence from Spamhaus: malware elf.mirai; classification mirai/malicious-code/infected-system; historical destination 104.131.68.180, port 6969, FQDN feed-only.example (feed context only).",
  ]);
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

test("IncidentAnalyzer sends enriched network context to the configured LLM provider", async () => {
  const { IncidentAnalyzer } = require("../src/services/analyzer");
  let capturedContext = null;

  const networkSnapshot = {
    status: "complete",
    generatedAt: "2026-09-08T00:00:00.000Z",
    ips: [
      {
        ip: "10.0.0.10",
        roles: ["source"],
        scope: "private",
        asset: { owned: true, organization: "Organization A" },
        threat: { directMatch: false, relationshipMatch: false },
      },
    ],
    correlations: [],
  };

  const canonicalResponse = {
    verdict: "SUSPICIOUS",
    one_line_summary: "Organizational asset generated a network alert.",
    attack_story: ["The supplied alert was observed."],
    why_alert_triggered: { rule: "Example Rule", evidence: ["Matched alert evidence"] },
    observed_evidence: ["Source IP belongs to Organization A."],
    detection_analysis: { rule_logic: "Example detection", limitations: "Threat evidence absent." },
    behavior_analysis: "Requires analyst review.",
    attack_mapping: [],
    risk_assessment: { severity: "medium", confidence: 70, reasoning: "Limited evidence." },
    analyst_decision: { action: "INVESTIGATE", reason: "Validate activity." },
    false_positive_analysis: ["Expected organizational traffic is possible."],
    recommended_investigation_steps: ["Review source host telemetry."],
    final_soc_note: "Investigate.",
  };

  const analyzer = new IncidentAnalyzer({
    llm: {
      getMetadata: () => ({ provider: "test", model: "test-model" }),
      async analyze(context) {
        capturedContext = context;
        return canonicalResponse;
      },
    },
    networkIntelligence: {
      async enrich() {
        return networkSnapshot;
      },
    },
    alertRepository: {},
    ruleResolver: {},
    logger: { info() {}, warn() {}, error() {} },
  });

  const ruleResolution = {
    status: "matched",
    matchType: "exact_signature",
    candidateCount: 1,
    rule: {
      ruleId: "1",
      revision: 1,
      title: "Example Rule",
      protocol: "tcp",
      parsedRule: { flow: [], contents: [], pcre: [], references: [] },
      rawRule: "alert tcp any any -> any any",
    },
  };

  const result = await analyzer.analyzePayload(
    { src_ip: "10.0.0.10", signature: "Example Rule" },
    { ruleResolution },
  );

  assert.equal(capturedContext.network_intelligence, networkSnapshot);
  assert.equal(result.networkIntelligence, networkSnapshot);
  assert.equal(result.metadata.enrichmentStatus, "complete");
});


test("air-gapped mode rejects cloud LLM calls before any request is attempted", async () => {
  const { createConfiguredLlmProvider } = require("../src/services/llmProviders");

  const provider = createConfiguredLlmProvider({
    llmProvider: "openai",
    airGapped: true,
    openaiApiKey: "test-key",
    openaiModel: "test-model",
    openaiTimeoutMs: 100,
  });

  await assert.rejects(
    () => provider.analyze({ incident: {} }),
    /disabled while AIR_GAPPED=true/,
  );
});

test("local LLM provider keeps the same analyze contract for future on-prem use", () => {
  const { createConfiguredLlmProvider } = require("../src/services/llmProviders");

  const provider = createConfiguredLlmProvider({
    llmProvider: "local",
    airGapped: true,
    localLlmApiKey: "local",
    localLlmModel: "soc-local-model",
    localLlmBaseUrl: "http://127.0.0.1:9000/v1",
    localLlmTimeoutMs: 1000,
    localLlmUseJsonMode: false,
  });

  assert.deepEqual(provider.getMetadata(), {
    provider: "local",
    model: "soc-local-model",
  });
  assert.equal(typeof provider.analyze, "function");
});
