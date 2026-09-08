const SOURCE_IP_PATHS = [
  "src_ip",
  "source_ip",
  "client_ip",
  "source.ip",
  "network.source.ip",
  "src",
];

const DESTINATION_IP_PATHS = [
  "dst_ip",
  "dest_ip",
  "destination_ip",
  "server_ip",
  "destination.ip",
  "network.destination.ip",
  "dst",
];

const SOURCE_PORT_PATHS = ["src_port", "source_port", "source.port", "network.source.port"];
const DESTINATION_PORT_PATHS = [
  "dst_port",
  "dest_port",
  "destination_port",
  "destination.port",
  "network.destination.port",
];
const PROTOCOL_PATHS = ["protocol", "proto", "protocol.transport", "network.transport"];

function extractIpIndicators(event = {}) {
  const indicators = new Map();

  collectRole(event, SOURCE_IP_PATHS, "source", indicators);
  collectRole(event, DESTINATION_IP_PATHS, "destination", indicators);

  return [...indicators.values()];
}

function collectRole(event, paths, role, indicators) {
  for (const path of paths) {
    const raw = getPathValue(event, path);
    for (const value of normalizeCandidates(raw)) {
      const ip = normalizeIpv4(value);
      if (!ip) continue;

      const existing = indicators.get(ip) || {
        ip,
        roles: [],
        fields: [],
        scope: classifyIpv4(ip),
        networkZone: classifyNetworkZone(ip),
        nationalNetwork: isNationalNetworkIpv4(ip),
      };

      if (!existing.roles.includes(role)) existing.roles.push(role);
      if (!existing.fields.includes(path)) existing.fields.push(path);
      indicators.set(ip, existing);
    }
  }
}

function extractNetworkTuple(event = {}) {
  return {
    sourceIp: firstIpv4(event, SOURCE_IP_PATHS),
    sourcePort: firstPort(event, SOURCE_PORT_PATHS),
    destinationIp: firstIpv4(event, DESTINATION_IP_PATHS),
    destinationPort: firstPort(event, DESTINATION_PORT_PATHS),
    protocol: firstString(event, PROTOCOL_PATHS)?.toLowerCase() || null,
  };
}

function firstIpv4(event, paths) {
  for (const path of paths) {
    const values = normalizeCandidates(getPathValue(event, path));
    for (const value of values) {
      const ip = normalizeIpv4(value);
      if (ip) return ip;
    }
  }
  return null;
}

function firstPort(event, paths) {
  for (const path of paths) {
    const value = getPathValue(event, path);
    const numeric = Number(value);
    if (Number.isInteger(numeric) && numeric >= 0 && numeric <= 65535) return numeric;
  }
  return null;
}

function firstString(event, paths) {
  for (const path of paths) {
    const value = getPathValue(event, path);
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return null;
}

function getPathValue(object, path) {
  if (!object || typeof object !== "object") return undefined;
  if (Object.prototype.hasOwnProperty.call(object, path)) return object[path];

  let current = object;
  for (const segment of path.split(".")) {
    if (!current || typeof current !== "object" || !(segment in current)) return undefined;
    current = current[segment];
  }
  return current;
}

function normalizeCandidates(value) {
  if (Array.isArray(value)) return value.flatMap(normalizeCandidates);
  if (value === null || value === undefined) return [];
  return [String(value).trim()].filter(Boolean);
}

function normalizeIpv4(value) {
  const input = String(value || "").trim();
  const parts = input.split(".");
  if (parts.length !== 4) return null;

  const normalized = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet < 0 || octet > 255) return null;
    normalized.push(String(octet));
  }
  return normalized.join(".");
}

function classifyIpv4(ip) {
  const normalized = normalizeIpv4(ip);
  if (!normalized) return "invalid";
  const [a, b] = normalized.split(".").map(Number);

  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) {
    return "private";
  }
  if (a === 127) return "loopback";
  if (a === 169 && b === 254) return "link_local";
  if (a === 100 && b >= 64 && b <= 127) return "shared";
  if (a >= 224 && a <= 239) return "multicast";

  const octets = normalized.split(".").map(Number);
  const documentation =
    (a === 192 && b === 0 && octets[2] === 2) ||
    (a === 198 && b === 51 && octets[2] === 100) ||
    (a === 203 && b === 0 && octets[2] === 113);
  const benchmark = a === 198 && (b === 18 || b === 19);

  if (documentation || benchmark || a === 0 || a >= 240) return "reserved";
  return "public";
}

function classifyNetworkZone(ip) {
  const normalized = normalizeIpv4(ip);
  if (!normalized) return "invalid";

  const firstOctet = Number(normalized.split(".")[0]);
  const scope = classifyIpv4(normalized);

  // Deployment policy: 10.0.0.0/8 and every public IPv4 are National Network.
  // Keep address-space scope separate from deployment trust-boundary policy.
  if (firstOctet === 10 || scope === "public") return "national_network";
  if (scope === "private") return "private_non_national";
  return scope;
}

function isNationalNetworkIpv4(ip) {
  return classifyNetworkZone(ip) === "national_network";
}

module.exports = {
  SOURCE_IP_PATHS,
  DESTINATION_IP_PATHS,
  extractIpIndicators,
  extractNetworkTuple,
  normalizeIpv4,
  classifyIpv4,
  classifyNetworkZone,
  isNationalNetworkIpv4,
  getPathValue,
};
