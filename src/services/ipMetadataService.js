const fs = require("node:fs");
const { settings } = require("../core/config");

class IpMetadataService {
  constructor({
    mmdbPath = settings.ipinfoMmdbPath,
    readerFactory = defaultReaderFactory,
    logger = null,
  } = {}) {
    this.mmdbPath = mmdbPath;
    this.readerFactory = readerFactory;
    this.logger = logger;
    this.readerPromise = null;
  }

  async lookup(ip) {
    if (!this.mmdbPath) return { status: "not_configured", provider: "ipinfo-mmdb" };

    try {
      const reader = await this.getReader();
      if (!reader) return { status: "unavailable", provider: "ipinfo-mmdb" };

      const record = reader.get(ip);
      if (!record) {
        return {
          status: "available",
          provider: "ipinfo-mmdb",
          matched: false,
        };
      }

      return {
        status: "available",
        provider: "ipinfo-mmdb",
        matched: true,
        ...normalizeMmdbRecord(record),
      };
    } catch (error) {
      this.logger?.warn?.({ err: error, ip }, "IPinfo MMDB lookup failed");
      return {
        status: "unavailable",
        provider: "ipinfo-mmdb",
        reason: "mmdb_lookup_failed",
      };
    }
  }

  async getReader() {
    if (!this.mmdbPath) return null;

    if (!this.readerPromise) {
      this.readerPromise = (async () => {
        if (!fs.existsSync(this.mmdbPath)) {
          throw new Error(`IPinfo MMDB file not found: ${this.mmdbPath}`);
        }
        return this.readerFactory(this.mmdbPath);
      })().catch((error) => {
        this.readerPromise = null;
        throw error;
      });
    }

    return this.readerPromise;
  }
}

async function defaultReaderFactory(filePath) {
  const maxmind = require("maxmind");
  return maxmind.open(filePath);
}

function normalizeMmdbRecord(record = {}) {
  const asn = numberOrNull(firstDefined(
    record.asn,
    record.autonomous_system_number,
    record.traits?.autonomous_system_number,
  ));

  const asName = stringOrNull(firstDefined(
    record.as_name,
    record.asn_name,
    record.autonomous_system_organization,
    record.traits?.autonomous_system_organization,
  ));

  const countryCode = stringOrNull(firstDefined(
    record.country_code,
    record.country?.iso_code,
    record.registered_country?.iso_code,
  ));

  const country = stringOrNull(firstDefined(
    record.country_name,
    record.country?.names?.en,
    record.country?.name,
    record.registered_country?.names?.en,
  ));

  const city = stringOrNull(firstDefined(
    record.city_name,
    record.city?.names?.en,
    record.city?.name,
  ));

  const organization = stringOrNull(firstDefined(
    record.organization,
    record.org,
    record.company?.name,
    record.name,
  ));

  const domain = stringOrNull(firstDefined(
    record.domain,
    record.company?.domain,
    record.as_domain,
  ));

  const latitude = numberOrNull(firstDefined(
    record.latitude,
    record.location?.latitude,
  ));

  const longitude = numberOrNull(firstDefined(
    record.longitude,
    record.location?.longitude,
  ));

  const privacy = normalizePrivacy(record.privacy || record.traits || {});

  return compactObject({
    asn,
    asName,
    organization,
    domain,
    countryCode,
    country,
    city,
    latitude,
    longitude,
    privacy,
  });
}

function normalizePrivacy(value = {}) {
  const privacy = compactObject({
    vpn: booleanOrNull(firstDefined(value.vpn, value.is_vpn)),
    proxy: booleanOrNull(firstDefined(value.proxy, value.is_proxy, value.is_anonymous_proxy)),
    tor: booleanOrNull(firstDefined(value.tor, value.is_tor_exit_node)),
    hosting: booleanOrNull(firstDefined(value.hosting, value.is_hosting)),
  });
  return Object.keys(privacy).length ? privacy : null;
}

function compactObject(value) {
  return Object.fromEntries(
    Object.entries(value).filter(([, item]) => item !== null && item !== undefined && item !== ""),
  );
}

function firstDefined(...values) {
  return values.find((value) => value !== undefined && value !== null);
}

function stringOrNull(value) {
  if (value === undefined || value === null) return null;
  const text = String(value).trim();
  return text || null;
}

function numberOrNull(value) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : null;
}

function booleanOrNull(value) {
  if (value === true || value === false) return value;
  return null;
}

module.exports = {
  IpMetadataService,
  normalizeMmdbRecord,
};
