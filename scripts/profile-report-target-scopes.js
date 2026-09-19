#!/usr/bin/env node

const path = require("node:path");
const { ReportImportService, normalizeYear } = require("../src/services/reportImportService");

async function main() {
  const yearArg = process.argv.find((arg) => arg.startsWith("--year="));
  const year = normalizeYear(yearArg ? yearArg.slice("--year=".length) : undefined);
  const importer = new ReportImportService();
  const scan = await importer.scanYear(year);
  const rows = [];
  const failures = [];
  const modeCounts = {};
  const scopeTypeCounts = {};

  for (const file of scan.files) {
    if (!file.eligible) continue;
    try {
      const parsed = await importer.parser(
        path.resolve(importer.root, file.relativePath),
        { yearHint: year },
      );
      const mode = parsed.target?.mode || "unknown";
      const scopeType = parsed.target?.scopeType || null;
      modeCounts[mode] = (modeCounts[mode] || 0) + 1;
      if (scopeType) scopeTypeCounts[scopeType] = (scopeTypeCounts[scopeType] || 0) + 1;

      if (mode === "scope" || mode === "multi_target" || parsed.target?.tableReference) {
        const organizations = [...new Set(
          (parsed.affectedSystems || []).map((item) => item.organization).filter(Boolean),
        )];
        const ips = [...new Set(
          (parsed.affectedSystems || []).map((item) => item.ip).filter(Boolean),
        )];
        rows.push({
          file: file.relativePath,
          reportNumber: parsed.reportNumber || null,
          title: parsed.title || null,
          mode,
          scopeType,
          scopeName: parsed.target?.scopeName || null,
          rawOrganization: parsed.target?.rawOrganization || null,
          rawIp: parsed.target?.rawIp || null,
          tableReference: parsed.target?.tableReference || null,
          organization: parsed.target?.organization || null,
          ip: parsed.target?.ip || null,
          affectedSystemCount: (parsed.affectedSystems || []).length,
          affectedOrganizations: organizations,
          affectedIps: ips,
          warnings: parsed.extraction?.warnings || [],
        });
      }
    } catch (error) {
      failures.push({
        file: file.relativePath,
        error: String(error?.message || error).slice(0, 500),
      });
    }
  }

  const scopeCount = rows.filter((row) => row.mode === "scope").length;
  const multiTargetCount = rows.filter((row) => row.mode === "multi_target").length;
  const tableReferenceCount = rows.filter((row) => row.tableReference).length;
  const unresolvedTableCount = rows.filter((row) => row.warnings.includes("target_table_reference_unresolved")).length;

  process.stdout.write(`${JSON.stringify({
    year,
    discovered: scan.count,
    eligible: scan.eligibleCount,
    modeCounts,
    scopeTypeCounts,
    scopeCount,
    multiTargetCount,
    tableReferenceCount,
    unresolvedTableCount,
    rows,
    failures,
  }, null, 2)}\n`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
