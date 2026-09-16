#!/usr/bin/env node

const path = require("node:path");
const base = require("../src/services/reportDocxParser");
const v4 = require("../src/services/reportDocxParserV4");
const { ReportImportService, normalizeYear } = require("../src/services/reportImportService");

async function main() {
  const yearArg = process.argv.find((arg) => arg.startsWith("--year="));
  const thresholdArg = process.argv.find((arg) => arg.startsWith("--large-threshold="));
  const year = normalizeYear(yearArg ? yearArg.slice("--year=".length) : undefined);
  const largeThreshold = Math.max(1, Number.parseInt(thresholdArg?.slice("--large-threshold=".length) || "100", 10) || 100);
  const importer = new ReportImportService();
  const scan = await importer.scanYear(year);
  const rows = [];
  const failures = [];

  for (const file of scan.files) {
    if (!file.eligible) continue;
    const absolutePath = path.resolve(importer.root, file.relativePath);

    try {
      const report = await importer.parser(absolutePath, { yearHint: year });
      const warnings = report.extraction?.warnings || [];
      const affectedSystemCount = (report.affectedSystems || []).length;
      const unresolved = warnings.includes("target_table_reference_unresolved");
      const large = affectedSystemCount >= largeThreshold;
      if (!unresolved && !large) continue;

      const xml = await base.extractDocumentXml(absolutePath);
      const parsed = base.parseWordXml(xml);
      rows.push({
        file: file.relativePath,
        reason: unresolved ? "unresolved_table_reference" : "large_affected_system_table",
        mode: report.target?.mode || "unknown",
        scopeType: report.target?.scopeType || null,
        tableReference: report.target?.tableReference || null,
        affectedSystemCount,
        warnings,
        tables: (parsed.tables || []).map((table, tableIndex) => summarizeTable(table, tableIndex)),
      });
    } catch (error) {
      failures.push({
        file: file.relativePath,
        error: String(error?.message || error).slice(0, 500),
      });
    }
  }

  process.stdout.write(`${JSON.stringify({
    year,
    largeThreshold,
    discovered: scan.count,
    eligible: scan.eligibleCount,
    diagnosticCount: rows.length,
    unresolvedCount: rows.filter((row) => row.reason === "unresolved_table_reference").length,
    largeTableCount: rows.filter((row) => row.reason === "large_affected_system_table").length,
    rows,
    failures,
    privacy: {
      rawCellValuesIncluded: false,
      organizationNamesIncluded: false,
      ipValuesIncluded: false,
      purpose: "table shape/header diagnostics only",
    },
  }, null, 2)}\n`);
}

function summarizeTable(table, tableIndex) {
  const rows = Array.isArray(table) ? table : [];
  const maxColumns = Math.max(0, ...rows.map((row) => Array.isArray(row) ? row.length : 0));
  const nonEmptyRows = rows.filter((row) => Array.isArray(row) && row.some((cell) => clean(cell))).length;
  const rowsWithIpv4 = rows.filter((row) => base.normalizeFirstIp((row || []).join(" "))).length;
  const rowsWithUrl = rows.filter((row) => base.extractUrls((row || []).join(" ")).length > 0).length;
  const candidateHeaderRows = [];

  rows.forEach((row, rowIndex) => {
    if (!Array.isArray(row)) return;
    const recognized = unique(row.map(v4.normalizeHeaderV4).filter(Boolean));
    const hints = headerHints(row);
    if (!recognized.length && hints.length < 2) return;
    candidateHeaderRows.push({
      rowIndex,
      nonEmptyCells: row.filter((cell) => clean(cell)).length,
      recognized,
      hints,
    });
  });

  return {
    tableIndex: tableIndex + 1,
    rowCount: rows.length,
    nonEmptyRowCount: nonEmptyRows,
    maxColumns,
    rowsWithIpv4,
    rowsWithUrl,
    candidateHeaderRows: candidateHeaderRows.slice(0, 12),
    columnSignals: summarizeColumns(rows, maxColumns),
  };
}

function summarizeColumns(rows, maxColumns) {
  const output = [];
  for (let index = 0; index < maxColumns; index += 1) {
    const cells = rows.map((row) => clean(row?.[index])).filter(Boolean);
    if (!cells.length) continue;
    output.push({
      columnIndex: index,
      nonEmptyCells: cells.length,
      ipv4Cells: cells.filter((cell) => Boolean(base.normalizeFirstIp(cell))).length,
      urlCells: cells.filter((cell) => base.extractUrls(cell).length > 0).length,
      cveCells: cells.filter((cell) => base.extractCves(cell).length > 0).length,
      numericCells: cells.filter((cell) => /^\d+(?:[.,]\d+)?$/.test(base.toAsciiDigits(cell).replace(/,/g, ""))).length,
      maxLength: Math.max(...cells.map((cell) => cell.length)),
    });
  }
  return output;
}

function headerHints(row) {
  const text = base.normalizeLabel((row || []).join(" "));
  const hints = [];
  const patterns = [
    ["organization_like", /سازمان|دستگاه|نهاد|شرکت|مجموعه|organization/],
    ["name_like", /(?:^|\s)نام(?:\s|$)|name/],
    ["ip_like", /(?:^|\s)ip(?:\s|$)|آی\s*پی|آدرس/],
    ["domain_like", /دامنه|domain/],
    ["url_like", /url|نشانی|وب|مسیر/],
    ["port_like", /پورت|port/],
    ["service_like", /سرویس|service/],
    ["asset_like", /دارایی|سامانه|سیستم|میزبان|host|asset|system/],
    ["row_number_like", /ردیف|شماره|index|row/],
    ["finding_like", /آسیب|ضعف|رخداد|finding|vulnerability/],
    ["description_like", /شرح|توضیح|description/],
  ];
  for (const [name, pattern] of patterns) {
    if (pattern.test(text)) hints.push(name);
  }
  return hints;
}

function clean(value) {
  return base.normalizeWhitespace(String(value || ""));
}

function unique(values) {
  return [...new Set(values)];
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
