const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const zlib = require("node:zlib");
const { PARSER_VERSION, parseDocxReport } = require("../src/services/reportParser");

function cell(value) {
  return `<w:tc><w:p><w:r><w:t>${value}</w:t></w:r></w:p></w:tc>`;
}

function table(rows) {
  return `<w:tbl>${rows.map((row) => `<w:tr>${row.map(cell).join("")}</w:tr>`).join("")}</w:tbl>`;
}

function p(text) {
  return `<w:p><w:r><w:t>${text}</w:t></w:r></w:p>`;
}

// Minimal single-entry ZIP (stored, no compression): enough for word/document.xml.
function zipSingleFile(name, content) {
  const nameBuffer = Buffer.from(name, "utf8");
  const data = Buffer.from(content, "utf8");
  const crc = zlib.crc32(data);

  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(0x0800, 6);
  local.writeUInt32LE(crc, 14);
  local.writeUInt32LE(data.length, 18);
  local.writeUInt32LE(data.length, 22);
  local.writeUInt16LE(nameBuffer.length, 26);

  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(20, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt16LE(0x0800, 8);
  central.writeUInt32LE(crc, 16);
  central.writeUInt32LE(data.length, 20);
  central.writeUInt32LE(data.length, 24);
  central.writeUInt16LE(nameBuffer.length, 28);

  const localSize = local.length + nameBuffer.length + data.length;
  const centralSize = central.length + nameBuffer.length;
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(1, 8);
  end.writeUInt16LE(1, 10);
  end.writeUInt32LE(centralSize, 12);
  end.writeUInt32LE(localSize, 16);

  return Buffer.concat([local, nameBuffer, data, central, nameBuffer, end]);
}

async function writeDocx(parts) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "report-parser-"));
  const filePath = path.join(dir, "report.docx");
  const xml = `<w:document xmlns:w="urn:test"><w:body>${parts.join("\n")}</w:body></w:document>`;
  await fs.writeFile(filePath, zipSingleFile("word/document.xml", xml));
  return { filePath, cleanup: () => fs.rm(dir, { recursive: true, force: true }) };
}

function reportHeader({ title, organization, ip }) {
  return [
    p(title),
    table([
      ["تاریخ ارائه گزارش:", "01/02/1404", "ارائه‌کننده گزارش:", "مرکز"],
      ["شماره گزارش:", "14040201_21_6F", "اطلاعات تماس:", "+98"],
    ]),
    p("اطلاعات سازمان"),
    table([
      ["سازمان هدف:", organization, "شدت رخداد:", "7.5"],
      ["آدرس IP:", ip, "فوریت اقدام:", "نیازمند اقدام فوری"],
    ]),
    p("شرح رخداد"),
    p("شرح نمونه برای گزارش."),
  ];
}

test("pipeline stamps the current parser version and file provenance", async () => {
  const { filePath, cleanup } = await writeDocx(reportHeader({
    title: "فعالیت APT و کد مخرب",
    organization: "سازمان نمونه",
    ip: "5.6.7.8",
  }));

  try {
    const report = await parseDocxReport(filePath, { yearHint: 1404 });
    assert.equal(report.extraction.parserVersion, PARSER_VERSION);
    assert.equal(report.finding.type, "apt_malicious_code_activity");
    assert.equal(report.reportType, "malware");
    assert.equal(report.target.mode, "single");
    assert.equal(report.target.ip, "5.6.7.8");
    assert.equal(report.source.filename, "report.docx");
    assert.match(report.source.sha256, /^[a-f0-9]{64}$/);
  } finally {
    await cleanup();
  }
});

test("pipeline runs scope resolution and structured asset recovery from report tables", async () => {
  const { filePath, cleanup } = await writeDocx([
    ...reportHeader({ title: "ارتباط با سرور مخرب", organization: "بانک‌ها", ip: "جدول 5" }),
    p("جدول 5"),
    table([
      ["IP مبدا", "نام سازمان", "مقدار مقصد", "شرح"],
      ["198.51.100.10", "سازمان نمونه", "10.20.30.40", "نمونه"],
      ["198.51.100.11", "سازمان دوم", "10.20.30.41", "نمونه"],
    ]),
  ]);

  try {
    const report = await parseDocxReport(filePath);
    assert.equal(report.target.mode, "multi_target");
    assert.deepEqual(report.affectedSystems.map((item) => item.ip), ["10.20.30.40", "10.20.30.41"]);
    assert.ok(report.extraction.warnings.includes("structured_asset_table_recovered"));
  } finally {
    await cleanup();
  }
});

test("pipeline rejects non-DOCX files before reading them", async () => {
  await assert.rejects(parseDocxReport("/tmp/report.pdf"), /Only \.docx files are supported/);
});
