const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");

const { ReportUploadReviewService } = require("../src/services/reportUploadReviewService");

function createModel(existing = new Map()) {
  const writes = [];
  return {
    writes,
    findOne(filter) {
      const value = existing.get(filter.documentKey) || null;
      return {
        lean() { return this; },
        async exec() { return value; },
      };
    },
    findOneAndUpdate(filter, update) {
      return {
        async exec() {
          writes.push({ filter, record: update.$set });
          existing.set(filter.documentKey, update.$set);
          return update.$set;
        },
      };
    },
  };
}

async function fakeParser(filePath, { yearHint }) {
  const buffer = await fs.readFile(filePath);
  const sha256 = crypto.createHash("sha256").update(buffer).digest("hex");
  const basename = path.basename(filePath);
  return {
    documentKey: null,
    reportNumber: `R-${sha256.slice(0, 8)}`,
    reportDateRaw: "01/01/1404",
    year: yearHint,
    month: 1,
    day: 1,
    title: `Synthetic preview ${basename}`,
    reportType: "vulnerability",
    provider: "SOC Test",
    contact: null,
    effect: "Test effect",
    target: { organization: "سازمان نمونه", ip: "10.20.30.40", rawIp: "10.20.30.40" },
    severity: { raw: "8.8", score: 8.8, level: "high" },
    urgency: { raw: "نیازمند اقدام", normalized: "action_required" },
    finding: { type: "xss", name: "Cross-Site Scripting", category: "web", cwe: "CWE-79" },
    vulnerability: { normalizedName: "xss", category: "web", cwe: "CWE-79" },
    cves: ["CVE-2024-12345"],
    affectedCves: ["CVE-2024-12345"],
    description: "This is the extracted description that an analyst should see before saving.",
    conclusion: "Synthetic conclusion.",
    recommendations: ["Patch the affected service", "Validate remediation"],
    affectedSystems: [{
      organization: "سازمان نمونه",
      ip: "10.20.30.40",
      domain: "example.invalid",
      url: "https://example.invalid/test",
      service: "HTTPS",
      port: 443,
      cves: ["CVE-2024-12345"],
    }],
    phishingInfrastructure: [],
    indicators: [],
    source: {
      filename: basename,
      relativePath: basename,
      sha256,
      sizeBytes: buffer.length,
      importedAt: new Date(),
    },
    extraction: { parserVersion: "test", warnings: [] },
    fullText: "Synthetic report",
  };
}

async function createUpload(directory, name, content) {
  const filePath = path.join(directory, `${crypto.randomUUID()}.tmp`);
  await fs.writeFile(filePath, content);
  return {
    path: filePath,
    originalname: name,
    size: Buffer.byteLength(content),
  };
}

test("uploaded reports are previewed without database writes, then saved only after confirmation", async () => {
  const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "report-review-test-"));
  const incoming = path.join(tempRoot, "incoming");
  await fs.mkdir(incoming, { recursive: true });

  try {
    const model = createModel();
    const service = new ReportUploadReviewService({
      model,
      parser: fakeParser,
      root: path.join(tempRoot, "reports"),
      stagingRoot: path.join(tempRoot, "staging"),
    });
    const upload = await createUpload(incoming, "security-report.docx", "docx-test-content");

    const preview = await service.previewUpload(1404, [upload]);
    assert.equal(preview.ready, 1);
    assert.equal(preview.failed, 0);
    assert.equal(preview.storagePolicy.databaseChanged, false);
    assert.equal(preview.previews[0].action, "new");
    assert.equal(preview.previews[0].organization, "سازمان نمونه");
    assert.match(preview.previews[0].descriptionPreview, /analyst should see/);
    assert.deepEqual(preview.previews[0].recommendationPreview, [
      "Patch the affected service",
      "Validate remediation",
    ]);
    assert.equal(model.writes.length, 0, "preview must not persist to MongoDB");

    const result = await service.commitUpload(preview.sessionToken, {
      selectedIds: [preview.previews[0].id],
    });
    assert.equal(result.imported, 1);
    assert.equal(result.failed, 0);
    assert.equal(model.writes.length, 1);

    const saved = model.writes[0].record;
    assert.equal(saved.source.relativePath, "1404/security-report.docx");
    assert.equal(await fs.readFile(path.join(tempRoot, "reports", "1404", "security-report.docx"), "utf8"), "docx-test-content");

    await assert.rejects(
      () => service.readManifest(preview.sessionToken),
      /not found or has expired/,
    );
  } finally {
    await fs.rm(tempRoot, { recursive: true, force: true });
  }
});

test("review session supports selecting only a subset and cancel deletes staged data", async () => {
  const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "report-review-subset-"));
  const incoming = path.join(tempRoot, "incoming");
  await fs.mkdir(incoming, { recursive: true });

  try {
    const model = createModel();
    const service = new ReportUploadReviewService({
      model,
      parser: fakeParser,
      root: path.join(tempRoot, "reports"),
      stagingRoot: path.join(tempRoot, "staging"),
    });
    const uploads = [
      await createUpload(incoming, "one.docx", "one"),
      await createUpload(incoming, "two.docx", "two"),
    ];

    const preview = await service.previewUpload(1404, uploads);
    assert.equal(preview.previews.length, 2);

    const result = await service.commitUpload(preview.sessionToken, {
      selectedIds: [preview.previews[1].id],
    });
    assert.equal(result.selected, 1);
    assert.equal(result.imported, 1);
    assert.equal(model.writes.length, 1);
    assert.equal(model.writes[0].record.source.filename, "two.docx");

    const cancelUpload = await createUpload(incoming, "cancel.docx", "cancel");
    const cancelPreview = await service.previewUpload(1404, [cancelUpload]);
    const cancelled = await service.cancelUpload(cancelPreview.sessionToken);
    assert.equal(cancelled.cancelled, true);
    await assert.rejects(() => service.readManifest(cancelPreview.sessionToken), /not found or has expired/);
  } finally {
    await fs.rm(tempRoot, { recursive: true, force: true });
  }
});
