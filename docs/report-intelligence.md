# Historical Report Intelligence

This feature converts local DOCX security reports into a structured MongoDB dataset. It is designed for air-gapped use: report files never need to leave the SOC server.

## 1. Configure the local report root

Set a local directory in `.env`:

```env
REPORTS_ROOT=/data/security-reports
REPORT_IMPORT_MAX_FILE_BYTES=26214400
```

The service expects a Jalali-year folder beneath that root:

```text
/data/security-reports/
└── 1404/
    ├── 14040201_21_6F.docx
    ├── report-002.docx
    └── ...
```

Nested folders under a year are supported. Temporary Word lock files beginning with `~$` are ignored.

## 2. Local dependency

DOCX files are ZIP containers. The parser reads `word/document.xml` with the local `unzip` command.

On Debian/Ubuntu systems:

```bash
sudo apt-get install unzip
```

No cloud document service is used.

### Parser layout

`src/services/reportParser/index.js` is the only entry point. It reads each DOCX once and runs the stages listed there in order (base extraction, table enrichment, finding catalog, date/type reconciliation, APT title override, target scope, mixed and structured asset recovery). Each stage lives in its own module under `src/services/reportParser/` and has a matching `test/reportParser*.test.js` file.

When a stage changes extraction output, bump `PARSER_VERSION` in `index.js` so `npm run reconcile:reports` flags records parsed by the previous pipeline as `stale_parser`.

## 3. Dry-run the 1404 dataset

```bash
npm run import:reports -- --year=1404 --dry-run
```

The command scans, parses and validates the files but does not change MongoDB.

## 4. Import

```bash
npm run import:reports -- --year=1404
```

The importer is idempotent for unchanged files. Existing report numbers are updated if the source document changes; unchanged documents are skipped.

The same actions are available in the panel under:

```text
Reports → Local Import
```

## 5. Extracted fields

The parser targets the current report template and stores:

- report title
- report number
- Jalali date / year / month / day
- report provider
- target organization
- target IP
- severity score and normalized severity level
- urgency
- normalized vulnerability family
- description
- affected-system table rows
- recommendations
- source file metadata and SHA-256
- extraction quality warnings

The original DOCX stays in `REPORTS_ROOT`; MongoDB stores the normalized dataset and extracted text.

## 6. Quality review

A report receives review warnings when important fields are missing or when the target organization/IP differs from values in the affected-system table. These warnings are visible in the report detail drawer and in the yearly `Needs Review` metric.

## 7. Statistics and Copilot

The Reports workspace provides deterministic MongoDB-backed statistics. The main SOC Copilot also recognizes historical-report questions before invoking the LLM planner.

Examples:

```text
در سال ۱۴۰۴ چند گزارش داشتیم؟
در سال ۱۴۰۴ چند گزارش XSS داشتیم؟
بیشترین آسیب‌پذیری سال ۱۴۰۴ چه بوده؟
کدام سازمان بیشترین گزارش High داشته؟
چند درصد گزارش‌های ۱۴۰۴ نیازمند اقدام فوری بوده‌اند؟
روند ماهانه گزارش‌های ۱۴۰۴ را نشان بده
برای IP 62.60.167.73 چه گزارش‌هایی داریم؟
```

Counts and percentages are calculated by MongoDB/backend code, not by the language model.

## 8. Deferred work

RAG/vector search is intentionally not required for V1. It can later be layered over `description` and `recommendations` for semantic questions after the structured dataset has been validated against the real 1404 reports.
