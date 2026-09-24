# AI-Driven SOC

Node.js/Express SOC triage service that receives Splunk-style alerts, stores them in MongoDB, resolves detection signatures against imported IDS/IPS rules, and lets an analyst trigger evidence-bounded AI analysis from the React panel.

## Current workflow

```text
Splunk / SIEM alert
      ↓
POST /webhook-alert
      ↓
MongoDB Alert queue
      ↓
Deterministic Signature → DetectionRule resolution
      ↓
Analyst opens /panel/ and clicks AI Analyze
      ↓
Incident evidence + matched detection rule + local network intelligence → LLM
      ↓
Canonical SOC assessment is validated and persisted
```

V1 is intentionally human-in-the-loop. Alerts without a Signature, or alerts whose Signature cannot be matched deterministically to a detection rule, remain visible but are not sent to the LLM.

## Stack

- Node.js / Express
- MongoDB / Mongoose
- Swappable OpenAI / local OpenAI-compatible LLM provider
- Zod validation
- React / TypeScript / Vite / Ant Design
- TanStack Query

## Run

```bash
npm install
export OPENAI_API_KEY="your_key"
export MONGODB_URI="mongodb://localhost:27017/ai-driven-soc"

npm run panel:install
npm run panel:build
npm start
```

Historical DOCX report import also needs the system `unzip` command (see `docs/report-intelligence.md`).

Analyst investigation writes (reviews, dispositions, notes, reopen) require MongoDB **transactions**, which need a replica set or sharded cluster. A single-node replica set is enough:

```bash
mongod --replSet rs0 --dbpath /data/db
mongosh --eval 'rs.initiate()'
export MONGODB_URI="mongodb://localhost:27017/ai-driven-soc?replicaSet=rs0"
```

Against a standalone `mongod` the rest of the service works, investigation reads work, and investigation writes return `503` (`reason: transactions_unavailable`) instead of writing without a transaction. Investigation writes also need an authenticated panel user: with `AUTH_ENABLED=false` there is no analyst identity and writes return `401`.

Open:

```text
http://localhost:8000/panel/
```

For backend development:

```bash
npm run dev
```

## Environment variables

- `PORT` (default `8000`)
- `AIR_GAPPED` (default `false`; when `true`, cloud OpenAI calls are blocked and MITRE imports require a local file)
- `LLM_PROVIDER` (default `openai`; set `local` for an on-prem OpenAI-compatible endpoint)
- `OPENAI_API_KEY`
- `OPENAI_MODEL` (default `gpt-4.1`)
- `OPENAI_TIMEOUT_MS` (default `5000`)
- `LOCAL_LLM_BASE_URL` (for example `http://local-llm:8000/v1`)
- `LOCAL_LLM_API_KEY` (default `local`)
- `LOCAL_LLM_MODEL`
- `LOCAL_LLM_TIMEOUT_MS` (default `15000`)
- `LOCAL_LLM_JSON_MODE` (default `false`)
- `IPINFO_MMDB_PATH` (local MMDB file; no runtime network lookup)
- `THREAT_INTEL_EVIDENCE_LIMIT` (default `12`)
- `MONGODB_URI`
- `MONGODB_MAX_RETRIES` (default `3`)
- `MONGODB_RETRY_DELAY_MS` (default `500`)
- `MONGODB_SERVER_SELECTION_TIMEOUT_MS` (default `2000`)
- `MAX_RAW_LOG_CHARS` (default `4000`)
- `MAX_PAYLOAD_SIZE_BYTES` (default `200000`)
- `ENABLE_RATE_LIMITING` (default `true`)
- `LOG_LEVEL` (default `info`)
- `SHUTDOWN_TIMEOUT_MS` (default `10000`; forced exit if open connections block graceful shutdown)

Numeric, boolean, enum (`LLM_PROVIDER`, `LOG_LEVEL`, `SOC_WEEK_START`) and time-zone values are validated at startup. The server and MCP entry points refuse to start and list every invalid variable instead of running with silently wrong values.

## Project layout

```text
src/
  main.js              process entry: config validation, Mongo connection, listen, graceful shutdown
  app.js               createApp(): Express middleware stack, used by main.js and tests
  api/
    routes.js          alert, copilot, investigation, analytics, MITRE and rule routes (wiring only)
    reportRoutes.js    historical report routes (wiring only)
    authRoutes.js      panel sign-in
    controllers/       request/response handling per resource
    presenters/        API shapes for persisted documents
    middleware/        auth, async handler, central error handler
  core/                config, logging, error types
  config/              stable vocabularies (disposition outcomes, actions, reason codes)
  investigation/       pure investigation logic: event schemas, triage reducer, analysis references, feedback metrics
  services/            domain logic (analysis, rule resolution, reports, copilot, investigation)
  repositories/        MongoDB access
  models/              Mongoose schemas
  copilot/, mcp/       Copilot query planning and MCP server
panel-ui/              React analyst panel
scripts/               import, profiling and maintenance CLIs
integration/           MongoDB replica-set integration tests (npm run test:integration)
```

## API

Every JSON endpoint uses one envelope:

```json
{ "success": true,  "message": "Success", "data": { }, "timestamp": "..." }
{ "success": false, "detail": "Human-readable reason", "timestamp": "..." }
```

Error responses may carry extra top-level context (for example `aiStatus`, `reason`, `ruleMatch` on a rejected analysis). Unknown routes return `404` in the same format, and unexpected failures return `500` without internal details.

### Health

```text
GET /health
```

Returns `200 {"status":"ok","database":"connected"}` when MongoDB is connected, otherwise `503` with `status: "degraded"`.

### Alert ingestion

```text
POST /webhook-alert
```

Accepts a single alert, a JSON array, or an object with `alerts` / `results` arrays. A deterministic SHA-256 `eventHash` is generated for duplicate detection.

Re-ingesting the same alert updates the latest raw event and rule match but **does not delete previous AI analysis history**.

### Alert queue

```text
GET /alerts
```

Server-side query parameters:

- `page`, `limit` (limit capped at 100)
- `status`: `new` or `analyzed`
- `aiStatus`: `not_analyzed`, `analyzing`, `analyzed`, `failed`
- `severity`
- `source`
- `search` / `q`
- `createdAtFrom` / `from`
- `createdAtTo` / `to`
- `sortBy`: `createdAt`, `updatedAt`, `alertId`, `severity`, `source`
- `sortDirection`: `asc` / `desc`
- `triageStatus`: `open` or `closed` (alerts created before investigations existed count as open)
- `outcome`: `true_positive`, `benign_true_positive`, `false_positive`, `inconclusive`

Invalid `triageStatus` / `outcome` values return `400`. Each alert summary includes a `triage` object: `status`, `version`, `outcome`, `action`, `ticketNumber`, `closedAt`, `updatedAt`, `updatedBy`, `reviewedAnalysisRef` and `latestAnalysisReviewed` (`null` when there is no referenceable analysis).

The React alert table uses this pagination directly; it is no longer limited to the first 50 stored alerts.

### Alert detail

```text
GET /alerts/:id
```

Returns the raw alert, AI lifecycle state, analysis history summaries, latest full analysis, detection-rule context, processing metadata, and `analysisCount`.

Optional SOC projections:

```text
?socFields=mitreAttack,iocs
?mitreAttack=true&threatIntelligence=true
```

### Analyst-triggered AI analysis

```text
POST /alerts/:id/analyze
```

Default behavior reuses the persisted result when the alert is already analyzed.

Explicit re-analysis:

```json
POST /alerts/:id/analyze
{
  "force": true
}
```

Each successful run appends a new summary entry to `Alert.analysis` and updates `fullAnalysis` to the latest canonical result.

### Immediate compatibility endpoint

```text
POST /analyze-incident
```

Runs the same canonical analysis pipeline immediately.

## Analyst investigation and disposition

Records what the analyst did with an alert: how they judged the AI analysis, their disposition and reasons, notes, reopenings, and an external ticket number. This release records **human actions only**. The investigation endpoints never call the LLM and never decide, close or reopen anything automatically. Re-analysis does not change triage either.

### Event model

Every action is an append-only document in the `investigation_events` collection (`src/models/InvestigationEvent.js`):

| Field | Meaning |
| --- | --- |
| `alertRef` | Immutable MongoDB `_id` of the Alert, used for joins, ordering and uniqueness |
| `alertId` | Public alert ID at the time of the event, kept for display |
| `schemaVersion` | `1` |
| `type` | `ai_review`, `disposition`, `note`, `reopened` (writable); `query_run`, `evidence_marked` (reserved) |
| `sequence` | Server-assigned per-alert sequence 1, 2, 3, …; the total order, even when timestamps tie |
| `createdAt` | Server time (UTC) |
| `actor` | `{ kind: "human" \| "ai", id, displayName }`; API writes are always `human` and use `req.user` |
| `payload` | Type-specific body validated with strict Zod schemas (`src/investigation/eventSchemas.js`) |
| `context` | Server-captured `analysisRef`, `analysisSnapshot` and `rule` (see below) |
| `idempotencyKey`, `requestHash` | Duplicate-write protection |

Events are never updated or deleted, and there is no TTL or delete endpoint; corrections are new events. The API resolves the public alert ID to the Alert `_id` and uses that internally, so history stays attached even if re-ingestion changes the public `alertId`.

`query_run` and `evidence_marked` are reserved for future agent workflows. They are validated by the model (MCP tool name from the shared tool list in `src/mcp/toolDefinitions.js`, tool input validated with the Copilot argument schemas, bounded result summary, evidence references; `evidence_marked` also records the evidence and whether it `supports`, `contradicts` or gives `context` for an assessment). No endpoint or UI writes them in V1. Clients can never write `actor.kind: "ai"`.

### Which AI analysis is being reviewed

`analysis[]` stores summaries of each run. `fullAnalysis`, `llmProvider` and `model` are replaced by each re-analysis, so they describe only the latest run. Consequently:

- Only the **latest persisted analysis** can receive a new review. Nothing is reconstructed for older runs.
- The investigation GET returns its reference: zero-based `analysisIndex` (the UI shows run #index+1), its stored `analyzedAt`, and a SHA-256 `fingerprint` of the reviewable context (index, time, verdict, severity, attack mapping, recommendations, provider, model and matched rule ID/revision).
- Reviews must send that reference. Dispositions must send it when an analysis exists, and send `null` otherwise.
- At write time the server stores an immutable **snapshot** on the event: AI verdict, severity, attack mapping, recommendations, provider, model, matched rule ID/revision, plus the reference. Missing legacy metadata is stored as `null` (unknown), never guessed.
- A reference whose analysis no longer exists returns `422`. A reference to an older run, a changed context, or an analysis in progress returns `409`. The client refreshes and keeps its unsaved input.
- The write re-checks the analysis state (index, `analyzedAt`, no newer entry, `aiStatus`, rule, provider/model) atomically in the same transaction as the event insert. A re-analysis that completes mid-write therefore aborts the write instead of attaching it to different data.

Later AI runs never overwrite or move earlier reviews. The timeline shows each review against its original run, and flags when the latest run has no review.

**Limitation:** re-ingesting an alert can update `ruleMatch` without re-analysis. The rule in a snapshot is the alert's matched rule when the event was written. A rule change makes an open review reference stale (`409`).

### Review, disposition, reasons

**AI review** (`ai_review`): four sections, `verdict`, `severity`, `mitre` and `recommendations`, each `agree`, `partially_agree`, `disagree` or `not_reviewed` (the default; nothing is preselected).
- At least one section must be reviewed.
- `disagree` on verdict or severity requires a corrected value from the canonical enums, and it must differ from the AI value.
- Corrections are rejected for sections that are not `disagree`.
- An optional comment of up to 2000 characters.
- A new review supersedes the previous one in the triage summary; all reviews and their snapshots are kept.

**Disposition** (`disposition`):

| Outcome | Definition |
| --- | --- |
| `true_positive` | The detected security concern was confirmed. |
| `benign_true_positive` | The rule correctly detected the behavior, but investigation established that it was authorized or benign. |
| `false_positive` | Investigation established that the detection incorrectly indicated the claimed condition. |
| `inconclusive` | The evidence is insufficient to determine the outcome. |

Actions:
- `ticket_created`, `escalated` and `closed_no_action` close local triage. That does not mean the incident was remediated.
- `monitoring` keeps triage open.

Other disposition fields:
- `reasonCodes` requires one to eight stable reason IDs, each valid for the chosen outcome.
- `reasonText` is required when `other` is selected and optional otherwise.
- `ticketNumber` is optional (up to 128 characters). There is no ticketing integration.

Outcome is never inferred from action or reason: a duplicate ticket is not automatically a false positive, and an authorized scan can be a benign true positive.

**Reason codes** live in `src/config/dispositionReasons.js` and are served by `GET /investigation/reasons`; the panel does not hardcode them. The table below lists each reason's allowed outcomes:

| ID | English | Persian | Allowed outcomes |
| --- | --- | --- | --- |
| `confirmed_malicious_activity` | Confirmed malicious activity | فعالیت مخرب تأییدشده | true positive |
| `authorized_internal_scanner` | Authorized internal scanner | اسکنر داخلی مجاز | benign true positive, false positive |
| `authorized_test_or_simulation` | Authorized test or simulation | آزمون یا شبیه‌سازی مجاز | benign true positive |
| `known_benign_service` | Known benign service | سرویس شناخته‌شده و بی‌خطر | benign true positive, false positive |
| `rule_too_broad` | Detection rule too broad | قاعده تشخیص بیش از حد کلی است | false positive, benign true positive |
| `duplicate_existing_ticket` | Duplicate of an existing ticket | تکراری؛ تیکت موجود | all |
| `remediated_previous_report` | Remediated per a previous report | طبق گزارش قبلی رفع شده است | true positive, benign true positive, inconclusive |
| `insufficient_evidence` | Insufficient evidence | شواهد ناکافی | inconclusive |
| `other` | Other | سایر | all (requires text) |

IDs are stored in events and never renamed or reused. A retired reason stays in the list with `retired: true` so history keeps its label.

**Note** (`note`): nonblank text, up to 4000 characters. **Reopen** (`reopened`): a required reason.

### Triage state and lifecycle

`status` and `aiStatus` are unchanged. `Alert.triage` is a separate projection produced by the pure reducer in `src/investigation/triageReducer.js`:

| Event / action | Effect |
| --- | --- |
| No investigation events | `open`, no disposition or review |
| `ai_review`, `note` | No change to open/closed or the current disposition |
| Disposition with `monitoring` | Stays open; records the disposition |
| Disposition with `ticket_created`, `escalated`, `closed_no_action` | Closes local triage |
| New disposition | Completely supersedes the previous one |
| `reopened` | Opens triage; clears disposition, outcome, action, reasons, ticket and closure time; keeps notes and reviews |

Reopening an alert that is already open (including `monitoring`) returns `409`, unless the request is an identical idempotent retry. `triage.version` equals the latest event `sequence`.

**Legacy alerts** without `triage` are treated as open at version 0 in responses and filters. Optional maintenance:

```bash
npm run investigation:backfill-triage          # idempotent: sets an explicit open projection on legacy alerts
npm run investigation:rebuild-triage           # report projections that differ from an event-log replay
npm run investigation:rebuild-triage -- --apply  # rewrite those projections from the event log
```

The backfill only helps the `triage.status` index serve `triageStatus=open`; queries are correct without it. New indexes are created by Mongoose on startup: `triage.status`/`createdAt`, `triage.outcome`/`createdAt` and `analysis.analyzedAt` on alerts, plus the event indexes above.

### Consistency and idempotency

- The event log is authoritative and the projection is derived from it. Each write inserts the event and updates `Alert.triage` in **one MongoDB transaction**, so both commit or neither does.
- **Idempotency:** every write needs an `Idempotency-Key` header (8–128 characters `[A-Za-z0-9._:-]`), unique per alert.
  - Repeating an identical request (same type, body and user) returns the original event with `200` and `Idempotent-Replayed: true`, without writing again.
  - Reusing a key for different content returns `409 idempotency_key_reused`.
  - The identical-retry check runs before the version check, so a retry is never rejected as stale.
- **Optimistic concurrency:** review, disposition and reopen require `expectedVersion`. For notes it is optional and enforced when sent. A mismatch returns `409 stale_version` with `currentVersion` and the current state.
- A lost race inside the transaction (concurrent write, re-analysis) returns `409 concurrent_change`, and nothing is written.

### Endpoints

All routes sit behind the panel auth gate.

| Method and path | Purpose |
| --- | --- |
| `GET /alerts/:id/investigation?limit=&before=` | Events newest first (`limit` 1–200, default 50; `before` = sequence cursor, `pagination.nextBefore` for the next page), current `state` and `version` derived from the **complete** history, `reviewableAnalysis`, `latestAnalysisReviewed`, and a summary of every stored AI run |
| `POST /alerts/:id/investigation/review` | `{ expectedVersion, analysisRef, payload: { sections, corrections?, comment? } }` |
| `POST /alerts/:id/investigation/disposition` | `{ expectedVersion, analysisRef \| null, payload: { outcome, action, reasonCodes, reasonText?, ticketNumber? } }` |
| `POST /alerts/:id/investigation/notes` | `{ expectedVersion?, payload: { text } }` |
| `POST /alerts/:id/investigation/reopen` | `{ expectedVersion, payload: { reason } }` |
| `GET /investigation/reasons` | Outcomes, actions and reason codes |
| `GET /analytics/ai-accuracy?from=&to=` | Analyst Feedback metrics (below) |

Writes return `201` with `{ event, state, version, replayed }`.

| Status | Meaning |
| --- | --- |
| `401` | No authenticated identity |
| `404` | Unknown alert |
| `422` | Invalid payload, reference or `Idempotency-Key`. The body carries `reason` and `issues[]`. Unknown fields such as `actor`, `createdAt`, `sequence` or `model` are rejected. |
| `409` | Stale version, stale reference, analysis in progress, already open, or reused key |
| `503` | Transactions unavailable |

### Analyst Feedback metrics

`GET /analytics/ai-accuracy` powers the **Analyst Feedback** page. The numbers describe **analyst-reviewed samples**, not calibrated AI accuracy on all SOC traffic. Only `actor.kind: "human"` events count as feedback.

**Window and cohorts**

- The window is a half-open UTC interval `[from, to)` using server event timestamps. It defaults to the last 30 days ending at request time. Malformed timestamps or `from >= to` return `400`.
- **Review cohort:** per alert, the latest human `ai_review` created before `to`, included only if it is at or after `from`.
  - A later note does not supersede a review, and a reopen does not erase one.
  - The review may concern an older AI run than the newest one. It stays attributed to its original analysis and model.
- **Disposition cohort:** per alert, disposition and reopen events from every actor before `to` are replayed. The effective disposition is included only if a human made it at or after `from`. A reopen before `to` removes the alert from this cohort.
- Grouping uses the rule, provider and model captured in event snapshots, never current Alert fields. There is an explicit `unknown` bucket.

**Formulas**

1. **Strict agreement** per section = `agree / (agree + partially_agree + disagree)`. `not_reviewed` is excluded from that section's denominator. Partial agreement and disagreement are reported separately rather than weighted.
2. The same breakdown **by detection rule** (`ruleId@revision`) and **by provider/model**, with counts and denominators.
3. **False-positive share** per rule = `false_positive / (true_positive + benign_true_positive + false_positive)`.
   - `inconclusive` is excluded from the denominator and reported separately.
   - Only the top 10 rules are listed, ordered by share, then sample size, then rule key.
   - This is not `FP / (FP + TN)`: non-alerting true negatives are never observed.
4. **AI verdict × analyst outcome** uses the AI snapshot stored on each effective disposition.
   - Original categories are kept; nothing is collapsed and no diagonal accuracy is computed.
   - Dispositions without an AI snapshot are excluded and counted.
5. **Median time to disposition** = disposition time − `analyzedAt` of the analysis that disposition referenced. Monitoring decisions are included. Missing or negative durations are excluded, and the eligible count is reported. This measures time to disposition, not time to remediation.
6. **Human-review coverage:** among alerts with an analysis persisted in `[from, to)`, how many have any human review before `to`. This is alert-level coverage, not per-run. The latest run before `to` is reported as reviewed, unreviewed, or not establishable from stored references.

Undefined rates and medians are `null` and are shown as "No data", never as zero. The pure calculators live in `src/investigation/feedbackMetrics.js`. MongoDB aggregations reduce the event log to one row per alert and stream them through the calculators, so events are never loaded into memory wholesale.

## Canonical AI output contract

The prompt, Zod validation, persistence layer, and React renderer use the same structure:

```json
{
  "verdict": "BENIGN|SUSPICIOUS|MALICIOUS|UNKNOWN",
  "one_line_summary": "Short analyst summary",
  "attack_story": ["Evidence-backed event"],
  "why_alert_triggered": {
    "rule": "Matched rule",
    "evidence": ["Observed trigger evidence"]
  },
  "observed_evidence": ["Confirmed evidence only"],
  "detection_analysis": {
    "rule_logic": "What the rule detects",
    "limitations": "Missing or ambiguous evidence"
  },
  "behavior_analysis": "Evidence-grounded behavior description",
  "attack_mapping": [
    { "technique": "Txxxx", "name": "Technique name" }
  ],
  "risk_assessment": {
    "severity": "critical|high|medium|low|info|unknown",
    "confidence": 0,
    "reasoning": "Evidence-based reason"
  },
  "analyst_decision": {
    "action": "INVESTIGATE|ESCALATE|MONITOR|CLOSE|UNKNOWN",
    "reason": "Recommended analyst action"
  },
  "false_positive_analysis": ["Possible benign explanation"],
  "recommended_investigation_steps": ["Next step"],
  "final_soc_note": "Short ticket note"
}
```

Legacy model responses are normalized into this contract before Zod validation so older response shapes do not break the pipeline.

## Detection-rule enrichment

There is one rule model and one parser pipeline: `DetectionRule` + `DetectionRuleRepository` + `src/services/ruleParser.js`.

CLI import:

```bash
export MONGODB_URI="mongodb://localhost:27017/ai-driven-soc"
npm run import:rules -- /path/to/rules.dataset.json
```

HTTP import:

```text
POST /rules/import
multipart/form-data field: rulesFile
```

Rule API:

```text
GET    /rules
GET    /rules/:ruleId
DELETE /rules/:ruleId
```

The resolver uses this order:

1. Exact Signature → title.
2. Normalized Signature → normalized title.
3. Same rule ID with multiple revisions → latest revision.
4. Deterministic protocol/content evidence to disambiguate duplicate titles.
5. Otherwise return `ambiguous` instead of guessing.

## Dashboard data

```text
GET /dashboard/stats
```

Optional date range:

```text
?createdAtFrom=<ISO date>&createdAtTo=<ISO date>
```

The dashboard now uses MongoDB alert/analysis data directly. It no longer displays placeholder MTTD/MTTA/MTTR, synthetic threat events, synthetic artifact counts, or fake MITRE values.

Displayed values are derived from persisted data:

- Alert count and severity distribution
- Unique hosts
- Detection-source distribution
- AI lifecycle counts
- AI analysis coverage
- Average persisted `processingTimeMs`
- Deterministic rule-match coverage
- Severity Pressure Index calculated from stored severities
- Unique MITRE techniques returned by analyzed alerts
- Percentage of analyzed alerts with a MITRE mapping
- Most recent stored alerts

The 24h / 7d / 30d controls send an actual date filter to the backend.

## SOC Analytics Copilot

The panel includes a floating, read-only SOC Copilot for natural-language analytics over registered MongoDB datasets.

The execution path is intentionally split between language understanding and deterministic data access:

```text
Analyst question
  ↓
Configured LLM planner
  ↓
Validated SOC Query Plan
  ↓
MCP read-only tool
  ↓
Generic SOC Query Engine
  ↓
Registered Mongoose model / MongoDB
  ↓
Structured result
  ↓
Grounded analyst answer
```

The model never receives permission to execute arbitrary MongoDB, JavaScript, shell commands, updates, or deletes.

Current registered datasets:

- `alerts`
- `detection_rules`
- `ip_assets`
- `threat_intelligence`
- `dataset_states`
- `mitre_coverage_snapshots`
- `mitre_techniques`

Known semantic fields are documented in the schema catalog. Safe fields added later to registered Mongoose models are automatically discovered, while arbitrary alert telemetry remains queryable through safe `rawEvent.*`, `fullAnalysis.*`, and `soc.*` paths.

Copilot API:

```text
GET  /copilot/schema
GET  /copilot/tools
POST /copilot/query
```

Example:

```json
{
  "message": "بیشترین سیگنیچری که در 7 روز گذشته افتاده چیه؟"
}
```

Conversation follow-ups can include a bounded `history` array. The backend truncates and normalizes this context before it is sent to the planner.

Time semantics use:

```env
SOC_TIMEZONE=Asia/Tehran
SOC_WEEK_START=saturday
```

Deterministic database-only smoke test:

```bash
npm run copilot:smoke
```

Natural-language CLI test using the configured LLM provider:

```bash
npm run copilot:ask -- "در 24 ساعت گذشته چند Alert داشتیم؟"
npm run copilot:ask -- "امروز چند Alert مربوط به SYN Flood داشتیم؟"
```

The MCP stdio server can also be started directly:

```bash
npm run mcp:serve
```

## Testing

```bash
npm test                  # hermetic unit and HTTP tests
npm run lint              # backend + panel ESLint
npm run format:check      # Prettier on the files listed in scripts/format.js
npm run panel:build
npm run test:integration  # MongoDB replica-set tests (transactions, rollback, aggregations)
```

`test:integration` starts a real single-node replica set through `mongodb-memory-server`. On first use it downloads the MongoDB binary from `fastdl.mongodb.org` (set `MONGOMS_VERSION` / `MONGOMS_DOWNLOAD_DIR` to control it). CI runs it as a separate `mongodb-integration` job.

Backend tests cover event hashing, model indexes, LLM contract normalization, duplicate-ingest history preservation, queue filtering/pagination, AI eligibility, analysis caching/re-analysis, rule resolution, alert detail, and dashboard statistics.


## MITRE ATT&CK rule coverage

The panel includes a rule-level MITRE ATT&CK coverage matrix at `/panel/mitre-coverage`.
Coverage is calculated from the latest revision of each detection rule, not from AI alert analysis.

Initial setup:

```bash
npm run import:mitre
npm run mitre:coverage
npm run panel:build
```

- `npm run import:mitre` imports the current Enterprise ATT&CK STIX bundle from the official MITRE ATT&CK data repository into MongoDB.
- `npm run mitre:coverage` marks the latest revision of each rule, performs deterministic MITRE extraction from explicit metadata/references, normalizes revoked ATT&CK IDs through official `revoked-by` relationships, and builds precomputed coverage snapshots for all/native/imported/community tiers.
- `npm run mitre:profile` profiles the remaining unmapped corpus by source file, classtype, protocol, and representative rules before curated mappings are added.
- `npm run mitre:curated:preview` evaluates conservative deterministic stage-2 mappings without changing MongoDB.
- `npm run mitre:curated:apply` applies the reviewed curated matcher set only to currently unmapped rules and invalidates coverage snapshots. Run `npm run mitre:coverage` afterwards to rebuild the matrix.
- `npm run mitre:gaps:preview` searches only currently-unmapped rules for high-confidence title evidence that targets active ATT&CK techniques not yet covered. It is read-only and is intended to increase technique diversity without forcing endpoint-only ATT&CK semantics onto network signatures.
- `npm run mitre:gaps:apply` applies the reviewed Stage 3 gap signals to currently-unmapped rules only. Applied mappings use `source=curated-gap`, record the gap signal version, and invalidate coverage snapshots. Run `npm run mitre:coverage` afterwards.
- Mapping provenance is preserved as explicit/reference, curated, or curated-gap. Rules that do not satisfy one of these deterministic evidence paths remain unmapped; the coverage engine does not use LLM guesses to manufacture ATT&CK coverage.

Coverage endpoints:

```text
GET  /mitre/coverage?tier=all
POST /mitre/coverage/rebuild
GET  /mitre/techniques/:techniqueId
GET  /mitre/techniques/:techniqueId/rules?page=1&limit=50&tier=all
```

Optional override for the ATT&CK bundle source:

```bash
MITRE_ATTACK_URL=https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
```

Rule imports invalidate existing coverage snapshots. Run `npm run mitre:coverage` after large rule-set changes so the matrix is rebuilt before validation.


## Offline IP intelligence enrichment

AI analysis can enrich IPv4 indicators before the prompt is sent to the LLM. The runtime lookup path is fully local:

```text
Alert
  ↓
Deterministic IPv4 extraction
  ├─ Local organizational asset registry
  ├─ Local IPinfo MMDB
  └─ Local current threat-intelligence dataset
  ↓
Deterministic network correlation
  ↓
Incident + detection rule + network intelligence
  ↓
Configured LLM provider
```

The current development provider can remain OpenAI. Production can switch to an internal OpenAI-compatible model endpoint by setting `LLM_PROVIDER=local`; the analysis context and canonical output contract do not change. Set `AIR_GAPPED=true` in the isolated environment to prevent accidental cloud-LLM use.

### Import organizational IPv4 assets

The asset dataset is expected as CSV/TSV with exactly these source columns:

```text
asset,bunit,category,province
```

`asset` is an exact IPv4 address and `bunit` is the organization name.

```bash
npm run import:ip-assets -- /offline-data/assets.csv
```

Imports are versioned internally. The new dataset becomes active only after the import completes, then records from the previous dataset are removed.

### Import current threat intelligence

The supplied feed format is JSON Lines (one JSON object per line) with dotted keys such as:

```text
source.ip
destination.ip
destination.port
protocol.transport
classification.identifier
classification.taxonomy
classification.type
malware.name
feed.provider
time.source
time.observation
unique_id
```

Import the latest approximately two-million-record snapshot:

```bash
npm run import:threat-intel -- /offline-data/threat-feed.jsonl
```

The latest successful import is the only active threat dataset. The previous dataset is removed after activation.

For the supplied feed adapter, `classification.*` is treated as classification evidence about `source.ip`. A match on `destination.ip` is preserved as relationship evidence and is never promoted to `malicious=true` by the deterministic layer. Exact IP + destination port + protocol matches are surfaced as stronger correlations.

### Point-in-time alert audit

The compact intelligence context used by the LLM is persisted on the analyzed alert under:

```text
soc.networkIntelligence
soc.iocs
soc.threatIntelligence
soc.correlation
```

The large threat feed itself does not need historical retention. Each analyzed alert retains only the small evidence snapshot that influenced that analysis.

Read-only validation endpoint:

```text
GET /intelligence/ip/:ipv4
```

This performs local enrichment only and does not call the LLM.

### Air-gapped operation

Runtime IP enrichment makes no external calls. Asset data, IPinfo MMDB, threat intelligence, detection rules, and ATT&CK data can all be supplied as files inside the isolated environment.

MITRE ATT&CK can also be imported from a local STIX bundle:

```bash
npm run import:mitre -- /offline-data/enterprise-attack.json
```

The existing URL-based MITRE importer remains available for connected development environments.
