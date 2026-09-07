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
Incident evidence + matched detection rule → LLM
      ↓
Canonical SOC assessment is validated and persisted
```

V1 is intentionally human-in-the-loop. Alerts without a Signature, or alerts whose Signature cannot be matched deterministically to a detection rule, remain visible but are not sent to the LLM.

## Stack

- Node.js / Express
- MongoDB / Mongoose
- OpenAI provider adapter
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
- `OPENAI_API_KEY`
- `OPENAI_MODEL` (default `gpt-4.1`)
- `OPENAI_TIMEOUT_MS` (default `5000`)
- `MONGODB_URI`
- `MONGODB_MAX_RETRIES` (default `3`)
- `MONGODB_RETRY_DELAY_MS` (default `500`)
- `MONGODB_SERVER_SELECTION_TIMEOUT_MS` (default `2000`)
- `MAX_RAW_LOG_CHARS` (default `4000`)
- `MAX_PAYLOAD_SIZE_BYTES` (default `200000`)
- `ENABLE_RATE_LIMITING` (default `true`)
- `LOG_LEVEL` (default `info`)

## API

### Health

```text
GET /health
```

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

## Testing

```bash
npm test
npm run panel:build
```

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
- Rules without explicit/reference ATT&CK identifiers remain unmapped; the coverage engine does not fabricate mappings from titles or LLM guesses.

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
