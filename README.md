# Real-Time SOC Incident Analysis API for Splunk (Node.js)

AI-Driven SOC platform API that receives Splunk-style alerts, persists them for analyst triage, and supports human-in-the-loop AI analysis. Existing clients can still call `POST /analyze-incident` for immediate analysis, while new workflows can ingest alerts first and trigger LLM analysis only after a human selects a stored alert.

## Architecture Overview

Current service boundaries keep provider and persistence concerns isolated so the platform can evolve toward local LLMs and air-gapped deployments:

```text
HTTP API (src/api)
  -> IncidentAnalyzer service (src/services)
    -> LLM service/provider adapter (src/services/llmService.js)
    -> Repositories (src/repositories)
      -> Alert model + AlertAnalysis model (src/models)
        -> MongoDB connection (src/database)
```

Persistence is intentionally accessed through the repository layer only. API controllers and business services call `AlertRepository` and `AlertAnalysisRepository`; they do not call Mongoose directly. The Alert schema includes timestamps, `status` (`new` or `analyzed`), deterministic `eventHash` duplicate detection, and a reference to the newest analysis. Each AI result is stored as its own `AlertAnalysis` document so repeated analyst-triggered analysis preserves history.

## Database Relationship

```text
Alert (alerts collection)
  _id
  alertId
  source
  rawEvent
  status
  severity
  eventHash
  latestAnalysisId  ───────────────┐
  analysisCount                    │ references newest result
  lastAnalyzedAt                   │
  createdAt / updatedAt           │
                                    ▼
AlertAnalysis (alertanalyses collection)
  _id
  alert ─────────────── references Alert._id
  alertId
  analysis { severity, summary, recommendations[] }
  fullAnalysis
  llmProvider / model / processingTimeMs
  soc { mitreAttack, iocs, correlation, threatIntelligence, providerMetadata }
  processing { attemptNumber, completedAt, errors[] }
  createdAt / updatedAt
```

One `Alert` can have many `AlertAnalysis` records. `Alert.latestAnalysisId` points to the newest `AlertAnalysis`, while older `AlertAnalysis` documents remain available as immutable analysis history. Webhook alert upserts reset only alert-level workflow fields such as `rawEvent`, `source`, `severity`, and `status`; they do **not** delete existing analysis history.

## Run

```bash
npm install
export OPENAI_API_KEY="your_key"
export MONGODB_URI="mongodb://localhost:27017/ai-driven-soc"
npm start
```

For development with file watching:

```bash
npm run dev
```

## MongoDB Setup

### Local MongoDB with Docker

```bash
docker run --name ai-driven-soc-mongo \
  -p 27017:27017 \
  -v ai-driven-soc-mongo-data:/data/db \
  -d mongo:7

export MONGODB_URI="mongodb://localhost:27017/ai-driven-soc"
```

### Local MongoDB Service

Install MongoDB Community Edition for your operating system, start the MongoDB service, and set:

```bash
export MONGODB_URI="mongodb://localhost:27017/ai-driven-soc"
```

If `MONGODB_URI` is not configured or MongoDB is unavailable, the backward-compatible `POST /analyze-incident` endpoint still analyzes incidents and returns responses. Human-in-the-loop alert workflow endpoints require MongoDB persistence and return storage errors if MongoDB is unavailable.

## Endpoints

- `GET /health`
- `POST /analyze-incident` (backward-compatible immediate analysis endpoint)
- `POST /webhook-alert`
- `GET /alerts`
- `POST /alerts/:id/analyze`
- `GET /alerts/:id`

## Human-in-the-Loop Alert Workflow

### 1. Ingest alert(s): `POST /webhook-alert`

Receives Splunk-style alert payloads, stores each alert with `status: "new"`, computes a deterministic SHA-256 `eventHash`, and does **not** call the LLM. It also does **not** create an `AlertAnalysis` document. If an incoming alert has the same `alertId` or `eventHash` as an existing alert, the alert-level fields are overwritten atomically with the latest raw alert and reset to `status: "new"`; existing `AlertAnalysis` history is preserved.

Single alert payload:

```bash
curl -X POST http://localhost:8000/webhook-alert \
  -H "Content-Type: application/json" \
  -d '{
    "alertId": "splunk-alert-001",
    "source": "splunk",
    "severity": "high",
    "host": "web-01",
    "rule_name": "Suspicious PowerShell",
    "_raw": "powershell.exe -EncodedCommand ..."
  }'
```

Bulk alert payloads can be either a JSON array or an object with an `alerts` (or `results`) array:

```bash
curl -X POST http://localhost:8000/webhook-alert \
  -H "Content-Type: application/json" \
  -d '{
    "alerts": [
      { "alert_id": "splunk-alert-002", "severity": "medium", "source": "splunk", "user": "alice" },
      { "alert_id": "splunk-alert-003", "severity": "critical", "source": "splunk", "user": "bob" }
    ]
  }'
```

Response:

```json
{
  "count": 2,
  "alerts": [
    {
      "alertId": "splunk-alert-002",
      "source": "splunk",
      "status": "new",
      "severity": "medium",
      "createdAt": "2026-06-02T12:00:00.000Z",
      "updatedAt": "2026-06-02T12:00:00.000Z",
      "eventHash": "<sha256>"
    }
  ]
}
```

### 2. Triage queue: `GET /alerts`

Returns summary alert records sorted by `createdAt` descending. Supported filters:

- `status`: `new` or `analyzed`
- `severity`: for example `low`, `medium`, `high`, or `critical`
- `createdAtFrom` / `createdAtTo`: ISO-8601 date range (aliases: `from` / `to`)
- `page` / `limit`: pagination (`limit` is capped at 100)

```bash
curl "http://localhost:8000/alerts?status=new&severity=high&page=1&limit=25"
```

Response records include alert summary fields (`alertId`, `source`, `status`, `severity`, `analysisCount`, `lastAnalyzedAt`, `createdAt`, `updatedAt`, and `eventHash`) plus `latestAnalysis` when a latest analysis exists.

### 3. Analyze selected alert: `POST /alerts/:id/analyze`

Fetches a stored alert by `alertId`, sends its `rawEvent` to `IncidentAnalyzer` / `LLMService`, validates the AI response with the existing Zod schema, creates a new `AlertAnalysis` document, sets `status: "analyzed"`, updates top-level `severity`, increments `analysisCount`, updates `lastAnalyzedAt`, and points `latestAnalysisId` at the new analysis. Previous `AlertAnalysis` records are not overwritten or deleted, so multiple clicks of Analyze create multiple historical results.

```bash
curl -X POST http://localhost:8000/alerts/splunk-alert-001/analyze
```

Response:

```json
{
  "alertId": "splunk-alert-001",
  "analysis": {
    "incident_summary": { "what_happened": "Suspicious PowerShell execution" },
    "detection_analysis": {},
    "behavior_analysis": {},
    "attack_mapping": {},
    "risk_assessment": { "severity": "high" },
    "false_positive_analysis": {},
    "recommended_investigation_steps": ["Review process tree"],
    "final_soc_note": "Investigate promptly."
  },
  "metadata": {
    "provider": "openai",
    "model": "gpt-4.1",
    "processingTimeMs": 1234
  },
  "latestAnalysis": {
    "id": "665f...",
    "alertId": "splunk-alert-001",
    "analysis": {
      "severity": "high",
      "summary": "Suspicious PowerShell execution",
      "recommendations": ["Review process tree"]
    },
    "llmProvider": "openai",
    "model": "gpt-4.1",
    "processingTimeMs": 1234
  }
}
```

### 4. Retrieve full alert: `GET /alerts/:id`

Returns the full alert document, including `rawEvent`, alert-level workflow fields, and `latestAnalysis`. Optional SOC query params can project requested extension fields from `latestAnalysis.soc` into a `socFields` object:

```bash
curl "http://localhost:8000/alerts/splunk-alert-001?socFields=mitreAttack,iocs"
curl "http://localhost:8000/alerts/splunk-alert-001?mitreAttack=true&threatIntelligence=true"
```

Supported SOC field names are `mitreAttack`, `iocs`, `correlation`, and `threatIntelligence`.

To retrieve the full analysis history, add `includeAnalyses=true`:

```bash
curl "http://localhost:8000/alerts/splunk-alert-001?includeAnalyses=true"
```

The response includes:

```json
{
  "alertId": "splunk-alert-001",
  "rawEvent": { "host": "web-01" },
  "latestAnalysis": { "id": "665f-newest", "analysis": { "severity": "high" } },
  "analyses": [
    { "id": "665f-newest", "analysis": { "severity": "high" } },
    { "id": "665f-older", "analysis": { "severity": "medium" } }
  ]
}
```

## Backward-Compatible Immediate Analysis Example

```bash
curl -X POST http://localhost:8000/analyze-incident \
  -H "Content-Type: application/json" \
  -d @example_request.json
```

## Environment Variables

- `PORT` (default: `8000`)
- `OPENAI_API_KEY` (required for the current OpenAI provider)
- `OPENAI_MODEL` (default: `gpt-4.1`)
- `OPENAI_TIMEOUT_MS` (default: `5000`)
- `MONGODB_URI` (optional; enables MongoDB alert persistence when set)
- `MONGODB_MAX_RETRIES` (default: `3`)
- `MONGODB_RETRY_DELAY_MS` (default: `500`)
- `MONGODB_SERVER_SELECTION_TIMEOUT_MS` (default: `2000`)
- `MAX_RAW_LOG_CHARS` (default: `4000`)
- `MAX_PAYLOAD_SIZE_BYTES` (default: `200000`)
- `ENABLE_RATE_LIMITING` (default: `true`)
- `LOG_LEVEL` (default: `info`)

## Alert Persistence

### Alert documents

`Alert` documents store alert-level triage state only:

- The original raw alert/event in `rawEvent`.
- `status`, beginning as `new` after webhook ingestion and changing to `analyzed` after human-triggered analysis.
- Top-level `severity` for queue filtering. Before analysis this comes from the webhook payload when present; after analysis it is updated to the newest AI severity.
- A deterministic SHA-256 `eventHash` generated from the normalized incoming event.
- `latestAnalysisId`, an ObjectId reference to the newest `AlertAnalysis`.
- `analysisCount` and `lastAnalyzedAt`, which make it easy to show whether and when an alert has been analyzed.

### AlertAnalysis documents

`AlertAnalysis` documents store every AI result independently:

- `alert`, an ObjectId reference to the parent `Alert._id`.
- `alertId`, duplicated for convenient lookup by external alert identifier.
- Summarized `analysis` (`severity`, `summary`, and `recommendations`).
- The full AI response in `fullAnalysis`.
- LLM provider/model metadata and processing timing.
- SOC fields for MITRE ATT&CK mapping, IOC extraction, correlation, offline threat intelligence, and provider metadata.
- Processing metadata, including `attemptNumber`, `completedAt`, and any errors.

MongoDB indexes are created on `Alert.alertId`, `Alert.status`, `Alert.createdAt`, `Alert.severity`, `Alert.eventHash`, and `Alert.latestAnalysisId`. `AlertAnalysis` indexes are created on `alert`, `alertId`, `createdAt`, `analysis.severity`, `llmProvider`, and `model`. `Alert.alertId` and `Alert.eventHash` are unique so duplicate webhook events update existing analyst work items instead of creating duplicate alerts, without deleting any historical `AlertAnalysis` records.

## Testing

```bash
npm test
```

The test suite uses Node's built-in test runner and focuses on deterministic event hashing, Alert and AlertAnalysis schemas, repository delegation, MongoDB initialization behavior, persistence failure handling, single and bulk alert ingestion, duplicate overwrite behavior, filtered alert listing, latest/full alert retrieval, historical analysis retrieval, immediate analysis compatibility, and repeated human-triggered AI analysis history creation.
