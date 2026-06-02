# Real-Time SOC Incident Analysis API for Splunk (Node.js)

AI-Driven SOC platform API that receives Splunk-style alerts, persists them for analyst triage, and supports human-in-the-loop AI analysis. Existing clients can still call `POST /analyze-incident` for immediate analysis, while new workflows can ingest alerts first and trigger LLM analysis only after a human selects a stored alert.

## Architecture Overview

Current service boundaries keep provider and persistence concerns isolated so the platform can evolve toward local LLMs and air-gapped deployments:

```text
HTTP API (src/api)
  -> IncidentAnalyzer service (src/services)
    -> LLM service/provider adapter (src/services/llmService.js)
    -> Alert repository (src/repositories)
      -> Mongoose alert model (src/models)
        -> MongoDB connection (src/database)
```

Persistence is intentionally accessed through the repository layer only. API controllers and business services call `AlertRepository`; they do not call Mongoose directly. The Alert schema includes timestamps, `status` (`new` or `analyzed`), deterministic `eventHash` duplicate detection, and extension points for future SOC capabilities such as MITRE ATT&CK enrichment, IOC extraction, correlation metadata, offline threat intelligence, and provider-specific metadata.

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

Receives Splunk-style alert payloads, stores each alert with `status: "new"`, computes a deterministic SHA-256 `eventHash`, and does **not** call the LLM. If an incoming alert has the same `alertId` or `eventHash` as an existing document, the existing document is overwritten atomically with the latest raw alert and reset to `status: "new"`.

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

Response records include summary fields only: `alertId`, `source`, `status`, `severity`, `createdAt`, `updatedAt`, and `eventHash`.

### 3. Analyze selected alert: `POST /alerts/:id/analyze`

Fetches a stored alert by `alertId`, sends its `rawEvent` to `IncidentAnalyzer` / `LLMService`, validates the AI response with the existing Zod schema, overwrites any previous AI result, sets `status: "analyzed"`, and stores LLM metadata (`provider`, `model`, and `processingTimeMs`). The update changes only analysis and metadata fields, so the original `rawEvent` is never lost during analysis.

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
  }
}
```

### 4. Retrieve full alert: `GET /alerts/:id`

Returns the full alert document, including `rawEvent`, summarized `analysis`, full model response (`fullAnalysis`), timestamps, status, processing metadata, and SOC extension fields. Optional SOC query params can project requested extension fields into a `socFields` object:

```bash
curl "http://localhost:8000/alerts/splunk-alert-001?socFields=mitreAttack,iocs"
curl "http://localhost:8000/alerts/splunk-alert-001?mitreAttack=true&threatIntelligence=true"
```

Supported SOC field names are `mitreAttack`, `iocs`, `correlation`, and `threatIntelligence`.

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

The alert workflow stores documents containing:

- The original raw alert/event in `rawEvent`.
- `status`, beginning as `new` after webhook ingestion and changing to `analyzed` after human-triggered analysis.
- A deterministic SHA-256 `eventHash` generated from the normalized incoming event.
- Top-level `severity` for queue filtering, plus summarized analysis (`severity`, `summary`, and `recommendations`) after AI review.
- The full AI response (`fullAnalysis`) for backward-compatible API behavior and richer future workflows.
- LLM provider/model metadata and processing timing.
- Future SOC fields for MITRE ATT&CK mapping, IOC extraction, correlation, offline threat intelligence, and provider metadata.

MongoDB indexes are created for `alertId`, `status`, `createdAt`, `severity`, `analysis.severity`, and `eventHash` to support triage queues, duplicate detection, time-window searches, and correlation. `alertId` and `eventHash` are unique so duplicate webhook events overwrite existing documents instead of creating duplicate analyst work items.

## Testing

```bash
npm test
```

The test suite uses Node's built-in test runner and focuses on deterministic event hashing, alert model indexes, repository delegation, MongoDB initialization behavior, persistence failure handling, single and bulk alert ingestion, duplicate overwrite behavior, filtered alert listing, full alert retrieval, and human-triggered AI analysis overwrites.
