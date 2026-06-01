# Real-Time SOC Incident Analysis API for Splunk (Node.js)

AI-Driven SOC platform API that receives Splunk-style alerts, builds a sanitized analysis context, sends the context to the configured LLM provider, returns the model's SOC analysis, and persists the analyzed alert for future investigation and correlation workflows.

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

Persistence is intentionally accessed through the repository layer only. Business services call `AlertRepository`; they do not call Mongoose directly. The Alert schema includes extension points for future SOC capabilities such as MITRE ATT&CK enrichment, IOC extraction, correlation metadata, offline threat intelligence, and provider-specific metadata.

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

If `MONGODB_URI` is not configured or MongoDB is unavailable, the API still analyzes incidents and returns responses. Persistence failures are logged and do not break the analysis workflow.

## Endpoint

- `POST /analyze-incident`
- `GET /health`

## Example

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

After successful LLM analysis, the API stores an alert document containing:

- The original raw alert/event.
- A deterministic SHA-256 `eventHash` generated from the normalized incoming event.
- A summarized analysis (`severity`, `summary`, and `recommendations`).
- The full analysis response for backward-compatible API behavior and richer future workflows.
- LLM provider/model metadata and processing timing.
- Future SOC fields for MITRE ATT&CK mapping, IOC extraction, correlation, offline threat intelligence, and provider metadata.

MongoDB indexes are created for `alertId`, `status`, `createdAt`, `analysis.severity`, and `eventHash` to support triage queues, duplicate detection, time-window searches, and correlation.

## Testing

```bash
npm test
```

The test suite uses Node's built-in test runner and focuses on deterministic event hashing, alert model indexes, repository delegation, MongoDB initialization behavior, and persistence failure handling.
