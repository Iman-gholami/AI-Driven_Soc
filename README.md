# Real-Time SOC Incident Analysis API for Splunk (Node.js)

## Run
```bash
npm install
export OPENAI_API_KEY="your_key"
npm start
```

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
- `OPENAI_API_KEY` (required)
- `OPENAI_MODEL` (default: `gpt-4.1`)
- `OPENAI_TIMEOUT_MS` (default: `5000`)
- `MAX_RAW_LOG_CHARS` (default: `4000`)
- `MAX_PAYLOAD_SIZE_BYTES` (default: `200000`)
- `ENABLE_RATE_LIMITING` (default: `true`)
