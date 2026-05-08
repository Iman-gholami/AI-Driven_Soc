# Real-Time SOC Incident Analysis API for Splunk

## Run
```bash
pip install -r requirements.txt
export OPENAI_API_KEY="your_key"
uvicorn app.main:app --host 0.0.0.0 --port 8000
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
