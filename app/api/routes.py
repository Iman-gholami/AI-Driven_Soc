import logging
from uuid import uuid4
from fastapi import APIRouter, HTTPException, Request
from app.core.config import get_settings
from app.services.analyzer import IncidentAnalyzer

router = APIRouter()
logger = logging.getLogger(__name__)
analyzer = IncidentAnalyzer()


@router.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@router.post("/analyze-incident")
async def analyze_incident(request: Request):
    settings = get_settings()
    request_id = str(uuid4())

    raw_body = await request.body()
    if len(raw_body) > settings.max_payload_size_bytes:
        raise HTTPException(status_code=413, detail="Payload too large")

    try:
        payload = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON payload") from exc

    logger.info("incident_received request_id=%s keys=%s", request_id, list(payload.keys())[:30])

    try:
        response = await analyzer.analyze_incident(payload)
        logger.info("incident_analyzed request_id=%s", request_id)
        return response.model_dump()
    except ValueError as exc:
        logger.warning("invalid_llm_output request_id=%s error=%s", request_id, str(exc))
        raise HTTPException(status_code=502, detail="Invalid model output") from exc
    except Exception as exc:
        logger.exception("analysis_failed request_id=%s", request_id)
        raise HTTPException(status_code=500, detail="Internal error during analysis") from exc
