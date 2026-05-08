from typing import Any, Dict
from app.models.incident_schema import AnalysisResponse
from app.services.context_builder import build_context
from app.services.llm_service import LLMService


REQUIRED_KEYS = {
    "incident_summary",
    "detection_analysis",
    "behavior_analysis",
    "attack_mapping",
    "risk_assessment",
    "false_positive_analysis",
    "recommended_investigation_steps",
    "final_soc_note",
}


class IncidentAnalyzer:
    def __init__(self) -> None:
        self.llm = LLMService()

    async def analyze_incident(self, payload: Dict[str, Any]) -> AnalysisResponse:
        context = build_context(payload)
        result = await self.llm.analyze(context)

        missing = REQUIRED_KEYS - set(result.keys())
        if missing:
            raise ValueError(f"LLM response missing required keys: {sorted(missing)}")

        return AnalysisResponse(**result)
