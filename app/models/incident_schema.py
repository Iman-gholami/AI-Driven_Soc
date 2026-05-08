from datetime import datetime
from typing import Any, Dict, List
from pydantic import BaseModel, Field


class SplunkIncident(BaseModel):
    rule_name: str | None = None
    severity: str | None = None
    host: str | None = None
    user: str | None = None
    process_name: str | None = None
    command_line: str | None = None
    parent_process: str | None = None
    raw_log: str | None = None
    timestamp: datetime | None = None
    extra: Dict[str, Any] = Field(default_factory=dict)


class AnalysisResponse(BaseModel):
    incident_summary: Dict[str, Any]
    detection_analysis: Dict[str, Any]
    behavior_analysis: Dict[str, Any]
    attack_mapping: Dict[str, Any]
    risk_assessment: Dict[str, Any]
    false_positive_analysis: Dict[str, Any]
    recommended_investigation_steps: List[str]
    final_soc_note: str
