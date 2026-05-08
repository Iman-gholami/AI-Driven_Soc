from datetime import datetime
from typing import Any, Dict
from app.core.config import get_settings
from app.core.logging import sanitize_text

RELEVANT_FIELDS = [
    "rule_name", "severity", "host", "user", "process_name", "command_line",
    "parent_process", "raw_log", "timestamp",
]


def _to_string(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def build_context(raw_incident: Dict[str, Any]) -> Dict[str, str | None]:
    settings = get_settings()
    context: Dict[str, str | None] = {}

    for field in RELEVANT_FIELDS:
        val = raw_incident.get(field)
        text_val = _to_string(val)
        if text_val:
            text_val = sanitize_text(text_val)
        if field == "raw_log" and text_val:
            text_val = text_val[: settings.max_raw_log_chars]
        context[field] = text_val

    return context
