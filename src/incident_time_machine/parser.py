"""Parser and validator for incident log records."""

from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any, Dict, List, Tuple

from .models import Event, ValidationError


def _parse_iso8601_timezone_aware(ts_raw: Any) -> Tuple[datetime, str]:
    """Parse and validate an ISO 8601 string, ensuring it is timezone-aware.

    Returns:
        Tuple of (datetime in UTC, original ISO string).

    Raises:
        ValueError: If timestamp is malformed, not a string, or timezone-naive.
    """
    if not isinstance(ts_raw, str):
        raise ValueError(f"Timestamp must be a string, got {type(ts_raw).__name__}")

    ts_str = ts_raw.strip()
    if not ts_str:
        raise ValueError("Timestamp cannot be an empty string")

    # Basic ISO 8601 pattern check
    # Matches formats like:
    # 2026-10-25T10:20:40Z
    # 2026-10-25T10:20:40.123456+05:30
    # 2026-10-25T10:20:40-08:00
    try:
        dt = datetime.fromisoformat(ts_str)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Malformed ISO 8601 timestamp: '{ts_str}'") from exc

    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError(
            f"Timestamp '{ts_str}' is timezone-naive. Timezone offset (e.g. 'Z' or '±HH:MM') is strictly required."
        )

    # Convert to UTC
    dt_utc = dt.astimezone(timezone.utc)
    return dt_utc, ts_str


def parse_and_validate_record(record: Any, raw_index: int) -> Tuple[Event | None, ValidationError | None]:
    """Validate a single raw record against schema and timestamp invariants.

    Returns:
        (Event, None) if valid, or (None, ValidationError) if invalid.
    """
    if not isinstance(record, dict):
        return None, ValidationError(
            raw_index=raw_index,
            raw_record=record,
            reason=f"Record must be a JSON object / dict, got {type(record).__name__}",
        )

    # Required fields validation
    required_fields = ["timestamp", "service", "level", "message"]
    missing = [f for f in required_fields if f not in record]
    if missing:
        return None, ValidationError(
            raw_index=raw_index,
            raw_record=record,
            reason=f"Missing required field(s): {', '.join(missing)}",
        )

    service = record.get("service")
    if not isinstance(service, str) or not service.strip():
        return None, ValidationError(
            raw_index=raw_index,
            raw_record=record,
            reason=f"Field 'service' must be a non-empty string, got: {service!r}",
        )

    level = record.get("level")
    if not isinstance(level, str) or not level.strip():
        return None, ValidationError(
            raw_index=raw_index,
            raw_record=record,
            reason=f"Field 'level' must be a non-empty string, got: {level!r}",
        )

    message = record.get("message")
    if not isinstance(message, str):
        return None, ValidationError(
            raw_index=raw_index,
            raw_record=record,
            reason=f"Field 'message' must be a string, got {type(message).__name__}",
        )

    # Timestamp validation
    try:
        dt_utc, ts_iso = _parse_iso8601_timezone_aware(record.get("timestamp"))
    except ValueError as exc:
        return None, ValidationError(
            raw_index=raw_index,
            raw_record=record,
            reason=str(exc),
        )

    # Optional fields
    raw_req_id = record.get("request_id")
    request_id: str | None = None
    if isinstance(raw_req_id, str):
        cleaned_req = raw_req_id.strip()
        request_id = cleaned_req if cleaned_req else None
    elif raw_req_id is not None:
        # If request_id is present but not a string (e.g. int or bool), convert to string or handle safely
        request_id = str(raw_req_id).strip() or None

    metadata = record.get("metadata")
    if not isinstance(metadata, dict):
        # Also check 'attributes' as alias
        attrs = record.get("attributes")
        if isinstance(attrs, dict):
            metadata = attrs
        else:
            metadata = {}

    # Create unassigned event placeholder (event_id will be assigned post-sort)
    event = Event(
        event_id="",  # Assigned deterministically after chronological sorting
        timestamp=dt_utc,
        timestamp_iso=ts_iso,
        service=service.strip(),
        level=level.strip().upper(),
        # Treat message payload as inert untrusted text data
        message=message,
        request_id=request_id,
        metadata=metadata,
        raw_index=raw_index,
    )
    return event, None


def parse_records(records: List[Any]) -> Tuple[List[Event], List[ValidationError]]:
    """Parse and validate a sequence of raw log entries.

    Returns:
        (valid_unindexed_events, validation_errors)
    """
    valid_events: List[Event] = []
    errors: List[ValidationError] = []

    for index, record in enumerate(records):
        event, err = parse_and_validate_record(record, raw_index=index)
        if err is not None:
            errors.append(err)
        elif event is not None:
            valid_events.append(event)

    return valid_events, errors
