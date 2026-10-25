"""Data models for Incident Time Machine log reconstruction and incident analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARN = "WARN"
    WARNING = "WARNING"
    ERROR = "ERROR"
    FATAL = "FATAL"
    CRITICAL = "CRITICAL"

    @classmethod
    def is_error(cls, level_str: str) -> bool:
        normalized = (level_str or "").strip().upper()
        return normalized in {cls.ERROR.value, cls.FATAL.value, cls.CRITICAL.value}


@dataclass(frozen=True)
class Event:
    """Represents a validated, normalized, and immutable log event."""

    event_id: str
    timestamp: datetime  # Timezone-aware UTC datetime
    timestamp_iso: str  # Original ISO 8601 string
    service: str
    level: str
    message: str
    request_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    raw_index: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "timestamp_iso": self.timestamp_iso,
            "service": self.service,
            "level": self.level,
            "message": self.message,
            "request_id": self.request_id,
            "metadata": self.metadata,
            "raw_index": self.raw_index,
        }


@dataclass
class CorrelatedTrace:
    """Represents a set of events sharing the same request_id across services."""

    request_id: str
    event_ids: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    has_error: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "event_ids": self.event_ids,
            "services": self.services,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "has_error": self.has_error,
        }


@dataclass
class Hypothesis:
    """Represents an evidence-backed hypothesis with explicit uncertainty."""

    hypothesis_id: str
    claim: str
    evidence_event_ids: List[str]
    confidence: str  # "LOW", "MEDIUM", "HIGH"
    rationale: str
    counter_evidence_or_falsification: str
    uncertainties: List[str]
    alternative_explanations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "claim": self.claim,
            "evidence_event_ids": self.evidence_event_ids,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "counter_evidence_or_falsification": self.counter_evidence_or_falsification,
            "uncertainties": self.uncertainties,
            "alternative_explanations": self.alternative_explanations,
        }


@dataclass
class ValidationError:
    """Represents a log record that failed schema or timestamp validation."""

    raw_index: int
    raw_record: Any
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "raw_index": self.raw_index,
            "raw_record": self.raw_record,
            "reason": self.reason,
        }


@dataclass
class AnalysisReport:
    """Comprehensive analysis report produced by the engine."""

    timeline: List[Event] = field(default_factory=list)
    traces: Dict[str, CorrelatedTrace] = field(default_factory=dict)
    unassociated_event_ids: List[str] = field(default_factory=list)
    earliest_recorded_error: Optional[Event] = None
    hypotheses: List[Hypothesis] = field(default_factory=list)
    unknowns: List[str] = field(default_factory=list)
    validation_errors: List[ValidationError] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timeline": [evt.to_dict() for evt in self.timeline],
            "traces": {rid: trace.to_dict() for rid, trace in self.traces.items()},
            "unassociated_event_ids": self.unassociated_event_ids,
            "earliest_recorded_error": (
                self.earliest_recorded_error.to_dict()
                if self.earliest_recorded_error
                else None
            ),
            "hypotheses": [hyp.to_dict() for hyp in self.hypotheses],
            "unknowns": self.unknowns,
            "validation_errors": [err.to_dict() for err in self.validation_errors],
        }
