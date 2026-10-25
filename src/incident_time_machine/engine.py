"""Deterministic incident log reconstruction and analysis engine."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import (
    AnalysisReport,
    CorrelatedTrace,
    Event,
    Hypothesis,
    LogLevel,
    ValidationError,
)
from .parser import parse_records


class IncidentTimeMachine:
    """Deterministic log reconstruction engine for incident analysis."""

    def __init__(self, raw_records: Optional[List[Dict[str, Any]]] = None) -> None:
        self.raw_records = raw_records or []

    @classmethod
    def from_file(cls, filepath: str | Path) -> IncidentTimeMachine:
        """Load raw log entries from a JSON file."""
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Log fixture not found: {filepath}")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, list):
            raise ValueError(f"Expected top-level JSON array in {filepath}, got {type(data).__name__}")

        return cls(raw_records=data)

    def analyze(self) -> AnalysisReport:
        """Run deterministic reconstruction, correlation, and hypothesis generation.

        Invariants enforced:
        1. Deterministic chronological sorting with secondary tie-breaking on input index.
        2. Stable event IDs assigned sequentially (evt-0001, evt-0002, ...) post-sort.
        3. Cross-service correlation by request_id.
        4. Identification of earliest recorded error without assuming causality.
        5. Evidence-backed hypotheses citing explicit event IDs with clear uncertainty boundaries.
        """
        # 1. Parse & validate
        valid_unindexed, validation_errors = parse_records(self.raw_records)

        # 2. Deterministic chronological sorting
        # Primary key: UTC timestamp
        # Secondary key: raw_index (preserves deterministic tie-breaker for identical timestamps)
        sorted_unindexed = sorted(
            valid_unindexed,
            key=lambda evt: (evt.timestamp, evt.raw_index),
        )

        # 3. Assign stable event IDs in sorted order
        timeline: List[Event] = []
        for seq_idx, evt in enumerate(sorted_unindexed, start=1):
            stable_id = f"evt-{seq_idx:04d}"
            # Create immutable event with assigned event_id
            timeline.append(
                replace(
                    evt,
                    event_id=stable_id,
                )
            )

        # 4. Cross-service correlation by request_id
        traces: Dict[str, CorrelatedTrace] = {}
        unassociated_event_ids: List[str] = []

        for event in timeline:
            rid = event.request_id
            if rid:
                if rid not in traces:
                    traces[rid] = CorrelatedTrace(
                        request_id=rid,
                        event_ids=[],
                        services=[],
                        start_time=event.timestamp,
                        end_time=event.timestamp,
                        has_error=False,
                    )
                trace = traces[rid]
                trace.event_ids.append(event.event_id)
                if event.service not in trace.services:
                    trace.services.append(event.service)
                trace.end_time = event.timestamp
                if LogLevel.is_error(event.level):
                    trace.has_error = True
            else:
                unassociated_event_ids.append(event.event_id)

        # 5. Identify earliest recorded error
        earliest_error: Optional[Event] = None
        all_error_events: List[Event] = []

        for event in timeline:
            if LogLevel.is_error(event.level):
                all_error_events.append(event)
                if earliest_error is None:
                    earliest_error = event

        # 6. Generate evidence-backed hypotheses with explicit uncertainty
        hypotheses, unknowns = self._generate_hypotheses(
            timeline=timeline,
            traces=traces,
            earliest_error=earliest_error,
            all_error_events=all_error_events,
            unassociated_count=len(unassociated_event_ids),
            validation_error_count=len(validation_errors),
        )

        # 7. Invariant check: Verify every hypothesis cites valid event IDs present in timeline
        timeline_ids = {evt.event_id for evt in timeline}
        for hyp in hypotheses:
            for eid in hyp.evidence_event_ids:
                if eid not in timeline_ids:
                    raise ValueError(
                        f"Invariant violation: Hypothesis '{hyp.hypothesis_id}' cited invalid event ID '{eid}' "
                        f"not present in timeline."
                    )

        return AnalysisReport(
            timeline=timeline,
            traces=traces,
            unassociated_event_ids=unassociated_event_ids,
            earliest_recorded_error=earliest_error,
            hypotheses=hypotheses,
            unknowns=unknowns,
            validation_errors=validation_errors,
        )

    def _generate_hypotheses(
        self,
        timeline: List[Event],
        traces: Dict[str, CorrelatedTrace],
        earliest_error: Optional[Event],
        all_error_events: List[Event],
        unassociated_count: int,
        validation_error_count: int,
    ) -> tuple[List[Hypothesis], List[str]]:
        """Formulate deterministic, evidence-backed hypotheses and identify unknowns."""
        hypotheses: List[Hypothesis] = []
        unknowns: List[str] = []

        if not earliest_error:
            # Baseline Healthy Scenario: State strictly what was observed in the supplied logs
            evidence_ids = [evt.event_id for evt in timeline[:5]] if timeline else []
            hypotheses.append(
                Hypothesis(
                    hypothesis_id="hyp-01",
                    claim="No errors detected in the supplied logs; observed events operated within normal parameters.",
                    evidence_event_ids=evidence_ids,
                    confidence="HIGH" if timeline else "LOW",
                    rationale="No ERROR, FATAL, or CRITICAL log records were encountered in the analyzed log stream.",
                    counter_evidence_or_falsification="Unlogged silent exceptions, unmonitored services, or dropped log streams would falsify normal status.",
                    uncertainties=[
                        "Absence of error logs in the supplied dataset does not prove absence of system malfunction.",
                        "Uninstrumented components, silent data corruption, or dropped logs cannot be detected from this log stream alone.",
                    ],
                    alternative_explanations=[
                        "Failures occurred on external unmonitored systems.",
                        "Errors were downgraded to INFO/DEBUG log levels by application code.",
                    ],
                )
            )
            if unassociated_count > 0:
                unknowns.append(
                    f"{unassociated_count} event(s) lacked a request_id and could not be tied to an end-to-end trace."
                )
            if validation_error_count > 0:
                unknowns.append(
                    f"{validation_error_count} raw log record(s) failed validation and were quarantined (excluded from timeline). Check quarantined records for details."
                )
            return hypotheses, unknowns

        # Incident Scenario
        # Hypothesis 1: Earliest Recorded Error Analysis
        err_service = earliest_error.service
        err_id = earliest_error.event_id
        correlated_trace = traces.get(earliest_error.request_id) if earliest_error.request_id else None

        # Related evidence: earliest error plus other error events
        related_error_ids = [evt.event_id for evt in all_error_events]

        hypotheses.append(
            Hypothesis(
                hypothesis_id="hyp-01",
                claim=(
                    f"Earliest recorded error manifested in service '{err_service}' at "
                    f"{earliest_error.timestamp_iso} ({err_id})."
                ),
                evidence_event_ids=[err_id],
                confidence="MEDIUM",
                rationale=(
                    f"Event {err_id} is the first chronological log entry with level '{earliest_error.level}'. "
                    f"Message: {earliest_error.message!r}."
                ),
                counter_evidence_or_falsification=(
                    f"If upstream telemetry reveals an unmonitored caller, network failure, or resource exhaustion "
                    f"that preceded {err_id}, then {err_service} was not the origin of failure."
                ),
                uncertainties=[
                    "CAUSATION DISCLAIMER: Chronological precedence does NOT prove causation. The earliest logged error may merely be a downstream symptom of a latent or unmonitored failure.",
                    f"No telemetry is available for the internal infrastructure hosting '{err_service}' (e.g. CPU, memory, database process health).",
                ],
                alternative_explanations=[
                    f"The failure in '{err_service}' was triggered by an unlogged external network partition.",
                    f"An upstream dependency saturated connection pools prior to '{err_service}' emitting an error log.",
                    "Pre-existing database lock or deadlock not captured in application logs.",
                ],
            )
        )

        # Hypothesis 2: Cascading Failure & Correlation Analysis
        if len(all_error_events) > 1:
            affected_services = list(dict.fromkeys(e.service for e in all_error_events))
            downstream_errors = [e.event_id for e in all_error_events if e.event_id != err_id]

            hypotheses.append(
                Hypothesis(
                    hypothesis_id="hyp-02",
                    claim=(
                        f"Cascading failure propagated across {len(affected_services)} services: "
                        f"{', '.join(affected_services)}."
                    ),
                    evidence_event_ids=related_error_ids,
                    confidence="HIGH" if correlated_trace else "MEDIUM",
                    rationale=(
                        f"Following the initial failure in '{err_service}' ({err_id}), subsequent errors occurred "
                        f"across correlated requests ({', '.join(downstream_errors)})."
                    ),
                    counter_evidence_or_falsification=(
                        "If multiple independent root causes triggered simultaneous errors across these services "
                        "(e.g., correlated clock-drift, AZ-wide network outage), then this was not a single cascade."
                    ),
                    uncertainties=[
                        "Request ID propagation may be incomplete across asynchronous queues or background workers.",
                        "Inter-service network latency and retry storm behavior are unknown from log text alone.",
                    ],
                    alternative_explanations=[
                        "Simultaneous external infrastructure degradation (e.g., shared cloud network/AZ partition) impacting multiple services concurrently.",
                        "Thundering herd problem caused by aggressive client-side retries after the first failure.",
                    ],
                )
            )

        # Catalog Unknowns
        unknowns.append(
            f"Underlying host/container health metrics for participating services ({', '.join({e.service for e in timeline})}) are absent."
        )
        if unassociated_count > 0:
            unknowns.append(
                f"{unassociated_count} event(s) have missing or empty request_id, preventing complete trace correlation."
            )
        if validation_error_count > 0:
            unknowns.append(
                f"{validation_error_count} raw log record(s) failed schema/timestamp validation and were quarantined."
            )

        return hypotheses, unknowns


def format_cli_summary(report: AnalysisReport) -> str:
    """Format an analysis report into a human-readable CLI summary."""
    lines: List[str] = []
    lines.append("=" * 70)
    lines.append("           INCIDENT TIME MACHINE - ANALYSIS REPORT")
    lines.append("=" * 70)
    lines.append(f"Timeline Total Events   : {len(report.timeline)}")
    lines.append(f"Correlated Traces       : {len(report.traces)}")
    lines.append(f"Unassociated Event IDs  : {len(report.unassociated_event_ids)}")
    lines.append(f"Quarantined/Invalid Logs: {len(report.validation_errors)}")

    lines.append("\n[1] CHRONOLOGICAL TIMELINE (FIRST 5 & LAST 3 EVENTS):")
    display_events = report.timeline[:5]
    if len(report.timeline) > 8:
        for evt in display_events:
            lines.append(f"  {evt.event_id} | {evt.timestamp_iso} | [{evt.level:5s}] {evt.service:16s} | {evt.message[:45]}")
        lines.append(f"  ... [{len(report.timeline) - 8} events omitted] ...")
        for evt in report.timeline[-3:]:
            lines.append(f"  {evt.event_id} | {evt.timestamp_iso} | [{evt.level:5s}] {evt.service:16s} | {evt.message[:45]}")
    else:
        for evt in report.timeline:
            lines.append(f"  {evt.event_id} | {evt.timestamp_iso} | [{evt.level:5s}] {evt.service:16s} | {evt.message[:45]}")

    lines.append("\n[2] EARLIEST RECORDED ERROR:")
    if report.earliest_recorded_error:
        ee = report.earliest_recorded_error
        lines.append(f"  Event ID  : {ee.event_id}")
        lines.append(f"  Timestamp : {ee.timestamp_iso} (UTC: {ee.timestamp.isoformat()})")
        lines.append(f"  Service   : {ee.service}")
        lines.append(f"  Level     : {ee.level}")
        lines.append(f"  Request ID: {ee.request_id or 'None'}")
        lines.append(f"  Message   : {ee.message}")
        lines.append("  * Note    : Earliest recorded error does NOT establish root cause.")
    else:
        lines.append("  None. All events in timeline are healthy (INFO/DEBUG/WARN).")

    lines.append("\n[3] CORRELATED TRACES:")
    for rid, trace in list(report.traces.items())[:5]:
        status = "ERROR" if trace.has_error else "OK"
        lines.append(f"  Trace {rid:12s} [{status:5s}] -> Services: {' -> '.join(trace.services)} ({len(trace.event_ids)} events)")

    lines.append("\n[4] EVIDENCE-BACKED HYPOTHESES:")
    for hyp in report.hypotheses:
        lines.append(f"  * [{hyp.hypothesis_id}] Confidence: {hyp.confidence}")
        lines.append(f"    Claim   : {hyp.claim}")
        lines.append(f"    Evidence: {', '.join(hyp.evidence_event_ids)}")
        lines.append(f"    Uncertainties:")
        for u in hyp.uncertainties:
            lines.append(f"      - {u}")
        lines.append(f"    Alternative Explanations:")
        for alt in hyp.alternative_explanations:
            lines.append(f"      - {alt}")

    lines.append("\n[5] UNKNOWNS & TELEMETRY GAPS:")
    for unk in report.unknowns:
        lines.append(f"  - {unk}")

    if report.validation_errors:
        lines.append("\n[6] QUARANTINED RECORDS (VALIDATION FAILURES):")
        lines.append(f"  Total Quarantined: {len(report.validation_errors)} record(s) excluded from the timeline.")
        for err in report.validation_errors:
            lines.append(f"  - Record #{err.raw_index}: {err.reason} (Quarantined)")

    lines.append("=" * 70)
    return "\n".join(lines)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m src.incident_time_machine.engine <path_to_fixture.json>")
        sys.exit(1)

    fixture_path = sys.argv[1]
    engine = IncidentTimeMachine.from_file(fixture_path)
    report = engine.analyze()
    print(format_cli_summary(report))
