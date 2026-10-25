---
name: incident-engineering
description: Build a deterministic Python incident-analysis engine with strict ISO 8601 timestamp validation, chronological sorting, cross-service request correlation, and evidence-backed hypothesis tracking.
---

# Incident Engineering

This skill provides operational patterns and technical standards for building a deterministic Python incident-analysis engine. The engine must ingest structured log records, validate schema and temporal invariants, correlate events across distributed services, and enforce strict evidence requirements for any analytical claims.

---

## 1. Core Architectural Invariants

1. **Determinism Above All**: Given the exact same set of log entries, the engine must produce an identical timeline, identical identifiers, and identical analytical outputs across runs.
2. **Strict Evidence Requirement**: Every hypothesis or analytical conclusion must directly cite one or more stable event IDs. Unreferenced assertions are considered invalid.
3. **No Temporal Fallacy**: **Chronological order does NOT prove causation.** An event occurring before an error does not automatically establish it as the cause (avoid *post hoc ergo propter hoc*). Treat temporal sequence as a necessary condition for direct causation, but never a sufficient one.

---

## 2. Ingestion & Schema Validation

The engine must enforce strict schema and timestamp validation before events enter processing:

### Timestamp Validation
- **ISO 8601 Compliance**: Timestamps must adhere to ISO 8601 (e.g., `2026-10-25T10:20:40Z` or `2026-10-25T10:20:40.123+05:30`).
- **Timezone-Awareness**: Every timestamp **must** include timezone information (UTC offset `Z` or `±HH:MM`). Reject or flag timezone-naive timestamps immediately; do not silently assume local time or UTC.
- **Microsecond Precision**: Support and preserve sub-second precision to maintain relative ordering during bursts.

### Required Fields
Each log event must contain at minimum:
- `timestamp`: ISO 8601 timezone-aware string.
- `service`: String identifier of the emitting service or component.
- `level`: Log level (e.g., `DEBUG`, `INFO`, `WARN`, `ERROR`, `FATAL`).
- `message`: Descriptive log message text.

Optional/contextual fields:
- `request_id`: Cross-service trace/correlation ID (may be absent in background tasks or uninstrumented spans).
- `attributes` / `metadata`: Key-value map of arbitrary execution context.

---

## 3. Normalization, Sorting & Stable Event IDs

### Chronological Sorting
- Normalize all timestamps to UTC unix epochs or UTC `datetime` objects for comparison.
- In the event of identical timestamps (timestamp collision):
  - Use a secondary deterministic tie-breaker (e.g., original ingestion index or hash of raw payload) so sorting remains 100% deterministic across platforms and Python versions.

### Stable Event IDs
- Assign a stable, reproducible event ID to each processed event (e.g., `evt-0001`, `evt-0002` sequentially in sorted order, or a deterministic content hash like SHA-256 of `timestamp + service + message + request_id`).
- Event IDs must remain consistent across repeated executions against the same dataset.

---

## 4. Cross-Service Request Correlation

- Extract and index `request_id` values across all participating services.
- Group and link events sharing the same `request_id` to trace distributed call flows (e.g., API Gateway $\rightarrow$ Auth Service $\rightarrow$ Order Service $\rightarrow$ Database).
- Handle edge cases gracefully:
  - **Missing Request IDs**: Isolate events without request IDs into an unassociated pool; do not drop them.
  - **Orphaned Spans**: Identify requests initiated in downstream services without upstream parent entries.
  - **Cross-Service Drift**: Account for clock skew across distinct service environments when evaluating cross-service traces.

---

## 5. Hypothesis & Evidence Model

Analytical engines must represent findings as structured hypotheses tied to concrete data:

- **Hypothesis Structure**:
  - `claim`: Clear statement of what occurred or what mechanism failed.
  - `evidence_event_ids`: Non-empty list of event IDs (`["evt-0012", "evt-0015"]`) supporting the statement.
  - `confidence`: Qualitative or numerical confidence based strictly on observable data.
  - `falsification_conditions`: What evidence would disprove this hypothesis?
- **Prohibited Patterns**:
  - Asserting root cause purely because event $A$ preceded event $B$.
  - Generating hypotheses without explicitly citing event IDs.
