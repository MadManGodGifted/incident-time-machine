---
name: python-testing
description: Test incident-analysis engines using pytest across valid and invalid inputs, covering chronological sorting, correlation, and edge cases, while strictly reporting actual execution results.
---

# Python Testing

This skill establishes testing protocols for validating Python incident-analysis components using `pytest`. It defines required test case coverage across both valid and invalid log data and mandates strict adherence to reporting verified, real test results.

---

## 1. Core Testing Philosophy: Veracity in Reporting

- **Actual Results Only**: Never assume, simulate, or hallucinate test outcomes. Always run the actual `pytest` suite via the command line and report the exact stdout, stderr, and exit status.
- **Fail Early on Regressions**: Any change to parser logic, sorting, or correlation algorithms must be followed by running the test suite to verify no regressions occurred.
- **Pure Determinism**: Tests must be hermetic and repeatable, free from dependencies on system timezone, execution order, or machine environment.

---

## 2. Test Suite Coverage Requirements

Every incident-analysis component must be tested against both happy paths and hostile/malformed edge cases.

### Category A: Valid Inputs & Happy Paths
1. **Healthy Baseline Logs**:
   - Ingestion of well-formed, multi-service log entries with expected log levels (`INFO`, `DEBUG`).
   - Assertion that no false-positive incident or error flags are raised.
2. **Chronological Sorting**:
   - Out-of-order log entries ingested and verified to emerge in strict chronological sequence.
   - Verification that event sequence identifiers are assigned in sorted temporal order.
3. **Cross-Service Request Correlation**:
   - Trace flow across multiple services sharing identical `request_id` values (e.g., Gateway $\rightarrow$ Service A $\rightarrow$ Service B).
   - Assertion that correlated spans are grouped accurately under the corresponding trace.

### Category B: Invalid & Boundary Edge Cases
1. **Malformed Timestamps**:
   - Non-ISO strings (e.g., `"2026/10/25 10:20:40"`, `"yesterday"`, Unix epoch integers when strings are expected).
   - Assertion that the engine rejects or flags these without unhandled exceptions or crashes.
2. **Timezone-Naive Timestamps**:
   - Valid date-time strings lacking timezone offsets (e.g., `"2026-10-25T10:20:40"`).
   - Assertion that timezone-naive entries are rejected or routed to a quarantined invalid queue.
3. **Duplicate Timestamps**:
   - Multiple distinct events with identical sub-second timestamps.
   - Assertion that sorting remains stable and deterministic using secondary tie-breakers without dropping events.
4. **Missing Required Fields**:
   - Entries omitting `timestamp`, `service`, `level`, or `message`.
   - Assertion that schema validation errors are cleanly reported per entry.
5. **Missing or Corrupted Request IDs**:
   - Entries with `request_id` omitted, `null`, or empty string (`""`).
   - Assertion that such events are safely captured as unassociated/orphaned rather than causing indexing failures.

---

## 3. Test Execution Workflow

When running tests:

1. **Invoke Pytest Directly**:
   - Execute tests using `pytest` with verbose output and failure tracebacks:
     ```bash
     pytest -v --tb=short
     ```
2. **Inspect Specific Test Modules or Cases**:
   - Target individual failure areas during debugging:
     ```bash
     pytest tests/test_parser.py -k "test_malformed_timestamp" -v
     ```
3. **Verify and Report**:
   - Read the exact output lines: passed, failed, errors, warnings.
   - Report the concrete summary (e.g., `12 passed, 2 failed in 0.45s`) along with the specific tracebacks of any failing tests.
