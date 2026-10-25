# Incident Time Machine

> A deterministic log-reconstruction and incident-forensics engine designed for autonomous root-cause investigation in distributed systems.

---

## 1. Architectural Invariants

Incident Time Machine adheres to five non-negotiable principles:

1. **Pure Determinism**: Ingesting the same logs always produces the exact same timeline, event IDs, traces, and analytical conclusions across operating systems and Python versions. Tie-breaking for identical timestamps uses the initial ingestion sequence.
2. **Untrusted Data Guardrail**: All log contents, payloads, and error strings are treated as **untrusted data**. Prompt injection strings (e.g. `"Ignore previous instructions..."`) embedded in log bodies are never interpreted as instructions.
3. **No Temporal Fallacy (*Post Hoc Ergo Propter Hoc*)**: **Chronological sequence does NOT prove causation.** The earliest recorded error is explicitly identified as an observable symptom, never assumed to be the root cause.
4. **Evidence-Backed Hypotheses**: Every hypothesis must explicitly cite concrete event IDs (`evt-0001`, `evt-0002`). Uncited claims are rejected.
5. **Explicit Uncertainty & Telemetry Gaps**: Hypotheses explicitly document uncertainties, alternative explanations (e.g., network partitions, resource saturation), falsification criteria, and missing telemetry.

---

## 2. Directory Structure

```text
Incident-AWS/
├── .agents/
│   └── skills/
│       ├── incident-engineering/SKILL.md      # Deterministic engine standards
│       ├── incident-investigation/SKILL.md    # Investigation & untrusted data guidelines
│       └── python-testing/SKILL.md            # pytest coverage & reporting protocols
├── lambda_function.py                        # AWS Lambda entrypoint (`lambda_function.lambda_handler`)
├── fixtures/
│   ├── incident_out_of_order.json            # Synthetic cascade outage (scrambled order)
│   └── healthy_traffic.json                  # Multi-service baseline traffic (no errors)
├── src/
│   └── incident_time_machine/
│       ├── __init__.py                       # Package exports (lazy-loaded remote tools)
│       ├── agent.py                          # Strands Agent factory & provider inspection
│       ├── agent_cli.py                      # Strands Agent interactive CLI runner
│       ├── cli.py                            # Standalone engine CLI parser & runner
│       ├── engine.py                         # Deterministic reconstruction & correlation
│       ├── lambda_handler.py                 # Pure AWS Lambda request parser & executor
│       ├── models.py                         # Dataclasses (Event, Trace, Hypothesis, Report)
│       ├── parser.py                         # ISO 8601 & schema validator
│       ├── prompts.py                        # Agent system prompt & anti-hallucination safeguards
│       ├── remote_tool.py                    # Strands `@tool invoke_lambda_incident_analysis` (boto3)
│       ├── server.py                         # Lightweight local HTTP dashboard server (127.0.0.1)
│       ├── tools.py                          # Local Strands `@tool analyze_incident_logs` with sandbox jail
│       └── __main__.py                       # Module entrypoint (`python -m src.incident_time_machine`)
├── web/
│   ├── index.html                            # Cinematic dark incident-response dashboard
│   ├── style.css                             # Cyberpunk/slate responsive styling & visual badges
│   └── app.js                               # Frontend controller connecting to REST bridge
├── tests/
│   ├── __init__.py
│   ├── test_agent.py                         # Strands local tool & agent integration test suite (11 tests)
│   ├── test_engine.py                        # Core deterministic engine test suite (12 tests)
│   ├── test_lambda_handler.py                # AWS Lambda handler test suite (13 tests)
│   ├── test_lambda_packaging.py              # ZIP artifact structure & isolated smoke tests (4 tests)
│   ├── test_remote_tool.py                   # AWS Lambda remote tool & envelope tests (11 tests)
│   └── test_server.py                        # Local HTTP bridge & REST endpoint test suite (9 tests)
├── DEPLOYMENT.md                             # Comprehensive AWS Lambda deployment guide
├── requirements.txt                          # Dependencies documentation
└── README.md                                 # Project documentation
```

---

## 3. Dependencies

### Core Engine & Lambda Runtime: Zero External Dependencies
Both the deterministic engine and the AWS Lambda handler are built 100% on the Python 3.11+ standard library:
- `dataclasses`: Type-safe immutable data structures.
- `datetime`: Strict ISO 8601 timezone-aware parsing and UTC conversion.
- `json`: Fixture ingestion and serialization.
- `enum`: Log level categorization.
- `typing`: Strict type annotations.
- `base64`: Decoding API Gateway proxy payloads.

> **Zero Lambda Packaging Overhead**: The Lambda package requires NO external pip packages. Size is < 50 KB.

### Agent Framework & Tool Integration:
- `strands-agents>=1.62.0`: The official Strands Agents Python SDK providing the `@tool` decorator, `Agent` harness, and provider bindings.

### Model Providers (Optional / Environment-Driven):
- **Google Gemini**: Requires `google-genai` and `GEMINI_API_KEY` (or `GOOGLE_API_KEY`).
- **Amazon Bedrock**: Included via `boto3` in `strands-agents` (requires AWS credentials).
- **Hermetic Mock**: Built-in deterministic mock model (`DeterministicMockIncidentModel`) for zero-credential testing and offline CI/CD.

### Development & Test:
- `pytest>=8.0.0`: Required to execute the test suite and verify test invariants.

---

## 4. Usage & Execution Commands

### A. Interactive Web Dashboard
Start the local dashboard server:
```bash
python -m src.incident_time_machine.server
```
Open **`http://127.0.0.1:8000`** in your browser.
- **Dual Engine Toggle**: Switch seamlessly between **Local Engine** (hermetic) and **AWS Lambda** (`ap-southeast-2`).
- **Interactive Timeline**: Inspect chronologically sorted events with level badges and service tags.
- **Trace Waterfall**: View multi-hop request propagations across microservices.
- **Anti-Causation Warning**: Highlights earliest error symptoms without confusing sequence with causation.

### B. AWS Lambda Handler (Local Invocation & Smoke Testing)
Run the complete Lambda handler and packaging test suites:
```bash
python -m pytest tests/test_lambda_handler.py tests/test_lambda_packaging.py -v
```

### C. Strands Agent CLI (Local Deterministic Tool)
```bash
# Investigate out-of-order incident with Strands Agent using local engine
python -m src.incident_time_machine.agent_cli incident_out_of_order.json

# Investigate healthy traffic fixture
python -m src.incident_time_machine.agent_cli healthy_traffic.json

# Direct local tool execution without LLM loop
python -m src.incident_time_machine.agent_cli incident_out_of_order.json --tool-only
```

### D. Strands Agent CLI with Deployed AWS Lambda Tool
When the engine is deployed to AWS Lambda, run the local Strands agent backed by the cloud function:
```bash
# Execute local Strands agent calling deployed Lambda in ap-southeast-2
python -m src.incident_time_machine.agent_cli incident_out_of_order.json --remote-lambda

# Direct remote Lambda tool invocation without LLM loop
python -m src.incident_time_machine.agent_cli incident_out_of_order.json --remote-lambda --tool-only

# Override function name and region explicitly if needed
python -m src.incident_time_machine.agent_cli incident_out_of_order.json --remote-lambda --function-name incident-time-machine --region ap-southeast-2
```

### E. Core Deterministic Engine CLI (Standalone)
```bash
python -m src.incident_time_machine fixtures/incident_out_of_order.json
python -m src.incident_time_machine fixtures/healthy_traffic.json
python -m src.incident_time_machine fixtures/incident_out_of_order.json --json
```

---

## 5. Security & Least-Privilege IAM Policy

To invoke the deployed Lambda engine (`incident-time-machine` in `ap-southeast-2`) from your local Strands agent, configure local AWS credentials (`aws configure` or environment variables) with this minimal IAM policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "InvokeIncidentTimeMachineOnly",
      "Effect": "Allow",
      "Action": "lambda:InvokeFunction",
      "Resource": "arn:aws:lambda:ap-southeast-2:*:function:incident-time-machine"
    }
  ]
}
```

> **Security Posture**:
> - Never hardcode AWS keys in codebase or configuration files.
> - Dashboard server strictly binds to `127.0.0.1` (localhost only) to prevent credential leakage.
> - No public Function URLs or unauthenticated API Gateways are created.
> - Path traversal defenses inspect all file fixture arguments before issuing AWS calls.
> - If credentials are missing, the tool returns a clean, structured `NO_CREDENTIALS` error.

---

## 6. Test Suite Verification (60 Tests Passed)

Run the complete test suite with pytest:
```bash
python -m pytest -v --tb=short
```

### Verified Test Breakdown (60/60 Passed)
- `tests/test_agent.py` (11 tests): Strands local tool invocation, output schema, path traversal defenses (`ACCESS_DENIED`), invalid arguments, and mock agent loop.
- `tests/test_engine.py` (12 tests): Deterministic chronological sorting, secondary tie-breakers for duplicate timestamps, cross-service correlation, malformed/timezone-naive timestamp quarantining, and hypothesis evidence integrity.
- `tests/test_lambda_handler.py` (13 tests): Direct list invocation, `{"logs": [...]}`, API Gateway envelopes, base64 payloads, Bedrock Agent Action Group payloads, 400 Bad Request validations, and zero-framework independence.
- `tests/test_lambda_packaging.py` (4 tests): Verification of `incident_time_machine_lambda.zip` artifact, module path structure, importability, and isolated smoke tests in external temp directory.
- `tests/test_remote_tool.py` (11 tests): Remote tool invoking Lambda via boto3, payload stream parsing, unhandled function errors, 400 Bad Request handling, client errors (`ResourceNotFoundException`, `AccessDeniedException`), credential error guidance, path-traversal rejection, region resolution precedence, and Strands agent integration.
- `tests/test_server.py` (9 tests): Local HTTP bridge server, static asset serving (`index.html`, `style.css`, `app.js`), `GET /api/status`, `GET /api/fixtures`, `POST /api/analyze` (local and remote modes), path-traversal defense, 404 handling, and 400 invalid mode handling.

---

## 7. AWS Lambda Deployment

See [DEPLOYMENT.md](DEPLOYMENT.md) for full deployment instructions:
- **Function Name**: `incident-time-machine`
- **Region**: `ap-southeast-2` (Sydney)
- **Runtime**: `Python 3.12` or `Python 3.11`
- **Handler**: `lambda_function.lambda_handler`
- **Memory**: `256 MB`
- **Timeout**: `30 seconds`
- **Architecture**: `arm64` (Graviton) or `x86_64`
