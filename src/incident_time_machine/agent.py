"""Strands Agent integration for Incident Time Machine."""

from __future__ import annotations

import json
import os
from typing import Any, AsyncGenerator, AsyncIterable, Dict, List, Optional, Tuple

from strands import Agent
from strands.models.model import Model
from strands.types.content import Messages
from strands.types.streaming import StreamEvent
from strands.types.tools import ToolSpec

from .prompts import INCIDENT_AGENT_SYSTEM_PROMPT
from .remote_tool import invoke_lambda_incident_analysis
from .tools import analyze_incident_logs


def check_model_provider_status() -> Tuple[bool, str, Optional[Any]]:
    """Inspect the local environment for supported Strands model providers.

    Checks for:
    1. Gemini provider via strands.models.gemini (requires 'google-genai' and GEMINI_API_KEY/GOOGLE_API_KEY)
    2. Amazon Bedrock provider via strands.models.bedrock (requires AWS credentials)

    Returns:
        (is_available, status_or_blocker_message, model_instance)
        Never logs or prints API keys.
    """
    # 1. Check Gemini availability
    has_gemini_key = bool(os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"))
    if has_gemini_key:
        try:
            from strands.models.gemini import GeminiModel

            # In strands 1.62.0, GeminiModel wraps google-genai
            model = GeminiModel(model_id="gemini-2.5-flash")
            return True, "Gemini provider is available and configured.", model
        except ImportError as exc:
            return (
                False,
                f"Gemini API key is present, but 'google-genai' dependency is missing: {exc}",
                None,
            )
        except Exception as exc:
            return False, f"Failed to initialize GeminiModel: {exc}", None

    # 2. Check Amazon Bedrock availability
    has_aws_creds = bool(
        os.environ.get("AWS_ACCESS_KEY_ID")
        or os.environ.get("AWS_PROFILE")
        or os.environ.get("AWS_DEFAULT_REGION")
    )
    if has_aws_creds:
        try:
            from strands.models.bedrock import BedrockModel

            model = BedrockModel(model_id="us.anthropic.claude-3-5-sonnet-20241022-v2:0")
            return True, "Amazon Bedrock provider is available.", model
        except Exception as exc:
            return False, f"Failed to initialize BedrockModel: {exc}", None

    # Precise blocker explanation without exposing keys
    blocker = (
        "No live model credentials found in environment. "
        "Missing GEMINI_API_KEY / GOOGLE_API_KEY for Google Gemini, "
        "and missing AWS_ACCESS_KEY_ID / AWS_PROFILE for Amazon Bedrock."
    )
    return False, blocker, None


class DeterministicMockIncidentModel(Model):
    """Hermetic mock model implementing the Strands Model interface for testing and offline CLI execution.

    Simulates the two-turn agent loop:
    Turn 1: Model issues a tool use request to either local or remote tool.
    Turn 2: After tool execution, model receives structured report and outputs a guarded synthesis.
    """

    def __init__(
        self,
        target_fixture: str = "incident_out_of_order.json",
        target_tool: str = "analyze_incident_logs",
    ) -> None:
        self.target_fixture = target_fixture
        self.target_tool = target_tool
        self.invocation_count = 0

    def update_config(self, **kwargs: Any) -> None:
        pass

    def get_config(self) -> Dict[str, Any]:
        return {"model_id": "deterministic-mock-model"}

    async def structured_output(
        self, output_model: type[Any], prompt: Messages, system_prompt: Optional[str] = None, **kwargs: Any
    ) -> AsyncGenerator[Dict[str, Any], None]:
        yield {}

    async def stream(
        self,
        messages: Messages,
        tool_specs: Optional[List[ToolSpec]] = None,
        system_prompt: Optional[str] = None,
        **kwargs: Any,
    ) -> AsyncIterable[StreamEvent]:
        self.invocation_count += 1

        if self.invocation_count == 1:
            # Turn 1: Model requests execution of the target tool
            yield {"messageStart": {"role": "assistant"}}
            yield {
                "contentBlockStart": {
                    "start": {
                        "toolUse": {
                            "name": self.target_tool,
                            "toolUseId": "call_itm_001",
                        }
                    }
                }
            }
            yield {
                "contentBlockDelta": {
                    "delta": {
                        "toolUse": {
                            "input": json.dumps({"fixture_name": self.target_fixture})
                        }
                    }
                }
            }
            yield {"contentBlockStop": {}}
            yield {"messageStop": {"stopReason": "tool_use"}}
        else:
            # Turn 2: Model receives tool output and provides guarded analysis adhering to safeguards
            # Inspect tool result from messages if available
            tool_content = ""
            for msg in messages:
                if msg.get("role") == "user":
                    for block in msg.get("content", []):
                        if isinstance(block, dict) and "toolResult" in block:
                            tool_content = str(block["toolResult"])

            is_error = "earliest_recorded_error" in tool_content and '"earliest_recorded_error": null' not in tool_content
            has_tool_failure = '"status": "error"' in tool_content or "'status': 'error'" in tool_content

            if has_tool_failure:
                synthesis = (
                    "### Tool Execution Failure (Agent Guardrails Enforced)\n\n"
                    "- **Analysis Incomplete**: The incident analysis tool reported an execution error.\n"
                    "- **Diagnostic Context**: Check tool parameters, file permissions, or AWS credentials/IAM permissions.\n"
                    "- **Uncertainties**: No conclusions or root-cause hypotheses can be established until logs are analyzed."
                )
            elif is_error:
                synthesis = (
                    "### Incident Analysis Summary (Agent Guardrails Enforced)\n\n"
                    "- **Earliest Recorded Error**: Manifested in `inventory-service` (Event ID: `evt-0005`).\n"
                    "- **Causation Notice**: Chronological priority does NOT establish root cause; "
                    "evt-0005 may be a symptom of unmonitored infrastructure or network latency.\n"
                    "- **Correlated Cascade**: Subsequent errors observed across `order-service` and `api-gateway` "
                    "(Event IDs: `evt-0006`, `evt-0007`, `evt-0010`, `evt-0011`).\n"
                    "- **Competing Hypotheses**: (1) Database connection pool saturation; (2) Network partition; "
                    "(3) Upstream retry storm.\n"
                    "- **Telemetry Gaps / Unknowns**: Host-level CPU/memory metrics and background worker logs are absent."
                )
            else:
                synthesis = (
                    "### Baseline Health Summary (Agent Guardrails Enforced)\n\n"
                    "- **Scope**: No errors were detected in the supplied logs across observed services.\n"
                    "- **Limitation Notice**: Absence of error logs does not prove global enterprise system health; "
                    "silent failures or uninstrumented components cannot be ruled out.\n"
                    "- **Evidence Event IDs**: `evt-0001`, `evt-0002`, `evt-0003`, `evt-0004`, `evt-0005`."
                )

            yield {"messageStart": {"role": "assistant"}}
            yield {"contentBlockStart": {"start": {"text": ""}}}
            yield {"contentBlockDelta": {"delta": {"text": synthesis}}}
            yield {"contentBlockStop": {}}
            yield {"messageStop": {"stopReason": "end_turn"}}


def create_incident_agent(
    model: Optional[Model] = None,
    target_fixture: str = "incident_out_of_order.json",
    tool_mode: str = "local",
) -> Tuple[Agent, str]:
    """Create a configured Strands Agent equipped with the Incident Time Machine tool.

    Args:
        model: Custom Strands Model instance (optional).
        target_fixture: Default fixture name to investigate.
        tool_mode: 'local' (uses local deterministic tool) or 'remote'/'lambda' (uses AWS Lambda tool).

    If no model is supplied, attempts to use available environment credentials, falling back
    to DeterministicMockIncidentModel if credentials are unavailable.

    Returns:
        (agent_instance, provider_description)
    """
    selected_tool = (
        invoke_lambda_incident_analysis
        if tool_mode.lower() in {"remote", "lambda"}
        else analyze_incident_logs
    )
    target_tool_name = (
        "invoke_lambda_incident_analysis"
        if tool_mode.lower() in {"remote", "lambda"}
        else "analyze_incident_logs"
    )

    if model is not None:
        agent = Agent(
            model=model,
            tools=[selected_tool],
            system_prompt=INCIDENT_AGENT_SYSTEM_PROMPT,
        )
        return agent, f"Custom model provider ({tool_mode} tool)"

    is_available, status_msg, detected_model = check_model_provider_status()

    if is_available and detected_model is not None:
        agent = Agent(
            model=detected_model,
            tools=[selected_tool],
            system_prompt=INCIDENT_AGENT_SYSTEM_PROMPT,
        )
        return agent, f"{status_msg} ({tool_mode} tool)"

    # Fallback to deterministic mock model for testing and local execution without API keys
    mock_model = DeterministicMockIncidentModel(
        target_fixture=target_fixture,
        target_tool=target_tool_name,
    )
    agent = Agent(
        model=mock_model,
        tools=[selected_tool],
        system_prompt=INCIDENT_AGENT_SYSTEM_PROMPT,
    )
    return agent, f"Mock Model Harness ({tool_mode} tool; Blocker: {status_msg})"
