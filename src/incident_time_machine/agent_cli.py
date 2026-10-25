"""CLI interface for running the Strands Incident Agent."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .agent import check_model_provider_status, create_incident_agent
from .remote_tool import DEFAULT_FUNCTION_NAME, DEFAULT_REGION, invoke_lambda_incident_analysis
from .tools import FIXTURES_DIR, analyze_incident_logs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Incident Time Machine: Strands Agent CLI"
    )
    parser.add_argument(
        "fixture",
        type=str,
        help="Name or relative path of the fixture file inside the authorized fixtures directory (e.g. 'incident_out_of_order.json').",
    )
    parser.add_argument(
        "--remote-lambda",
        action="store_true",
        help="Connect agent to deployed AWS Lambda engine ('incident-time-machine') via boto3.",
    )
    parser.add_argument(
        "--function-name",
        type=str,
        default=DEFAULT_FUNCTION_NAME,
        help=f"AWS Lambda function name or ARN (default: '{DEFAULT_FUNCTION_NAME}').",
    )
    parser.add_argument(
        "--region",
        type=str,
        default=DEFAULT_REGION,
        help=f"AWS region of deployed Lambda function (default: '{DEFAULT_REGION}').",
    )
    parser.add_argument(
        "--tool-only",
        action="store_true",
        help="Execute only the deterministic Strands tool directly without running the agent loop.",
    )

    args = parser.parse_args(argv)
    fixture_input = args.fixture.strip()
    tool_mode = "remote" if args.remote_lambda else "local"

    print("=" * 70)
    print("      INCIDENT TIME MACHINE - STRANDS AGENT HARNESS")
    print("=" * 70)
    print(f"Target Fixture       : {fixture_input}")
    print(f"Authorized Directory : {FIXTURES_DIR}")
    print(f"Tool Execution Mode  : {tool_mode.upper()} {'(AWS Lambda)' if args.remote_lambda else '(Local Engine)'}")
    if args.remote_lambda:
        print(f"Target Lambda Func   : {args.function_name}")
        print(f"Target AWS Region    : {args.region}")

    # Check model provider availability
    is_available, status_msg, _ = check_model_provider_status()
    print(f"Model Provider Status: {status_msg}")

    if args.tool_only:
        if args.remote_lambda:
            print(f"\n--- Executing Remote Lambda Tool: invoke_lambda_incident_analysis ({args.region}) ---")
            tool_result = invoke_lambda_incident_analysis(
                fixture_name=fixture_input,
                function_name=args.function_name,
                region_name=args.region,
            )
        else:
            print("\n--- Executing Local Strands Tool: analyze_incident_logs ---")
            tool_result = analyze_incident_logs(fixture_input)

        if tool_result.get("status") == "error":
            print(f"Tool Error [{tool_result.get('error_code')}]: {tool_result.get('message')}", file=sys.stderr)
            return 1

        print(f"Execution Mode            : {tool_result.get('execution_mode', 'local')}")
        print(f"Timeline Events Processed : {len(tool_result.get('timeline', []))}")
        print(f"Correlated Traces         : {len(tool_result.get('traces', {}))}")
        print(f"Earliest Recorded Error   : {tool_result.get('earliest_recorded_error')}")
        print(f"Hypotheses Generated      : {len(tool_result.get('hypotheses', []))}")
        print(f"Unknowns / Telemetry Gaps : {len(tool_result.get('unknowns', []))}")
        print("=" * 70)
        return 0

    print(f"\n--- Initializing Strands Agent ({tool_mode} tool) ---")
    agent, provider_info = create_incident_agent(
        target_fixture=fixture_input,
        tool_mode=tool_mode,
    )
    print(f"Agent Harness Active : {provider_info}")
    print("\n--- Invoking Agent with Incident Investigation Prompt ---")

    tool_name = "invoke_lambda_incident_analysis" if args.remote_lambda else "analyze_incident_logs"
    prompt = (
        f"Investigate the incident described in fixture '{fixture_input}'. "
        f"Invoke the '{tool_name}' tool to inspect the deterministic timeline. "
        "Do not invent event IDs or telemetry. Adhere strictly to all system prompt safeguards."
    )

    try:
        response = agent(prompt)
        print("\n--- Agent Response ---")
        print(response)
        print("=" * 70)
        return 0
    except Exception as exc:
        print(f"Agent Execution Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
