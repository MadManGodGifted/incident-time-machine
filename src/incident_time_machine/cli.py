"""CLI entrypoint for Incident Time Machine."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import IncidentTimeMachine, format_cli_summary


def main(args: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Incident Time Machine: Deterministic log reconstruction and analysis engine."
    )
    parser.add_argument(
        "fixture",
        type=str,
        help="Path to JSON fixture file containing raw log entries.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON analysis report instead of human-readable summary.",
    )

    parsed = parser.parse_args(args)
    fixture_path = Path(parsed.fixture)

    if not fixture_path.exists():
        print(f"Error: Fixture file not found: {fixture_path}", file=sys.stderr)
        return 1

    try:
        engine = IncidentTimeMachine.from_file(fixture_path)
        report = engine.analyze()

        if parsed.json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(format_cli_summary(report))
        return 0
    except Exception as exc:
        print(f"Error during analysis: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
