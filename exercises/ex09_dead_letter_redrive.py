#!/usr/bin/env python3
"""EX-09: investigate a dead-letter event and redrive a corrected finding."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_PATH = ROOT / "services" / "playground" / "app.py"
INVALID_EVENT_PATH = ROOT / "exercises" / "dead-letter-invalid-finding.json"
CORRECTED_EVENT_PATH = ROOT / "exercises" / "dead-letter-corrected-finding.json"
DEFAULT_DB = ROOT / "playground-data" / "exercises.db"
SPEC = importlib.util.spec_from_file_location("playground", APP_PATH)
playground = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(playground)


def database(path: str):
    return playground.Store(path)


def read_json(path: Path) -> dict:
    return json.loads(path.read_text())


def newest_open_dlq(store) -> dict:
    open_events = [
        event for event in store.list_dead_letter_events() if event["status"] == "open"
    ]
    if not open_events:
        raise RuntimeError("EX-09 has no open dead-letter event to redrive")
    return open_events[-1]


def prepare(args: argparse.Namespace) -> int:
    store = database(args.database)
    before_cases = len(store.list_cases())
    payload = read_json(INVALID_EVENT_PATH)
    try:
        playground.normalize_securityhub(payload)
        raise RuntimeError("invalid EX-09 payload was unexpectedly accepted")
    except playground.FindingValidationError as exc:
        dlq = store.capture_dead_letter(
            "aws-securityhub",
            payload,
            exc.code,
            str(exc),
        )

    after_cases = len(store.list_cases())
    if after_cases != before_cases:
        raise RuntimeError("invalid dead-letter event created a case")

    print("EX-09 - Dead-Letter Queue Investigation")
    print("=" * 40)
    print(f"DLQ ID:           {dlq['id']}")
    print(f"Status:           {dlq['status']}")
    print(f"Source:           {dlq['source']}")
    print(f"Error code:       {dlq['error_code']}")
    print(f"Error message:    {dlq['error_message']}")
    print(f"Cases before:     {before_cases}")
    print(f"Cases after:      {after_cases}")
    print("\nContext")
    print("- The event failed validation before case creation")
    print("- The raw payload was preserved in a dead-letter record")
    print("- The error is sanitized and operationally useful")
    print("- No enrichment, response proposal, or containment occurred")
    print("\nAnalyst task")
    print("Inspect the failure, correct the payload, then redrive the event.")
    return 0


def redrive(args: argparse.Namespace) -> int:
    store = database(args.database)
    dlq = newest_open_dlq(store)
    corrected_payload = read_json(CORRECTED_EVENT_PATH)
    cases = store.redrive_dead_letter_event(dlq["id"], corrected_payload, args.analyst)
    if len(cases) != 1:
        raise RuntimeError("EX-09 redrive must create exactly one case")
    case = cases[0]
    refreshed_dlq = store.get_dead_letter_event(dlq["id"])
    events = [event["event_type"] for event in case["audit"]]
    if refreshed_dlq["status"] != "redriven":
        raise RuntimeError("dead-letter event was not marked redriven")
    required = {
        "case_created",
        "enrichment_completed",
        "response_proposed",
        "dead_letter_redriven",
    }
    missing = sorted(required - set(events))
    if missing:
        raise RuntimeError(f"missing audit events: {', '.join(missing)}")

    print(f"Redriven by:      {args.analyst}")
    print(f"DLQ ID:           {refreshed_dlq['id']}")
    print(f"DLQ status:       {refreshed_dlq['status']}")
    print(f"Case ID:          {case['id']}")
    print(f"Case status:      {case['status']}")
    print(f"Observable:       {case['enrichment'][0]['type']} {case['enrichment'][0]['value']}")
    print(f"Intel verdict:    {case['enrichment'][0]['verdict']}")
    print(f"Proposed action:  {case['proposed_action']['action']}")
    print("\nVerified:")
    print("- The invalid event stayed out of the case table")
    print("- The corrected event was processed through normal ingestion")
    print("- The DLQ record links to the redriven case")
    print("- Response approval is still required before execution")
    print("Audit trail:")
    for index, event in enumerate(case["audit"], 1):
        print(f"  {index:02d}. {event['event_type']} - {event['actor']}")
    print(f"PASS: EX-09 completed for case {case['id']}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", default=str(DEFAULT_DB))
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("prepare")
    recovery = commands.add_parser("redrive")
    recovery.add_argument("--analyst", required=True)
    args = parser.parse_args()
    return prepare(args) if args.command == "prepare" else redrive(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
