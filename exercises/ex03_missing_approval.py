#!/usr/bin/env python3
"""EX-03: attempt a response with no analyst approval."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_PATH = ROOT / "services" / "playground" / "app.py"
EVENT_PATH = ROOT / "exercises" / "unauthorized-response-finding.json"
DEFAULT_DB = ROOT / "playground-data" / "exercises.db"
SPEC = importlib.util.spec_from_file_location("playground", APP_PATH)
playground = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(playground)


def run(database_path: str, actor: str) -> int:
    store = playground.Store(database_path)
    event = json.loads(EVENT_PATH.read_text())
    findings = playground.normalize_securityhub(event)
    if len(findings) != 1:
        raise RuntimeError("EX-03 must contain exactly one finding")

    case, created = store.ingest(findings[0])
    print("EX-03 — Response Without Approval")
    print("=" * 37)
    print(f"Case ID:          {case['id']}")
    print(f"New case:         {'yes' if created else 'no'}")
    print(f"Status:           {case['status']}")
    print(f"Severity:         {case['severity']}")
    print(f"Observable:       {case['enrichment'][0]['value']}")
    print(f"Intel verdict:    {case['enrichment'][0]['verdict']}")
    print(f"Proposed action:  {case['proposed_action']['action']}")
    print(f"Approval record:  {case['approval']}")

    if case["status"] != "awaiting_approval" or case["approval"] is not None:
        raise RuntimeError("case is not in the required unapproved state")

    print(f"\nAttempting execution as {actor} without an analyst decision...")
    try:
        store.execute(case["id"], actor)
        raise RuntimeError("response unexpectedly executed")
    except PermissionError as exc:
        print(f"DENIED: {exc}")

    denied = store.get_case(case["id"])
    events = [event["event_type"] for event in denied["audit"]]
    if denied["execution"] is not None:
        raise RuntimeError("execution data exists after denied response")
    if denied["status"] != "awaiting_approval":
        raise RuntimeError("denied response changed the case status")
    if "response_execution_denied" not in events:
        raise RuntimeError("authorization denial was not audited")
    if "response_simulated" in events:
        raise RuntimeError("denied response produced a simulation event")

    print("Verified:")
    print("- No response execution record exists")
    print("- Case remains awaiting approval")
    print("- Authorization denial is in the audit trail")
    print("- No response_simulated event exists")

    closed = store.close(
        case["id"],
        "control-test-analyst",
        "Authorization control validated; no response action was authorized",
    )
    print(f"\nFinal state: {closed['status']}")
    print("Audit trail:")
    for index, event in enumerate(closed["audit"], 1):
        print(f"  {index:02d}. {event['event_type']} — {event['actor']}")
    print(f"PASS: EX-03 completed for case {closed['id']}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", default=str(DEFAULT_DB))
    parser.add_argument("--actor", default="unauthorized-automation")
    args = parser.parse_args()
    return run(args.database, args.actor)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
