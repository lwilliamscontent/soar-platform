#!/usr/bin/env python3
"""EX-14: approve simulated containment, verify it, then perform verified rollback."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_PATH = ROOT / "services" / "playground" / "app.py"
EVENT_PATH = ROOT / "exercises" / "approved-response-rollback-finding.json"
DEFAULT_DB = ROOT / "playground-data" / "exercises.db"
SPEC = importlib.util.spec_from_file_location("playground", APP_PATH)
playground = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(playground)


def database(path: str):
    return playground.Store(path)


def finding() -> dict:
    result = playground.normalize_securityhub(json.loads(EVENT_PATH.read_text()))
    if len(result) != 1:
        raise RuntimeError("EX-14 must contain exactly one finding")
    return result[0]


def locate_case(store) -> dict:
    key = finding()["incident_key"]
    matches = [case for case in store.list_cases() if case["incident_key"] == key]
    if not matches:
        raise RuntimeError("EX-14 case has not been prepared")
    return matches[0]


def prepare(args: argparse.Namespace) -> int:
    store = database(args.database)
    case, created = store.ingest(finding())
    intel = case["enrichment"][0]
    action = case["proposed_action"]
    print("EX-14 - Approved Response and Rollback")
    print("=" * 39)
    print(f"Case ID:          {case['id']}")
    print(f"New case:         {'yes' if created else 'no'}")
    print(f"Status:           {case['status']}")
    print(f"Observable:       {intel['value']}")
    print(f"Intel verdict:    {intel['verdict']}")
    print(f"Proposed action:  {action['action']}")
    print(f"Rollback plan:    {action['rollback']}")
    print("\nExercise phases")
    print("1. Approve and execute the temporary simulated block.")
    print("2. Review containment verification and preserve the execution record.")
    print("3. Roll back the block with a recovery rationale.")
    print("4. Verify the rollback, then close the case.")
    return 0


def respond(args: argparse.Namespace) -> int:
    store = database(args.database)
    case = locate_case(store)
    if case["proposed_action"]["action"] != "block_ip":
        raise RuntimeError("EX-14 expected a temporary IP-block response proposal")
    approved = store.approve(case["id"], args.analyst, "approved", args.rationale)
    contained = store.execute(approved["id"], args.analyst)
    print(f"Approved by:      {args.analyst}")
    print(f"Case ID:          {contained['id']}")
    print(f"State:            {contained['status']}")
    print(f"Action:           {contained['execution']['action']}")
    print(f"Verification:     {contained['execution']['verification']}")
    print(f"Rollback plan:    {contained['execution']['rollback']}")
    return 0


def recover(args: argparse.Namespace) -> int:
    store = database(args.database)
    case = locate_case(store)
    recovered = store.rollback(case["id"], args.analyst, args.rationale)
    closed = store.close(
        recovered["id"],
        args.analyst,
        "Temporary block removed after recovery validation and rollback verification",
    )
    rollback = closed["rollback"]
    events = [event["event_type"] for event in closed["audit"]]
    required = {
        "case_created",
        "enrichment_completed",
        "response_proposed",
        "response_approved",
        "response_simulated",
        "response_verified",
        "response_rolled_back",
        "response_rollback_verified",
        "case_closed",
    }
    missing = sorted(required - set(events))
    if missing:
        raise RuntimeError(f"missing audit events: {', '.join(missing)}")
    print(f"Recovered by:     {args.analyst}")
    print(f"Case ID:          {closed['id']}")
    print(f"Final state:      {closed['status']}")
    print(f"Rollback action:  {rollback['action']}")
    print(f"Target:           {rollback['target']}")
    print(f"Verification:     {rollback['verification']}")
    print("\nVerified:")
    print("- Containment and rollback are separate auditable actions")
    print("- The original execution record remains available after recovery")
    print("- Rollback required a rationale and completed verification")
    print("Audit trail:")
    for index, event in enumerate(closed["audit"], 1):
        print(f"  {index:02d}. {event['event_type']} - {event['actor']}")
    print(f"PASS: EX-14 completed for case {closed['id']}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", default=str(DEFAULT_DB))
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("prepare")
    response = commands.add_parser("respond")
    response.add_argument("--analyst", required=True)
    response.add_argument("--rationale", required=True)
    recovery = commands.add_parser("recover")
    recovery.add_argument("--analyst", required=True)
    recovery.add_argument("--rationale", required=True)
    args = parser.parse_args()
    return {
        "prepare": prepare,
        "respond": respond,
        "recover": recover,
    }[args.command](args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError, PermissionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
