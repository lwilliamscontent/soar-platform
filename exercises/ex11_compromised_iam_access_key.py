#!/usr/bin/env python3
"""EX-11: investigate a compromised IAM access key and approve reversible containment."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_PATH = ROOT / "services" / "playground" / "app.py"
EVENT_PATH = ROOT / "exercises" / "compromised-iam-access-key-finding.json"
DEFAULT_DB = ROOT / "playground-data" / "exercises.db"
SPEC = importlib.util.spec_from_file_location("playground", APP_PATH)
playground = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(playground)


def database(path: str):
    return playground.Store(path)


def finding() -> dict:
    result = playground.normalize_securityhub(json.loads(EVENT_PATH.read_text()))
    if len(result) != 1:
        raise RuntimeError("EX-11 must contain exactly one finding")
    return result[0]


def locate_case(store) -> dict:
    key = finding()["incident_key"]
    matches = [case for case in store.list_cases() if case["incident_key"] == key]
    if not matches:
        raise RuntimeError("EX-11 case has not been prepared")
    return matches[0]


def prepare(args: argparse.Namespace) -> int:
    store = database(args.database)
    case, created = store.ingest(finding())
    intel = case["enrichment"][0]
    action = case["proposed_action"]
    print("EX-11 - Compromised IAM Access Key")
    print("=" * 38)
    print(f"Case ID:          {case['id']}")
    print(f"New case:         {'yes' if created else 'no'}")
    print(f"Status:           {case['status']}")
    print(f"Severity:         {case['severity']}")
    print(f"Confidence:       {case['finding']['confidence']}%")
    print(f"Observable:       {intel['type']} {intel['value']}")
    print(f"Intel verdict:    {intel['verdict']}")
    print(f"Risk score:       {intel['risk_score']}")
    print(f"Principal:        {intel['principal']}")
    print(f"Key status:       {intel['access_key_status']}")
    print(f"Proposed action:  {action['action']}")
    print(f"Rollback:         {action['rollback']}")
    print("\nObserved anomalies")
    for anomaly in intel["anomalies"]:
        print(f"- {anomaly}")
    print("\nContext")
    print("- The target is an IAM access key, not a network or file indicator")
    print("- The simulated response disables the key instead of deleting it")
    print("- Previous key state is preserved for rollback review")
    print("- Analyst approval is required before containment")
    print("\nAnalyst task")
    print("Approve only if the identity risk justifies reversible key disablement.")
    return 0


def decide(args: argparse.Namespace) -> int:
    store = database(args.database)
    case = locate_case(store)
    if case["proposed_action"]["action"] != "disable_iam_access_key":
        raise RuntimeError("EX-11 expected an IAM access-key response proposal")
    approved = store.approve(case["id"], args.analyst, "approved", args.rationale)
    executed = store.execute(approved["id"], args.analyst)
    if executed["execution"]["action"] != "disable_iam_access_key":
        raise RuntimeError("EX-11 executed the wrong response action")
    closed = store.close(
        executed["id"],
        args.analyst,
        "Compromised IAM access-key disablement simulated and rollback recorded",
    )
    events = [event["event_type"] for event in closed["audit"]]
    required = {
        "case_created",
        "enrichment_completed",
        "response_proposed",
        "response_approved",
        "response_simulated",
        "response_verified",
        "case_closed",
    }
    missing = sorted(required - set(events))
    if missing:
        raise RuntimeError(f"missing audit events: {', '.join(missing)}")
    print(f"Approved by:      {args.analyst}")
    print(f"Case ID:          {closed['id']}")
    print(f"Final state:      {closed['status']}")
    print(f"Action:           {closed['execution']['action']}")
    print(f"Target key:       {closed['execution']['target']}")
    print(f"Verification:     {closed['execution']['verification']}")
    print(f"Rollback:         {closed['execution']['rollback']}")
    print("\nVerified:")
    print("- AWS access-key observable was validated and enriched")
    print("- The proposed response disabled the key rather than deleting it")
    print("- Pre-change state and rollback instructions were preserved")
    print("- Simulated execution required analyst approval")
    print("Audit trail:")
    for index, event in enumerate(closed["audit"], 1):
        print(f"  {index:02d}. {event['event_type']} - {event['actor']}")
    print(f"PASS: EX-11 completed for case {closed['id']}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", default=str(DEFAULT_DB))
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("prepare")
    decision = commands.add_parser("decide")
    decision.add_argument("--analyst", required=True)
    decision.add_argument("--rationale", required=True)
    args = parser.parse_args()
    return prepare(args) if args.command == "prepare" else decide(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
