#!/usr/bin/env python3
"""Guided EX-01 suspicious-IP investigation without Docker or HTTP."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_PATH = ROOT / "services" / "playground" / "app.py"
EVENT_PATH = ROOT / "exercises" / "suspicious-ip-finding.json"
DEFAULT_DB = ROOT / "playground-data" / "exercises.db"
SPEC = importlib.util.spec_from_file_location("playground", APP_PATH)
playground = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(playground)


def store(path: str) -> object:
    return playground.Store(path)


def locate_case(database: object) -> dict:
    findings = playground.normalize_securityhub(json.loads(EVENT_PATH.read_text()))
    if len(findings) != 1:
        raise RuntimeError("EX-01 must contain exactly one finding")
    key = findings[0]["incident_key"]
    cases = [case for case in database.list_cases() if case["incident_key"] == key]
    if not cases:
        raise RuntimeError("EX-01 case has not been prepared")
    return cases[0]


def prepare(args: argparse.Namespace) -> int:
    database = store(args.database)
    event = json.loads(EVENT_PATH.read_text())
    findings = playground.normalize_securityhub(event)
    if len(findings) != 1:
        raise RuntimeError("expected exactly one normalized finding")
    case, created = database.ingest(findings[0])
    print("EX-01 — Suspicious IP Investigation")
    print("=" * 42)
    print(f"Case ID:       {case['id']}")
    print(f"Case state:    {case['status']}")
    print(f"New case:      {'yes' if created else 'no (existing case correlated)'}")
    print(f"Title:         {case['title']}")
    print(f"Severity:      {case['severity']}")
    print(f"Confidence:    {case['finding']['confidence']}%")
    print(f"Source:        {case['source']}")
    print(f"AWS account:   {case['finding'].get('account_id')}")
    print(f"Region:        {case['finding'].get('region')}")
    print("\nObservable evidence")
    for result in case["enrichment"]:
        stats = result["last_analysis_stats"]
        print(f"- {result['type']}: {result['value']}")
        print(f"  Provider:    {result['provider']}")
        print(f"  Verdict:     {result['verdict']}")
        print(f"  Reputation:  {result['reputation']}")
        print(
            "  Engines:     "
            f"{stats['malicious']} malicious, {stats['suspicious']} suspicious, "
            f"{stats['harmless']} harmless"
        )
    action = case["proposed_action"]
    print("\nProposed response")
    print(f"- Action:      {action['action']}")
    print(f"- Target:      {action['target']}")
    print(f"- Mode:        {action['mode']} (no real control changes)")
    print(f"- Reason:      {action['reason']}")
    print(f"- Rollback:    {action['rollback']}")
    print("\nAnalyst task")
    print("Decide whether the available evidence justifies the simulated temporary block.")
    print("Record both your decision and reasoning; do not rely on severity alone.")
    return 0


def decide(args: argparse.Namespace) -> int:
    if len(args.rationale.strip()) < 15:
        raise ValueError("rationale must contain at least 15 characters")
    database = store(args.database)
    case = locate_case(database)
    reviewed = database.approve(case["id"], args.analyst, args.decision, args.rationale)
    print(f"Decision recorded: {args.decision} by {args.analyst}")
    if args.decision == "approved":
        reviewed = database.execute(case["id"], args.analyst)
        print("Simulated containment executed and verified.")
        print(f"Rollback: {reviewed['execution']['rollback']}")
    else:
        print("Containment was not executed.")
    resolution = (
        "Synthetic malicious IP contained and rollback documented"
        if args.decision == "approved"
        else "Proposed containment rejected based on analyst review"
    )
    closed = database.close(case["id"], args.analyst, resolution)
    print(f"Case state: {closed['status']}")
    print("Audit trail:")
    for index, event in enumerate(closed["audit"], 1):
        print(f"  {index:02d}. {event['event_type']} — {event['actor']}")
    expected = "response_simulated" if args.decision == "approved" else "response_rejected"
    if expected not in [event["event_type"] for event in closed["audit"]]:
        raise RuntimeError("expected decision evidence is missing from audit trail")
    print(f"PASS: EX-01 completed for case {closed['id']}")
    return 0


def show(args: argparse.Namespace) -> int:
    print(json.dumps(locate_case(store(args.database)), indent=2))
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--database", default=str(DEFAULT_DB))
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("prepare")
    decision = commands.add_parser("decide")
    decision.add_argument("--decision", choices=["approved", "rejected"], required=True)
    decision.add_argument("--analyst", required=True)
    decision.add_argument("--rationale", required=True)
    commands.add_parser("show")
    return result


def main() -> int:
    args = parser().parse_args()
    return {"prepare": prepare, "decide": decide, "show": show}[args.command](args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
