#!/usr/bin/env python3
"""Guided EX-04 benign-observable and false-positive exercise."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_PATH = ROOT / "services" / "playground" / "app.py"
EVENT_PATH = ROOT / "exercises" / "benign-observable-finding.json"
DEFAULT_DB = ROOT / "playground-data" / "exercises.db"
SPEC = importlib.util.spec_from_file_location("playground", APP_PATH)
playground = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(playground)


def database(path: str):
    return playground.Store(path)


def finding() -> dict:
    result = playground.normalize_securityhub(json.loads(EVENT_PATH.read_text()))
    if len(result) != 1:
        raise RuntimeError("EX-04 must contain exactly one finding")
    return result[0]


def locate_case(store) -> dict:
    key = finding()["incident_key"]
    matches = [case for case in store.list_cases() if case["incident_key"] == key]
    if not matches:
        raise RuntimeError("EX-04 case has not been prepared")
    return matches[0]


def prepare(args: argparse.Namespace) -> int:
    store = database(args.database)
    case, created = store.ingest(finding())
    intel = case["enrichment"][0]
    stats = intel["last_analysis_stats"]
    print("EX-04 — Benign Observable and False-Positive Closure")
    print("=" * 53)
    print(f"Case ID:          {case['id']}")
    print(f"New case:         {'yes' if created else 'no'}")
    print(f"Status:           {case['status']}")
    print(f"Severity:         {case['severity']}")
    print(f"Confidence:       {case['finding']['confidence']}%")
    print(f"Observable:       {intel['type']} {intel['value']}")
    print(f"Intel verdict:    {intel['verdict']}")
    print(f"Reputation:       {intel['reputation']}")
    print(
        "Engine votes:     "
        f"{stats['malicious']} malicious, {stats['suspicious']} suspicious, "
        f"{stats['harmless']} harmless"
    )
    print(f"Proposed action:  {case['proposed_action']}")
    print("\nContext")
    print("- The detector is explicitly low fidelity")
    print("- Source confidence is 25%")
    print("- Threat intelligence reports 0 malicious and 0 suspicious votes")
    print("- All 53 recorded engines classify the observable as harmless")
    print("- No corroborating evidence is present")
    print("\nAnalyst task")
    print("Choose a disposition and explain whether this is a false positive,")
    print("a benign positive, or an undetermined event requiring more evidence.")
    return 0


def decide(args: argparse.Namespace) -> int:
    store = database(args.database)
    case = locate_case(store)
    if case["proposed_action"] is not None:
        raise RuntimeError("benign observable unexpectedly has a proposed response")
    classified = store.disposition(
        case["id"], args.analyst, args.classification, args.rationale
    )
    if classified["execution"] is not None:
        raise RuntimeError("response execution exists on benign case")
    closed = store.close(
        case["id"],
        args.analyst,
        f"{args.classification}: {args.rationale}",
    )
    events = [event["event_type"] for event in closed["audit"]]
    if "response_proposed" in events or "response_simulated" in events:
        raise RuntimeError("benign case contains response activity")
    print(f"Disposition recorded: {args.classification} by {args.analyst}")
    print("Verified:")
    print("- No containment was proposed")
    print("- No response was executed")
    print("- Analyst rationale was audited")
    print(f"- Case state is {closed['status']}")
    print("Audit trail:")
    for index, event in enumerate(closed["audit"], 1):
        print(f"  {index:02d}. {event['event_type']} — {event['actor']}")
    print(f"PASS: EX-04 completed for case {closed['id']}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", default=str(DEFAULT_DB))
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("prepare")
    decision = commands.add_parser("decide")
    decision.add_argument(
        "--classification",
        choices=["false_positive", "benign_positive", "undetermined"],
        required=True,
    )
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
