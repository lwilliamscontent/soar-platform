#!/usr/bin/env python3
"""Guided EX-02 rejection exercise without Docker or HTTP."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_PATH = ROOT / "services" / "playground" / "app.py"
EVENT_PATH = ROOT / "exercises" / "insufficient-evidence-finding.json"
DEFAULT_DB = ROOT / "playground-data" / "exercises.db"
SPEC = importlib.util.spec_from_file_location("playground", APP_PATH)
playground = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(playground)


def database(path: str):
    return playground.Store(path)


def normalized_finding() -> dict:
    findings = playground.normalize_securityhub(json.loads(EVENT_PATH.read_text()))
    if len(findings) != 1:
        raise RuntimeError("EX-02 must contain exactly one finding")
    return findings[0]


def locate_case(store) -> dict:
    key = normalized_finding()["incident_key"]
    matches = [case for case in store.list_cases() if case["incident_key"] == key]
    if not matches:
        raise RuntimeError("EX-02 case has not been prepared")
    return matches[0]


def prepare(args: argparse.Namespace) -> int:
    store = database(args.database)
    case, created = store.ingest(normalized_finding())
    result = case["enrichment"][0]
    stats = result["last_analysis_stats"]
    print("EX-02 — Reject an Insufficient-Evidence Response")
    print("=" * 53)
    print(f"Case ID:       {case['id']}")
    print(f"Case state:    {case['status']}")
    print(f"New case:      {'yes' if created else 'no (existing case correlated)'}")
    print(f"Title:         {case['title']}")
    print(f"Severity:      {case['severity']}")
    print(f"Confidence:    {case['finding']['confidence']}%")
    print(f"Observable:    {result['type']} {result['value']}")
    print(f"Intel verdict: {result['verdict']}")
    print(f"Reputation:    {result['reputation']}")
    print(
        "Engine votes:  "
        f"{stats['malicious']} malicious, {stats['suspicious']} suspicious, "
        f"{stats['harmless']} harmless"
    )
    action = case["proposed_action"]
    print("\nAutomation recommendation")
    print(f"- Proposed:    {action['action']} for {action['target']}")
    print(f"- Reason:      {action['reason']}")
    print(f"- Mode:        {action['mode']}")
    print("\nMissing context")
    print("- No corroborating internal telemetry")
    print("- No confirmed asset owner or business impact")
    print("- No evidence of successful exploitation or data transfer")
    print("- Threat-intelligence results are overwhelmingly harmless")
    print("\nAnalyst task")
    print("Decide whether the proposed block is justified by the available evidence.")
    print("A SOAR recommendation is not authorization; document why you accept or reject it.")
    return 0


def decide(args: argparse.Namespace) -> int:
    if len(args.rationale.strip()) < 15:
        raise ValueError("rationale must contain at least 15 characters")
    store = database(args.database)
    case = locate_case(store)
    reviewed = store.approve(case["id"], args.analyst, args.decision, args.rationale)
    print(f"Decision recorded: {args.decision} by {args.analyst}")
    blocked = False
    if args.decision == "rejected":
        try:
            store.execute(case["id"], args.analyst)
        except PermissionError as exc:
            blocked = True
            print(f"Control check passed: execution blocked — {exc}")
        if not blocked:
            raise RuntimeError("rejected response was unexpectedly executable")
    else:
        print("WARNING: approval was recorded; EX-02's intended lesson is safe rejection.")
        reviewed = store.execute(case["id"], args.analyst)
    resolution = (
        "Containment rejected; insufficient evidence and additional investigation required"
        if args.decision == "rejected"
        else "Simulation executed after analyst approval"
    )
    closed = store.close(case["id"], args.analyst, resolution)
    print(f"Case state: {closed['status']}")
    print("Audit trail:")
    for index, event in enumerate(closed["audit"], 1):
        print(f"  {index:02d}. {event['event_type']} — {event['actor']}")
    if args.decision == "rejected" and any(
        event["event_type"] == "response_simulated" for event in closed["audit"]
    ):
        raise RuntimeError("rejected case contains an execution event")
    print(f"PASS: EX-02 completed for case {closed['id']}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", default=str(DEFAULT_DB))
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("prepare")
    decision = commands.add_parser("decide")
    decision.add_argument("--decision", choices=["approved", "rejected"], required=True)
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
