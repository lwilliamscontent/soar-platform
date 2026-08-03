#!/usr/bin/env python3
"""EX-10: investigate a malicious SHA-256 file hash and approve evidence-safe response."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_PATH = ROOT / "services" / "playground" / "app.py"
EVENT_PATH = ROOT / "exercises" / "malicious-file-hash-finding.json"
DEFAULT_DB = ROOT / "playground-data" / "exercises.db"
SPEC = importlib.util.spec_from_file_location("playground", APP_PATH)
playground = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(playground)


def database(path: str):
    return playground.Store(path)


def finding() -> dict:
    result = playground.normalize_securityhub(json.loads(EVENT_PATH.read_text()))
    if len(result) != 1:
        raise RuntimeError("EX-10 must contain exactly one finding")
    return result[0]


def locate_case(store) -> dict:
    key = finding()["incident_key"]
    matches = [case for case in store.list_cases() if case["incident_key"] == key]
    if not matches:
        raise RuntimeError("EX-10 case has not been prepared")
    return matches[0]


def prepare(args: argparse.Namespace) -> int:
    store = database(args.database)
    case, created = store.ingest(finding())
    intel = case["enrichment"][0]
    stats = intel["last_analysis_stats"]
    action = case["proposed_action"]
    print("EX-10 - Malicious File-Hash Investigation")
    print("=" * 43)
    print(f"Case ID:          {case['id']}")
    print(f"New case:         {'yes' if created else 'no'}")
    print(f"Status:           {case['status']}")
    print(f"Severity:         {case['severity']}")
    print(f"Confidence:       {case['finding']['confidence']}%")
    print(f"Observable:       {intel['type']} {intel['value']}")
    print(f"Intel verdict:    {intel['verdict']}")
    print(f"File type:        {intel['file_type']}")
    print(f"Threat class:     {intel['popular_threat_classification']}")
    print(
        "Engine votes:     "
        f"{stats['malicious']} malicious, {stats['suspicious']} suspicious, "
        f"{stats['harmless']} harmless"
    )
    print(f"Proposed action:  {action['action']}")
    print(f"Evidence rule:    {action['evidence_handling']}")
    print("\nContext")
    print("- The observable is a SHA-256 file hash, not an IP address")
    print("- The proposed response preserves evidence before remediation")
    print("- The simulated action queues host quarantine and file collection")
    print("- Analyst approval is required before execution")
    print("\nAnalyst task")
    print("Approve only if the hash evidence and response scope justify containment.")
    return 0


def decide(args: argparse.Namespace) -> int:
    store = database(args.database)
    case = locate_case(store)
    if case["proposed_action"]["action"] != "quarantine_host_collect_file":
        raise RuntimeError("EX-10 expected a file-specific response proposal")
    approved = store.approve(case["id"], args.analyst, "approved", args.rationale)
    executed = store.execute(approved["id"], args.analyst)
    if executed["execution"]["action"] != "quarantine_host_collect_file":
        raise RuntimeError("EX-10 executed the wrong response action")
    closed = store.close(
        executed["id"],
        args.analyst,
        "Malicious file-hash containment simulated and evidence handling verified",
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
    print(f"Target hash:      {closed['execution']['target']}")
    print(f"Verification:     {closed['execution']['verification']}")
    print(f"Rollback:         {closed['execution']['rollback']}")
    print("\nVerified:")
    print("- SHA-256 observable was normalized and enriched")
    print("- File-specific response was proposed")
    print("- Evidence handling was documented before remediation")
    print("- Simulated execution required analyst approval")
    print("Audit trail:")
    for index, event in enumerate(closed["audit"], 1):
        print(f"  {index:02d}. {event['event_type']} - {event['actor']}")
    print(f"PASS: EX-10 completed for case {closed['id']}")
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
