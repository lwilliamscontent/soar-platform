#!/usr/bin/env python3
"""EX-08: queue and recover a Splunk SOAR handoff during an outage."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_PATH = ROOT / "services" / "playground" / "app.py"
EVENT_PATH = ROOT / "exercises" / "splunk-soar-outage-finding.json"
DEFAULT_DB = ROOT / "playground-data" / "exercises.db"
SPEC = importlib.util.spec_from_file_location("playground", APP_PATH)
playground = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(playground)


def database(path: str):
    return playground.Store(path)


def finding() -> dict:
    result = playground.normalize_securityhub(json.loads(EVENT_PATH.read_text()))
    if len(result) != 1:
        raise RuntimeError("EX-08 must contain exactly one finding")
    return result[0]


def locate_case(store) -> dict:
    key = finding()["incident_key"]
    matches = [case for case in store.list_cases() if case["incident_key"] == key]
    if not matches:
        raise RuntimeError("EX-08 case has not been prepared")
    return matches[0]


def prepare(args: argparse.Namespace) -> int:
    store = database(args.database)
    case, created = store.ingest(finding())
    intel = case["enrichment"][0]
    events = [event["event_type"] for event in case["audit"]]
    if "splunk_soar_handoff_queued" not in events:
        raise RuntimeError("Splunk SOAR outage did not queue a handoff")
    print("EX-08 - Splunk SOAR Outage")
    print("=" * 29)
    print(f"Case ID:          {case['id']}")
    print(f"New case:         {'yes' if created else 'no'}")
    print(f"Status:           {case['status']}")
    print(f"Severity:         {case['severity']}")
    print(f"Confidence:       {case['finding']['confidence']}%")
    print(f"Observable:       {intel['type']} {intel['value']}")
    print(f"Intel verdict:    {intel['verdict']}")
    print(f"Proposed action:  {case['proposed_action']['action']}")
    print(f"Handoff status:   {case['handoffs'][0]['status']}")
    print(f"Handoff attempts: {case['handoffs'][0]['attempts']}")
    print("\nContext")
    print("- Local intake, enrichment, and response proposal still worked")
    print("- The downstream Splunk SOAR handoff failed")
    print("- The case was not dropped and the failed handoff was queued")
    print("- Analyst approval is still required before containment")
    print("\nAnalyst task")
    print("Approve the simulated containment when the evidence supports it,")
    print("then recover the queued Splunk SOAR handoff.")
    return 0


def recover(args: argparse.Namespace) -> int:
    store = database(args.database)
    case = locate_case(store)
    if not case["handoffs"] or case["handoffs"][0]["status"] != "queued":
        raise RuntimeError("EX-08 requires one queued handoff before recovery")
    if case["status"] == "awaiting_approval":
        case = store.approve(case["id"], args.analyst, "approved", args.rationale)
    if case["status"] == "approved":
        case = store.execute(case["id"], args.analyst)
    delivered = store.retry_splunk_soar_handoffs("handoff-recovery-worker")
    if not delivered:
        raise RuntimeError("queued handoff was not delivered")
    recovered = store.get_case(case["id"])
    if recovered["handoffs"][0]["status"] != "delivered":
        raise RuntimeError("handoff recovery did not mark the item delivered")
    closed = store.close(
        recovered["id"],
        args.analyst,
        "Splunk SOAR handoff recovered and simulated containment verified",
    )
    events = [event["event_type"] for event in closed["audit"]]
    required = {
        "case_created",
        "enrichment_completed",
        "response_proposed",
        "splunk_soar_handoff_queued",
        "response_approved",
        "response_simulated",
        "response_verified",
        "splunk_soar_handoff_delivered",
        "case_closed",
    }
    missing = sorted(required - set(events))
    if missing:
        raise RuntimeError(f"missing audit events: {', '.join(missing)}")
    print(f"Approved and recovered by: {args.analyst}")
    print("Verified:")
    print("- Local case was preserved during the Splunk SOAR outage")
    print("- Handoff queue retained the failed downstream sync")
    print("- Queued handoff was delivered after recovery")
    print("- Simulated containment still required analyst approval")
    print(f"- Case state is {closed['status']}")
    print("Audit trail:")
    for index, event in enumerate(closed["audit"], 1):
        print(f"  {index:02d}. {event['event_type']} - {event['actor']}")
    print(f"PASS: EX-08 completed for case {closed['id']}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", default=str(DEFAULT_DB))
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("prepare")
    recovery = commands.add_parser("recover")
    recovery.add_argument("--analyst", required=True)
    recovery.add_argument("--rationale", required=True)
    args = parser.parse_args()
    return prepare(args) if args.command == "prepare" else recover(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
