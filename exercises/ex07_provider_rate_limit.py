#!/usr/bin/env python3
"""EX-07: handle VirusTotal timeout or rate-limit degraded mode safely."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_PATH = ROOT / "services" / "playground" / "app.py"
EVENT_PATH = ROOT / "exercises" / "provider-rate-limit-finding.json"
DEFAULT_DB = ROOT / "playground-data" / "exercises.db"
SPEC = importlib.util.spec_from_file_location("playground", APP_PATH)
playground = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(playground)


def database(path: str):
    return playground.Store(path)


def finding() -> dict:
    result = playground.normalize_securityhub(json.loads(EVENT_PATH.read_text()))
    if len(result) != 1:
        raise RuntimeError("EX-07 must contain exactly one finding")
    return result[0]


def locate_case(store) -> dict:
    key = finding()["incident_key"]
    matches = [case for case in store.list_cases() if case["incident_key"] == key]
    if not matches:
        raise RuntimeError("EX-07 case has not been prepared")
    return matches[0]


def prepare(args: argparse.Namespace) -> int:
    store = database(args.database)
    case, created = store.ingest(finding())
    intel = case["enrichment"][0]
    print("EX-07 - VirusTotal Timeout or Rate Limit")
    print("=" * 42)
    print(f"Case ID:          {case['id']}")
    print(f"New case:         {'yes' if created else 'no'}")
    print(f"Status:           {case['status']}")
    print(f"Severity:         {case['severity']}")
    print(f"Confidence:       {case['finding']['confidence']}%")
    print(f"Observable:       {intel['type']} {intel['value']}")
    print(f"Intel provider:   {intel['provider']}")
    print(f"Intel verdict:    {intel['verdict']}")
    print(f"Provider status:  {intel['status']}")
    print(f"Retry after:      {intel['retry_after_seconds']} seconds")
    print(f"Proposed action:  {case['proposed_action']}")
    print("\nContext")
    print("- The alert has enough source severity and confidence to investigate")
    print("- Threat intelligence is unavailable because the provider is rate limited")
    print("- Missing enrichment is not proof that the observable is harmless")
    print("- The platform must not propose containment without usable evidence")
    print("\nAnalyst task")
    print("Classify the case as undetermined and document follow-up actions,")
    print("such as retrying enrichment later or checking internal logs for corroboration.")
    return 0


def decide(args: argparse.Namespace) -> int:
    store = database(args.database)
    case = locate_case(store)
    events = [event["event_type"] for event in case["audit"]]
    if case["proposed_action"] is not None:
        raise RuntimeError("rate-limited enrichment unexpectedly produced a response")
    if "enrichment_degraded" not in events:
        raise RuntimeError("case does not contain degraded-enrichment audit evidence")
    classified = store.disposition(
        case["id"],
        args.analyst,
        "undetermined",
        args.rationale,
    )
    if classified["execution"] is not None:
        raise RuntimeError("response execution exists on degraded-enrichment case")
    closed = store.close(
        case["id"],
        args.analyst,
        f"undetermined: {args.rationale}",
    )
    final_events = [event["event_type"] for event in closed["audit"]]
    if "response_proposed" in final_events or "response_simulated" in final_events:
        raise RuntimeError("degraded-enrichment case contains response activity")
    print(f"Disposition recorded: undetermined by {args.analyst}")
    print("Verified:")
    print("- Enrichment outage was audited")
    print("- No containment was proposed")
    print("- No response was executed")
    print("- Follow-up rationale was audited")
    print(f"- Case state is {closed['status']}")
    print("Audit trail:")
    for index, event in enumerate(closed["audit"], 1):
        print(f"  {index:02d}. {event['event_type']} - {event['actor']}")
    print(f"PASS: EX-07 completed for case {closed['id']}")
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
