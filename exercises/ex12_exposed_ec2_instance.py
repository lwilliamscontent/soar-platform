#!/usr/bin/env python3
"""EX-12: investigate an exposed EC2 instance and approve a safe quarantine plan."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_PATH = ROOT / "services" / "playground" / "app.py"
EVENT_PATH = ROOT / "exercises" / "exposed-ec2-instance-finding.json"
DEFAULT_DB = ROOT / "playground-data" / "exercises.db"
SPEC = importlib.util.spec_from_file_location("playground", APP_PATH)
playground = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(playground)


def database(path: str):
    return playground.Store(path)


def finding() -> dict:
    result = playground.normalize_securityhub(json.loads(EVENT_PATH.read_text()))
    if len(result) != 1:
        raise RuntimeError("EX-12 must contain exactly one finding")
    return result[0]


def locate_case(store) -> dict:
    key = finding()["incident_key"]
    matches = [case for case in store.list_cases() if case["incident_key"] == key]
    if not matches:
        raise RuntimeError("EX-12 case has not been prepared")
    return matches[0]


def prepare(args: argparse.Namespace) -> int:
    store = database(args.database)
    case, created = store.ingest(finding())
    intel = case["enrichment"][0]
    action = case["proposed_action"]
    print("EX-12 - Exposed EC2 Instance")
    print("=" * 29)
    print(f"Case ID:          {case['id']}")
    print(f"New case:         {'yes' if created else 'no'}")
    print(f"Status:           {case['status']}")
    print(f"Severity:         {case['severity']}")
    print(f"Confidence:       {case['finding']['confidence']}%")
    print(f"Instance:         {intel['value']}")
    print(f"State:            {intel['instance_state']}")
    print(f"Public IP:        {intel['public_ip']}")
    print(f"Instance profile: {intel['instance_profile']}")
    print(f"Proposed action:  {action['action']}")
    print(f"Rollback:         {action['rollback']}")
    print("\nExposure evidence")
    for exposure in intel["exposure"]:
        print(f"- {exposure}")
    print("\nContainment safeguards")
    print("- Replace security groups with a no-ingress quarantine group in simulation")
    print("- Preserve the running instance and attached volumes")
    print("- Collect security-group rules, VPC flow logs, and instance metadata first")
    print("- Require analyst approval before simulated isolation")
    print("\nAnalyst task")
    print("Approve only if the documented exposure justifies reversible isolation.")
    return 0


def decide(args: argparse.Namespace) -> int:
    store = database(args.database)
    case = locate_case(store)
    if case["proposed_action"]["action"] != "quarantine_ec2_instance":
        raise RuntimeError("EX-12 expected an EC2 quarantine response proposal")
    approved = store.approve(case["id"], args.analyst, "approved", args.rationale)
    executed = store.execute(approved["id"], args.analyst)
    if executed["execution"]["action"] != "quarantine_ec2_instance":
        raise RuntimeError("EX-12 executed the wrong response action")
    closed = store.close(
        executed["id"],
        args.analyst,
        "EC2 quarantine simulated with original security groups preserved for rollback",
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
    pre_change = closed["proposed_action"]["pre_change_state"]
    print(f"Approved by:      {args.analyst}")
    print(f"Case ID:          {closed['id']}")
    print(f"Final state:      {closed['status']}")
    print(f"Action:           {closed['execution']['action']}")
    print(f"Target instance:  {closed['execution']['target']}")
    print(f"Verification:     {closed['execution']['verification']}")
    print(f"Original groups:  {', '.join(pre_change['security_groups'])}")
    print(f"Rollback:         {closed['execution']['rollback']}")
    print("\nVerified:")
    print("- EC2 instance ID was validated and enriched with exposure context")
    print("- The simulated response isolates network access without terminating the instance")
    print("- Original network configuration is retained for rollback")
    print("- Simulated execution required analyst approval")
    print("Audit trail:")
    for index, event in enumerate(closed["audit"], 1):
        print(f"  {index:02d}. {event['event_type']} - {event['actor']}")
    print(f"PASS: EX-12 completed for case {closed['id']}")
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
