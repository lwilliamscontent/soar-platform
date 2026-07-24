#!/usr/bin/env python3
"""EX-05: submit repeated alerts and verify idempotent case correlation."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_PATH = ROOT / "services" / "playground" / "app.py"
EVENT_PATH = ROOT / "exercises" / "duplicate-alert-finding.json"
DEFAULT_DB = ROOT / "playground-data" / "exercises.db"
SPEC = importlib.util.spec_from_file_location("playground", APP_PATH)
playground = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(playground)


def run(database_path: str, submissions: int) -> int:
    if submissions < 2:
        raise ValueError("EX-05 requires at least two submissions")
    store = playground.Store(database_path)
    findings = playground.normalize_securityhub(json.loads(EVENT_PATH.read_text()))
    if len(findings) != 1:
        raise RuntimeError("EX-05 must contain exactly one finding")
    finding = findings[0]

    print("EX-05 — Duplicate Alert Handling")
    print("=" * 34)
    case_ids = []
    creation_results = []
    for number in range(1, submissions + 1):
        case, created = store.ingest(finding)
        case_ids.append(case["id"])
        creation_results.append(created)
        print(
            f"Submission {number}: case={case['id']} "
            f"created={str(created).lower()} duplicates={case['duplicate_count']}"
        )

    case = store.get_case(case_ids[0])
    events = [event["event_type"] for event in case["audit"]]
    expected_duplicates = submissions - 1
    checks = {
        "all submissions correlated to one case": len(set(case_ids)) == 1,
        "only the first submission created a case": creation_results
        == [True] + [False] * expected_duplicates,
        "duplicate counter is correct": case["duplicate_count"]
        == expected_duplicates,
        "case creation occurred once": events.count("case_created") == 1,
        "enrichment occurred once": events.count("enrichment_completed") == 1,
        "response proposal occurred once": events.count("response_proposed") == 1,
        "every repeat was audited": events.count("duplicate_received")
        == expected_duplicates,
        "no response executed": case["execution"] is None
        and "response_simulated" not in events,
    }
    print("\nVerification")
    for description, passed in checks.items():
        print(f"- {'PASS' if passed else 'FAIL'}: {description}")
    if not all(checks.values()):
        raise RuntimeError("one or more duplicate-handling controls failed")

    closed = store.close(
        case["id"],
        "correlation-test-analyst",
        f"Duplicate-correlation control validated with {submissions} submissions",
    )
    print(f"\nFinal state: {closed['status']}")
    print("Audit trail:")
    for index, event in enumerate(closed["audit"], 1):
        print(f"  {index:02d}. {event['event_type']} — {event['actor']}")
    print(f"PASS: EX-05 completed for case {closed['id']}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", default=str(DEFAULT_DB))
    parser.add_argument("--submissions", type=int, default=4)
    args = parser.parse_args()
    return run(args.database, args.submissions)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
