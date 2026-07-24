#!/usr/bin/env python3
"""EX-06: reject malformed findings before any case or action is created."""

from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_PATH = ROOT / "services" / "playground" / "app.py"
BASE_EVENT_PATH = ROOT / "exercises" / "benign-observable-finding.json"
DEFAULT_DB = ROOT / "playground-data" / "exercises.db"
SPEC = importlib.util.spec_from_file_location("playground", APP_PATH)
playground = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(playground)


def scenarios() -> list[tuple[str, dict, str]]:
    base = json.loads(BASE_EVENT_PATH.read_text())

    missing_id = copy.deepcopy(base)
    del missing_id["detail"]["findings"][0]["Id"]

    invalid_confidence = copy.deepcopy(base)
    invalid_confidence["detail"]["findings"][0]["Id"] = "ex06-invalid-confidence"
    invalid_confidence["detail"]["findings"][0]["Confidence"] = 145

    invalid_structure = copy.deepcopy(base)
    invalid_structure["detail"]["findings"] = {
        "Id": "ex06-findings-is-an-object-not-an-array"
    }

    oversized_description = copy.deepcopy(base)
    oversized_description["detail"]["findings"][0]["Id"] = "ex06-oversized-description"
    oversized_description["detail"]["findings"][0]["Description"] = "X" * 10001

    return [
        ("missing finding ID", missing_id, "MISSING_FINDING_ID"),
        ("confidence above 100", invalid_confidence, "INVALID_CONFIDENCE"),
        ("findings is not an array", invalid_structure, "FINDINGS_NOT_ARRAY"),
        ("description exceeds limit", oversized_description, "DESCRIPTION_TOO_LONG"),
    ]


def run(database_path: str) -> int:
    store = playground.Store(database_path)
    before = len(store.list_cases())
    print("EX-06 — Malformed Finding Validation")
    print("=" * 38)
    passed = 0
    observed_codes = []
    for name, event, expected_code in scenarios():
        try:
            normalized = playground.normalize_securityhub(event)
            for finding in normalized:
                store.ingest(finding)
            print(f"FAIL: {name} was accepted")
        except playground.FindingValidationError as exc:
            observed_codes.append(exc.code)
            if exc.code == expected_code:
                passed += 1
                print(f"PASS: {name} → {exc.code}: {exc}")
            else:
                print(
                    f"FAIL: {name} returned {exc.code}; expected {expected_code}"
                )

    after_cases = store.list_cases()
    created_during_test = len(after_cases) - before
    print("\nSafety verification")
    print(f"- Cases before: {before}")
    print(f"- Cases after:  {len(after_cases)}")
    print(f"- Cases created by malformed events: {created_during_test}")
    print(f"- Sanitized error codes: {', '.join(observed_codes)}")

    if passed != len(scenarios()):
        raise RuntimeError(f"only {passed} of {len(scenarios())} scenarios passed")
    if created_during_test != 0:
        raise RuntimeError("malformed events created one or more partial cases")
    print("- No enrichments, proposals, or responses could run because validation failed first")
    print("PASS: EX-06 completed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", default=str(DEFAULT_DB))
    args = parser.parse_args()
    return run(args.database)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
