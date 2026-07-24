import importlib.util
import copy
import tempfile
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "services" / "playground" / "app.py"
SPEC = importlib.util.spec_from_file_location("playground", MODULE_PATH)
playground = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(playground)


def sample_event():
    return {
        "detail": {
            "findings": [
                {
                    "Id": "exercise-1",
                    "Title": "Suspicious IP",
                    "Severity": {"Label": "HIGH"},
                    "Confidence": 90,
                    "UpdatedAt": "2026-07-20T12:00:00Z",
                    "Network": {"SourceIpV4": "198.51.100.66"},
                    "Resources": [],
                }
            ]
        }
    }


def test_complete_simulated_workflow():
    with tempfile.TemporaryDirectory() as directory:
        store = playground.Store(str(Path(directory) / "test.db"))
        finding = playground.normalize_securityhub(sample_event())[0]
        case, created = store.ingest(finding)
        assert created is True
        assert case["status"] == "awaiting_approval"
        assert case["enrichment"][0]["verdict"] == "malicious"

        duplicate, created = store.ingest(finding)
        assert created is False
        assert duplicate["duplicate_count"] == 1

        approved = store.approve(case["id"], "analyst", "approved", "reviewed")
        assert approved["status"] == "approved"

        executed = store.execute(case["id"], "analyst")
        assert executed["status"] == "contained"
        assert executed["execution"]["status"] == "simulated"

        closed = store.close(case["id"], "analyst", "exercise complete")
        assert closed["status"] == "closed"
        assert [event["event_type"] for event in closed["audit"]] == [
            "case_created",
            "enrichment_completed",
            "response_proposed",
            "duplicate_received",
            "response_approved",
            "response_simulated",
            "response_verified",
            "case_closed",
        ]


def test_execution_requires_approval():
    with tempfile.TemporaryDirectory() as directory:
        store = playground.Store(str(Path(directory) / "test.db"))
        case, _ = store.ingest(playground.normalize_securityhub(sample_event())[0])
        try:
            store.execute(case["id"], "analyst")
            assert False, "execute should have failed"
        except PermissionError:
            pass
        denied = store.get_case(case["id"])
        assert denied["execution"] is None
        assert denied["status"] == "awaiting_approval"
        assert denied["audit"][-1]["event_type"] == "response_execution_denied"


def test_rejected_response_cannot_execute():
    with tempfile.TemporaryDirectory() as directory:
        store = playground.Store(str(Path(directory) / "test.db"))
        event = sample_event()
        event["detail"]["findings"][0]["Id"] = "exercise-rejection"
        case, _ = store.ingest(playground.normalize_securityhub(event)[0])
        rejected = store.approve(
            case["id"],
            "analyst",
            "rejected",
            "Evidence is insufficient for containment",
        )
        assert rejected["status"] == "rejected"
        try:
            store.execute(case["id"], "analyst")
            assert False, "rejected response should not execute"
        except PermissionError:
            pass
        closed = store.close(case["id"], "analyst", "further investigation required")
        events = [event["event_type"] for event in closed["audit"]]
        assert "response_rejected" in events
        assert "response_execution_denied" in events
        assert "response_simulated" not in events


def test_benign_observable_closes_without_response():
    with tempfile.TemporaryDirectory() as directory:
        store = playground.Store(str(Path(directory) / "test.db"))
        event = sample_event()
        finding = event["detail"]["findings"][0]
        finding["Id"] = "exercise-benign"
        finding["Severity"] = {"Label": "LOW"}
        finding["Confidence"] = 25
        finding["Network"] = {"SourceIpV4": "203.0.113.10"}
        case, _ = store.ingest(playground.normalize_securityhub(event)[0])
        assert case["status"] == "investigating"
        assert case["enrichment"][0]["verdict"] == "benign"
        assert case["proposed_action"] is None
        classified = store.disposition(
            case["id"],
            "analyst",
            "false_positive",
            "All enrichment results are harmless and no activity corroborates the alert",
        )
        assert classified["audit"][-1]["event_type"] == "case_dispositioned"
        closed = store.close(case["id"], "analyst", "false positive")
        events = [event["event_type"] for event in closed["audit"]]
        assert closed["status"] == "closed"
        assert closed["execution"] is None
        assert "response_proposed" not in events
        assert "response_simulated" not in events


def test_repeated_alerts_correlate_to_one_case():
    with tempfile.TemporaryDirectory() as directory:
        store = playground.Store(str(Path(directory) / "test.db"))
        event = sample_event()
        event["detail"]["findings"][0]["Id"] = "exercise-duplicate"
        finding = playground.normalize_securityhub(event)[0]
        results = [store.ingest(finding) for _ in range(4)]
        case_ids = [case["id"] for case, _created in results]
        creation_results = [created for _case, created in results]
        case = store.get_case(case_ids[0])
        events = [event["event_type"] for event in case["audit"]]
        assert len(set(case_ids)) == 1
        assert creation_results == [True, False, False, False]
        assert case["duplicate_count"] == 3
        assert events.count("case_created") == 1
        assert events.count("enrichment_completed") == 1
        assert events.count("response_proposed") == 1
        assert events.count("duplicate_received") == 3
        assert case["execution"] is None


def test_malformed_findings_are_rejected_before_case_creation():
    with tempfile.TemporaryDirectory() as directory:
        store = playground.Store(str(Path(directory) / "test.db"))
        base = sample_event()
        scenarios = []

        missing_id = copy.deepcopy(base)
        del missing_id["detail"]["findings"][0]["Id"]
        scenarios.append((missing_id, "MISSING_FINDING_ID"))

        invalid_confidence = copy.deepcopy(base)
        invalid_confidence["detail"]["findings"][0]["Confidence"] = 145
        scenarios.append((invalid_confidence, "INVALID_CONFIDENCE"))

        invalid_structure = copy.deepcopy(base)
        invalid_structure["detail"]["findings"] = {"Id": "not-an-array"}
        scenarios.append((invalid_structure, "FINDINGS_NOT_ARRAY"))

        oversized = copy.deepcopy(base)
        oversized["detail"]["findings"][0]["Description"] = "X" * 10001
        scenarios.append((oversized, "DESCRIPTION_TOO_LONG"))

        observed = []
        for event, expected_code in scenarios:
            try:
                playground.normalize_securityhub(event)
                assert False, f"scenario should have failed with {expected_code}"
            except playground.FindingValidationError as exc:
                observed.append(exc.code)
                assert exc.code == expected_code

        assert observed == [
            "MISSING_FINDING_ID",
            "INVALID_CONFIDENCE",
            "FINDINGS_NOT_ARRAY",
            "DESCRIPTION_TOO_LONG",
        ]
        assert store.list_cases() == []
