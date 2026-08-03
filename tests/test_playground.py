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


def test_rate_limited_enrichment_stays_investigating_without_response():
    with tempfile.TemporaryDirectory() as directory:
        store = playground.Store(str(Path(directory) / "test.db"))
        event = sample_event()
        finding = event["detail"]["findings"][0]
        finding["Id"] = "exercise-provider-rate-limit"
        finding["Network"] = {"SourceIpV4": "192.0.2.44"}
        case, created = store.ingest(playground.normalize_securityhub(event)[0])
        events = [event["event_type"] for event in case["audit"]]

        assert created is True
        assert case["status"] == "investigating"
        assert case["enrichment"][0]["verdict"] == "unavailable"
        assert case["enrichment"][0]["status"] == "rate_limited"
        assert case["proposed_action"] is None
        assert "enrichment_degraded" in events
        assert "enrichment_completed" not in events
        assert "response_proposed" not in events

        classified = store.disposition(
            case["id"],
            "analyst",
            "undetermined",
            "Provider rate limit prevents a containment decision until corroboration",
        )
        assert classified["execution"] is None
        closed = store.close(case["id"], "analyst", "provider retry required")
        final_events = [event["event_type"] for event in closed["audit"]]
        assert closed["status"] == "closed"
        assert "response_simulated" not in final_events


def test_splunk_soar_outage_queues_handoff_and_recovers():
    with tempfile.TemporaryDirectory() as directory:
        store = playground.Store(str(Path(directory) / "test.db"))
        event = sample_event()
        event["detail"]["findings"][0]["Id"] = "soar-playground/splunk-soar-outage/test"
        case, created = store.ingest(playground.normalize_securityhub(event)[0])
        events = [event["event_type"] for event in case["audit"]]

        assert created is True
        assert case["status"] == "awaiting_approval"
        assert case["proposed_action"]["action"] == "block_ip"
        assert len(case["handoffs"]) == 1
        assert case["handoffs"][0]["destination"] == "mock-splunk-soar"
        assert case["handoffs"][0]["status"] == "queued"
        assert case["handoffs"][0]["attempts"] == 1
        assert "splunk_soar_handoff_queued" in events
        assert "response_simulated" not in events

        approved = store.approve(
            case["id"],
            "analyst",
            "approved",
            "Malicious enrichment supports simulated containment",
        )
        executed = store.execute(approved["id"], "analyst")
        delivered = store.retry_splunk_soar_handoffs("handoff-recovery-worker")
        recovered = store.get_case(executed["id"])
        final_events = [event["event_type"] for event in recovered["audit"]]

        assert len(delivered) == 1
        assert recovered["handoffs"][0]["status"] == "delivered"
        assert recovered["handoffs"][0]["attempts"] == 2
        assert recovered["handoffs"][0]["last_error"] is None
        assert "response_simulated" in final_events
        assert "splunk_soar_handoff_delivered" in final_events


def test_dead_letter_event_can_be_inspected_and_redriven():
    with tempfile.TemporaryDirectory() as directory:
        store = playground.Store(str(Path(directory) / "test.db"))
        invalid = sample_event()
        del invalid["detail"]["findings"][0]["Id"]

        try:
            playground.normalize_securityhub(invalid)
            assert False, "invalid event should have failed validation"
        except playground.FindingValidationError as exc:
            dlq = store.capture_dead_letter(
                "aws-securityhub",
                invalid,
                exc.code,
                str(exc),
            )

        assert dlq["status"] == "open"
        assert dlq["error_code"] == "MISSING_FINDING_ID"
        assert store.list_cases() == []

        corrected = sample_event()
        corrected["detail"]["findings"][0]["Id"] = "exercise-dead-letter-redrive"
        cases = store.redrive_dead_letter_event(dlq["id"], corrected, "analyst")
        case = cases[0]
        refreshed = store.get_dead_letter_event(dlq["id"])
        events = [event["event_type"] for event in case["audit"]]

        assert len(cases) == 1
        assert refreshed["status"] == "redriven"
        assert refreshed["redrive_case_id"] == case["id"]
        assert case["status"] == "awaiting_approval"
        assert case["enrichment"][0]["verdict"] == "malicious"
        assert case["proposed_action"]["action"] == "block_ip"
        assert "dead_letter_redriven" in events
        assert "response_simulated" not in events


def test_malicious_sha256_gets_file_specific_response():
    with tempfile.TemporaryDirectory() as directory:
        store = playground.Store(str(Path(directory) / "test.db"))
        event = sample_event()
        finding = event["detail"]["findings"][0]
        finding["Id"] = "exercise-malicious-file-hash"
        finding.pop("Network")
        finding["Observables"] = [
            {
                "Type": "SHA256",
                "Value": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            }
        ]
        case, created = store.ingest(playground.normalize_securityhub(event)[0])

        assert created is True
        assert case["status"] == "awaiting_approval"
        assert case["enrichment"][0]["type"] == "sha256"
        assert case["enrichment"][0]["verdict"] == "malicious"
        assert case["enrichment"][0]["popular_threat_classification"] == "trojan"
        assert case["proposed_action"]["action"] == "quarantine_host_collect_file"
        assert case["proposed_action"]["target"] == (
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        )
        assert "evidence_handling" in case["proposed_action"]

        approved = store.approve(
            case["id"],
            "analyst",
            "approved",
            "Malicious hash evidence supports evidence-safe simulated containment",
        )
        executed = store.execute(approved["id"], "analyst")

        assert executed["execution"]["action"] == "quarantine_host_collect_file"
        assert "evidence collection" in executed["execution"]["verification"]
        assert executed["status"] == "contained"


def test_compromised_aws_access_key_gets_reversible_disable_response():
    with tempfile.TemporaryDirectory() as directory:
        store = playground.Store(str(Path(directory) / "test.db"))
        event = sample_event()
        finding = event["detail"]["findings"][0]
        finding["Id"] = "exercise-compromised-iam-access-key"
        finding["Severity"] = {"Label": "CRITICAL"}
        finding.pop("Network")
        finding["Observables"] = [
            {"Type": "AWS_ACCESS_KEY", "Value": "AKIAIOSFODNN7EXAMPLE"}
        ]
        case, created = store.ingest(playground.normalize_securityhub(event)[0])

        assert created is True
        assert case["status"] == "awaiting_approval"
        assert case["enrichment"][0]["type"] == "aws_access_key"
        assert case["enrichment"][0]["verdict"] == "compromised"
        assert case["enrichment"][0]["access_key_status"] == "Active"
        assert case["proposed_action"]["action"] == "disable_iam_access_key"
        assert case["proposed_action"]["target"] == "AKIAIOSFODNN7EXAMPLE"
        assert case["proposed_action"]["pre_change_state"]["access_key_status"] == "Active"
        assert "Restore access key" in case["proposed_action"]["rollback"]

        approved = store.approve(
            case["id"],
            "analyst",
            "approved",
            "Compromised key evidence supports reversible simulated disablement",
        )
        executed = store.execute(approved["id"], "analyst")

        assert executed["execution"]["action"] == "disable_iam_access_key"
        assert "Inactive" in executed["execution"]["verification"]
        assert executed["status"] == "contained"


def test_exposed_ec2_instance_gets_preserving_quarantine_plan():
    with tempfile.TemporaryDirectory() as directory:
        store = playground.Store(str(Path(directory) / "test.db"))
        event = sample_event()
        finding = event["detail"]["findings"][0]
        finding["Id"] = "exercise-exposed-ec2-instance"
        finding["Severity"] = {"Label": "CRITICAL"}
        finding.pop("Network")
        finding["Observables"] = [
            {"Type": "AWS_EC2_INSTANCE", "Value": "i-0a1b2c3d4e5f67890"}
        ]
        case, created = store.ingest(playground.normalize_securityhub(event)[0])

        assert created is True
        assert case["status"] == "awaiting_approval"
        assert case["enrichment"][0]["type"] == "aws_ec2_instance"
        assert case["enrichment"][0]["verdict"] == "exposed"
        assert case["enrichment"][0]["instance_state"] == "running"
        assert "SSH open to 0.0.0.0/0" in case["enrichment"][0]["exposure"]
        assert case["proposed_action"]["action"] == "quarantine_ec2_instance"
        assert case["proposed_action"]["target"] == "i-0a1b2c3d4e5f67890"
        assert case["proposed_action"]["containment_plan"]["preserve_instance"] is True
        assert case["proposed_action"]["pre_change_state"]["security_groups"] == [
            "sg-0123456789abcdef0"
        ]

        approved = store.approve(
            case["id"],
            "analyst",
            "approved",
            "Internet-exposed administrative access justifies reversible simulated isolation",
        )
        executed = store.execute(approved["id"], "analyst")

        assert executed["execution"]["action"] == "quarantine_ec2_instance"
        assert "no-ingress quarantine" in executed["execution"]["verification"]
        assert executed["status"] == "contained"


def test_critical_burp_issue_routes_to_owner_without_app_changes():
    with tempfile.TemporaryDirectory() as directory:
        store = playground.Store(str(Path(directory) / "test.db"))
        event = sample_event()
        finding = event["detail"]["findings"][0]
        finding["Id"] = "exercise-critical-burp-issue"
        finding["Severity"] = {"Label": "CRITICAL"}
        finding.pop("Network")
        finding["Observables"] = [
            {
                "Type": "BURP_ISSUE",
                "Value": "burp-issue-sql-injection-checkout-api",
            }
        ]
        case, created = store.ingest(playground.normalize_securityhub(event)[0])

        assert created is True
        assert case["status"] == "awaiting_approval"
        assert case["enrichment"][0]["type"] == "burp_issue"
        assert case["enrichment"][0]["issue_type"] == "SQL injection"
        assert case["enrichment"][0]["owner"] == "web-platform-team"
        assert case["proposed_action"]["action"] == "route_web_vulnerability_remediation"
        assert case["proposed_action"]["target"] == "checkout-api"
        assert case["proposed_action"]["owner_routing"]["remediation_sla"] == "24 hours"
        assert "developer review" in case["proposed_action"]["automation_boundary"].lower()

        approved = store.approve(
            case["id"],
            "analyst",
            "approved",
            "Critical scanner evidence warrants immediate accountable-team routing, not an untested application change",
        )
        executed = store.execute(approved["id"], "analyst")

        assert executed["execution"]["action"] == "route_web_vulnerability_remediation"
        assert "no application change was automated" in executed["execution"]["verification"]
        assert executed["status"] == "contained"


def test_approved_ip_block_can_be_rolled_back_and_closed():
    with tempfile.TemporaryDirectory() as directory:
        store = playground.Store(str(Path(directory) / "test.db"))
        event = sample_event()
        event["detail"]["findings"][0]["Id"] = "exercise-approved-response-rollback"
        case, _ = store.ingest(playground.normalize_securityhub(event)[0])
        approved = store.approve(
            case["id"],
            "analyst",
            "approved",
            "Malicious IP evidence supports temporary containment before recovery validation",
        )
        contained = store.execute(approved["id"], "analyst")
        rolled_back = store.rollback(
            contained["id"],
            "analyst",
            "Containment validation is complete and normal communication can be restored",
        )

        assert rolled_back["status"] == "rolled_back"
        assert rolled_back["execution"]["action"] == "block_ip"
        assert rolled_back["rollback"]["action"] == "rollback_block_ip"
        assert rolled_back["rollback"]["target"] == "198.51.100.66"
        assert "block removed" in rolled_back["rollback"]["verification"]
        events = [event["event_type"] for event in rolled_back["audit"]]
        assert events[-2:] == ["response_rolled_back", "response_rollback_verified"]

        closed = store.close(rolled_back["id"], "analyst", "rollback verified")
        assert closed["status"] == "closed"
