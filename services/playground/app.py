"""Dependency-free local SOAR playground API and analyst dashboard."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


SEVERITY = {
    "INFORMATIONAL": "informational",
    "LOW": "low",
    "MEDIUM": "medium",
    "HIGH": "high",
    "CRITICAL": "critical",
}
MOCK_INTELLIGENCE = {
    "198.51.100.66": {
        "provider": "mock-virustotal",
        "verdict": "malicious",
        "reputation": -85,
        "last_analysis_stats": {"malicious": 18, "suspicious": 4, "harmless": 31},
    },
    "203.0.113.10": {
        "provider": "mock-virustotal",
        "verdict": "benign",
        "reputation": 12,
        "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 53},
    },
    "198.51.100.77": {
        "provider": "mock-virustotal",
        "verdict": "suspicious",
        "reputation": -5,
        "last_analysis_stats": {"malicious": 1, "suspicious": 2, "harmless": 50},
    },
    "192.0.2.44": {
        "provider": "mock-virustotal",
        "verdict": "unavailable",
        "status": "rate_limited",
        "reputation": None,
        "last_analysis_stats": None,
        "retry_after_seconds": 60,
        "error": "provider rate limit reached",
    },
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
        "provider": "mock-virustotal",
        "verdict": "malicious",
        "reputation": -92,
        "last_analysis_stats": {"malicious": 42, "suspicious": 5, "harmless": 9},
        "file_type": "Win32 EXE",
        "popular_threat_classification": "trojan",
        "names": ["invoice-review.exe", "payload.bin"],
    },
    "AKIAIOSFODNN7EXAMPLE": {
        "provider": "mock-aws-iam-analyzer",
        "verdict": "compromised",
        "risk_score": 95,
        "principal": "arn:aws:iam::589528729991:user/playground-build-user",
        "user_name": "playground-build-user",
        "access_key_status": "Active",
        "anomalies": [
            "first use from unrecognized ASN",
            "console login followed by access-key activity",
            "failed privilege-escalation API calls",
        ],
    },
    "i-0a1b2c3d4e5f67890": {
        "provider": "mock-aws-ec2-analyzer",
        "verdict": "exposed",
        "risk_score": 91,
        "instance_state": "running",
        "instance_profile": "playground-web-tier",
        "public_ip": "203.0.113.80",
        "subnet_id": "subnet-0a1b2c3d4e5f67890",
        "security_groups": ["sg-0123456789abcdef0"],
        "tags": {"Name": "playground-public-web", "Environment": "sandbox"},
        "exposure": [
            "SSH open to 0.0.0.0/0",
            "administrative port 8443 open to 0.0.0.0/0",
        ],
    },
    "burp-issue-sql-injection-checkout-api": {
        "provider": "mock-burp-suite-enterprise",
        "verdict": "critical",
        "risk_score": 98,
        "issue_type": "SQL injection",
        "application": "checkout-api",
        "affected_endpoint": "https://sandbox.shop.local/api/checkout",
        "affected_parameter": "coupon",
        "owner": "web-platform-team",
        "remediation_sla": "24 hours",
        "evidence": "Synthetic scanner evidence shows a time-based response differential.",
        "recommended_remediation": [
            "use parameterized queries",
            "validate server-side input",
            "add a regression test before deployment",
        ],
    },
}


class FindingValidationError(ValueError):
    """A safe validation failure that never includes attacker-controlled data."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def incident_key(source: str, source_id: str) -> str:
    return hashlib.sha256(f"{source}:{source_id}".encode()).hexdigest()


def normalize_securityhub(event: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(event, dict):
        raise FindingValidationError("EVENT_NOT_OBJECT", "event must be a JSON object")
    detail = event.get("detail")
    if not isinstance(detail, dict):
        raise FindingValidationError(
            "DETAIL_NOT_OBJECT", "event detail must be a JSON object"
        )
    findings = detail.get("findings")
    if not isinstance(findings, list) or not findings:
        raise FindingValidationError(
            "FINDINGS_NOT_ARRAY", "detail.findings must be a non-empty array"
        )
    if len(findings) > 100:
        raise FindingValidationError(
            "TOO_MANY_FINDINGS", "an event may contain at most 100 findings"
        )
    result = []
    for item in findings:
        if not isinstance(item, dict):
            raise FindingValidationError(
                "FINDING_NOT_OBJECT", "each finding must be a JSON object"
            )
        source_id = item.get("Id")
        if not isinstance(source_id, str) or not source_id.strip():
            raise FindingValidationError(
                "MISSING_FINDING_ID", "finding Id must be a non-empty string"
            )
        if len(source_id) > 512:
            raise FindingValidationError(
                "FINDING_ID_TOO_LONG", "finding Id exceeds 512 characters"
            )
        title = item.get("Title", "AWS security finding")
        if not isinstance(title, str) or not title.strip() or len(title) > 512:
            raise FindingValidationError(
                "INVALID_TITLE", "finding Title must contain 1 to 512 characters"
            )
        description = item.get("Description", "")
        if not isinstance(description, str) or len(description) > 10000:
            raise FindingValidationError(
                "DESCRIPTION_TOO_LONG",
                "finding Description must not exceed 10000 characters",
            )
        confidence = item.get("Confidence", 50)
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, int)
            or not 0 <= confidence <= 100
        ):
            raise FindingValidationError(
                "INVALID_CONFIDENCE", "finding Confidence must be an integer from 0 to 100"
            )
        resources = item.get("Resources", [])
        if not isinstance(resources, list) or len(resources) > 100:
            raise FindingValidationError(
                "INVALID_RESOURCES", "finding Resources must be an array of at most 100 items"
            )
        observables = []
        network = item.get("Network", {})
        if not isinstance(network, dict):
            raise FindingValidationError(
                "INVALID_NETWORK", "finding Network must be a JSON object"
            )
        source_ip = network.get("SourceIpV4")
        if source_ip:
            try:
                parsed_ip = ipaddress.ip_address(source_ip)
            except ValueError as exc:
                raise FindingValidationError(
                    "INVALID_SOURCE_IP", "Network.SourceIpV4 must be a valid IPv4 address"
                ) from exc
            if parsed_ip.version != 4:
                raise FindingValidationError(
                    "INVALID_SOURCE_IP", "Network.SourceIpV4 must be a valid IPv4 address"
                )
            observables.append({"type": "ip", "value": source_ip})
        supplied_observables = item.get("Observables", [])
        if not isinstance(supplied_observables, list) or len(supplied_observables) > 200:
            raise FindingValidationError(
                "INVALID_OBSERVABLES",
                "finding Observables must be an array of at most 200 items",
            )
        for observable in supplied_observables:
            if not isinstance(observable, dict):
                raise FindingValidationError(
                    "INVALID_OBSERVABLE", "each observable must be a JSON object"
                )
            if observable.get("Type") and observable.get("Value"):
                if not isinstance(observable["Type"], str) or not isinstance(observable["Value"], str):
                    raise FindingValidationError(
                        "INVALID_OBSERVABLE", "observable Type and Value must be strings"
                    )
                observable_type = observable["Type"].lower()
                observable_value = observable["Value"]
                if observable_type in {"sha256", "file_hash"}:
                    if not re.fullmatch(r"[A-Fa-f0-9]{64}", observable_value):
                        raise FindingValidationError(
                            "INVALID_SHA256", "sha256 observables must be 64 hex characters"
                        )
                    observable_type = "sha256"
                    observable_value = observable_value.lower()
                elif observable_type in {"aws_access_key", "access_key"}:
                    if not re.fullmatch(r"(A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}", observable_value):
                        raise FindingValidationError(
                            "INVALID_AWS_ACCESS_KEY",
                            "AWS access key observables must match the expected key ID shape",
                        )
                    observable_type = "aws_access_key"
                elif observable_type in {"aws_ec2_instance", "ec2_instance", "ec2_instance_id"}:
                    if not re.fullmatch(r"i-[a-f0-9]{8,17}", observable_value):
                        raise FindingValidationError(
                            "INVALID_EC2_INSTANCE_ID",
                            "EC2 instance observables must match the expected instance ID shape",
                        )
                    observable_type = "aws_ec2_instance"
                elif observable_type in {"burp_issue", "web_vulnerability"}:
                    if not re.fullmatch(r"burp-issue-[a-z0-9-]{3,120}", observable_value):
                        raise FindingValidationError(
                            "INVALID_BURP_ISSUE_ID",
                            "Burp issue observables must use a safe local issue identifier",
                        )
                    observable_type = "burp_issue"
                observables.append(
                    {"type": observable_type, "value": observable_value}
                )
        result.append(
            {
                "schema_version": "1.0",
                "incident_key": incident_key("aws-securityhub", source_id),
                "source": "aws-securityhub",
                "source_id": source_id,
                "title": title,
                "description": description,
                "severity": SEVERITY.get(
                    item.get("Severity", {}).get("Label", "INFORMATIONAL"),
                    "informational",
                ),
                "confidence": confidence,
                "observed_at": item.get("UpdatedAt", now()),
                "account_id": item.get("AwsAccountId"),
                "region": item.get("Region"),
                "resource_arns": [
                    resource["Id"][:2048]
                    for resource in resources
                    if isinstance(resource, dict)
                    and isinstance(resource.get("Id"), str)
                    and resource.get("Id")
                ][:100],
                "observables": observables[:200],
                "labels": ["aws", "securityhub", "playground"],
            }
        )
    return result


def enrich(observables: list[dict[str, str]]) -> list[dict[str, Any]]:
    enriched = []
    for observable in observables:
        base = {"type": observable["type"], "value": observable["value"], "checked_at": now()}
        intel = MOCK_INTELLIGENCE.get(
            observable["value"],
            {
                "provider": "mock-virustotal",
                "verdict": "unknown",
                "reputation": 0,
                "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 0},
            },
        )
        enriched.append({**base, **intel})
    return enriched


def enrichment_is_degraded(enrichment: list[dict[str, Any]]) -> bool:
    return any(item.get("verdict") == "unavailable" for item in enrichment)


def propose_response(actionable: dict[str, Any]) -> dict[str, Any]:
    if actionable["type"] == "burp_issue":
        return {
            "action": "route_web_vulnerability_remediation",
            "target": actionable.get("application", actionable["value"]),
            "mode": "simulation",
            "reason": "Mock Burp Suite analysis identified a critical web vulnerability",
            "rollback": (
                "Cancel or update the simulated remediation handoff before work begins; "
                "no application, WAF, or production configuration is changed automatically"
            ),
            "owner_routing": {
                "owner": actionable.get("owner"),
                "remediation_sla": actionable.get("remediation_sla"),
                "issue_type": actionable.get("issue_type"),
                "affected_endpoint": actionable.get("affected_endpoint"),
                "affected_parameter": actionable.get("affected_parameter"),
            },
            "automation_boundary": (
                "Create a simulated ownership handoff only. Application remediation "
                "requires developer review, testing, and change management."
            ),
        }
    if actionable["type"] == "aws_ec2_instance":
        return {
            "action": "quarantine_ec2_instance",
            "target": actionable["value"],
            "mode": "simulation",
            "reason": "Mock EC2 analysis identified internet-exposed administrative access",
            "rollback": (
                f"Restore security groups {', '.join(actionable.get('security_groups', []))} "
                f"to instance {actionable['value']} only after exposure review and owner approval"
            ),
            "containment_plan": {
                "method": "replace attached security groups with a no-ingress quarantine group",
                "preserve_instance": True,
                "preserve_volumes": True,
                "collect_before_change": ["security-group rules", "VPC flow logs", "instance metadata"],
            },
            "pre_change_state": {
                "instance_state": actionable.get("instance_state"),
                "public_ip": actionable.get("public_ip"),
                "subnet_id": actionable.get("subnet_id"),
                "security_groups": actionable.get("security_groups", []),
                "instance_profile": actionable.get("instance_profile"),
            },
        }
    if actionable["type"] == "aws_access_key":
        return {
            "action": "disable_iam_access_key",
            "target": actionable["value"],
            "mode": "simulation",
            "reason": "Mock IAM analysis classified the access key as compromised",
            "rollback": f"Restore access key {actionable['value']} to Active only after owner validation and credential rotation",
            "pre_change_state": {
                "access_key_status": actionable.get("access_key_status"),
                "principal": actionable.get("principal"),
                "user_name": actionable.get("user_name"),
            },
        }
    if actionable["type"] == "sha256":
        return {
            "action": "quarantine_host_collect_file",
            "target": actionable["value"],
            "mode": "simulation",
            "reason": "Mock intelligence classified the file hash as malicious",
            "rollback": "Release the host from quarantine after evidence review",
            "evidence_handling": "Preserve file path, hash, host ID, user, and timestamps before remediation",
        }
    return {
        "action": "block_ip",
        "target": actionable["value"],
        "mode": "simulation",
        "reason": f"Mock intelligence classified the observable as {actionable['verdict']}",
        "rollback": f"Remove temporary block for {actionable['value']}",
    }


def verification_message(action: dict[str, Any]) -> str:
    if action["action"] == "route_web_vulnerability_remediation":
        return (
            "Mock AppSec workflow reports the critical issue assigned to the web-platform-team "
            "with a 24-hour remediation SLA; no application change was automated"
        )
    if action["action"] == "quarantine_ec2_instance":
        return "Mock EC2 control reports the instance is attached to the no-ingress quarantine security group"
    if action["action"] == "disable_iam_access_key":
        return "Mock IAM control reports the access key status as Inactive"
    if action["action"] == "quarantine_host_collect_file":
        return "Mock endpoint control reports the host quarantine and evidence collection task as queued"
    return "Mock control reports the temporary block as active"


def rollback_verification_message(action: dict[str, Any]) -> str:
    if action["action"] == "quarantine_ec2_instance":
        return "Mock EC2 control reports the original security groups restored to the instance"
    if action["action"] == "disable_iam_access_key":
        return "Mock IAM control reports the access key restored to its recorded pre-change status"
    if action["action"] == "quarantine_host_collect_file":
        return "Mock endpoint control reports the host released from quarantine after evidence review"
    if action["action"] == "route_web_vulnerability_remediation":
        return "Mock AppSec workflow reports the simulated remediation handoff cancelled or updated"
    return "Mock control reports the temporary IP block removed"


def splunk_soar_handoff_available(finding: dict[str, Any]) -> bool:
    return "/splunk-soar-outage/" not in finding["source_id"]


class Store:
    def __init__(self, path: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.connection:
            self.connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS cases (
                    id TEXT PRIMARY KEY,
                    incident_key TEXT NOT NULL UNIQUE,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    source TEXT NOT NULL,
                    finding_json TEXT NOT NULL,
                    enrichment_json TEXT NOT NULL,
                    proposed_action_json TEXT,
                    approval_json TEXT,
                    execution_json TEXT,
                    rollback_json TEXT,
                    duplicate_count INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    detail_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS handoff_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL,
                    destination TEXT NOT NULL,
                    status TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS dead_letter_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT NOT NULL,
                    status TEXT NOT NULL,
                    error_code TEXT NOT NULL,
                    error_message TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    redrive_case_id TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )
            columns = {
                row["name"] for row in self.connection.execute("PRAGMA table_info(cases)")
            }
            if "rollback_json" not in columns:
                self.connection.execute("ALTER TABLE cases ADD COLUMN rollback_json TEXT")

    def audit(self, case_id: str, event_type: str, actor: str, detail: dict[str, Any]) -> None:
        self.connection.execute(
            "INSERT INTO audit_events(case_id,event_type,actor,detail_json,created_at) VALUES(?,?,?,?,?)",
            (case_id, event_type, actor, json.dumps(detail), now()),
        )

    def ingest(self, finding: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        with self.lock, self.connection:
            existing = self.connection.execute(
                "SELECT id FROM cases WHERE incident_key=?", (finding["incident_key"],)
            ).fetchone()
            if existing:
                self.connection.execute(
                    "UPDATE cases SET duplicate_count=duplicate_count+1,updated_at=? WHERE id=?",
                    (now(), existing["id"]),
                )
                self.audit(existing["id"], "duplicate_received", "system", {"source_id": finding["source_id"]})
                return self.get_case(existing["id"]), False

            case_id = str(uuid.uuid4())
            intelligence = enrich(finding.get("observables", []))
            actionable = next(
                (
                    item
                    for item in intelligence
                    if item["verdict"] in {
                        "malicious",
                        "suspicious",
                        "compromised",
                        "exposed",
                        "critical",
                    }
                ),
                None,
            )
            degraded = enrichment_is_degraded(intelligence)
            proposed = None
            status = "investigating"
            if actionable and not degraded:
                proposed = propose_response(actionable)
                status = "awaiting_approval"
            timestamp = now()
            self.connection.execute(
                """INSERT INTO cases(
                    id,incident_key,title,severity,status,source,finding_json,enrichment_json,
                    proposed_action_json,created_at,updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    case_id,
                    finding["incident_key"],
                    finding["title"],
                    finding["severity"],
                    status,
                    finding["source"],
                    json.dumps(finding),
                    json.dumps(intelligence),
                    json.dumps(proposed) if proposed else None,
                    timestamp,
                    timestamp,
                ),
            )
            self.audit(case_id, "case_created", "system", {"incident_key": finding["incident_key"]})
            enrichment_actor = (
                intelligence[0].get("provider", "mock-enrichment")
                if intelligence
                else "mock-enrichment"
            )
            if degraded:
                self.audit(
                    case_id,
                    "enrichment_degraded",
                    enrichment_actor,
                    {
                        "results": intelligence,
                        "handling": "case remains investigating until enrichment recovers or evidence is corroborated",
                    },
                )
            else:
                self.audit(case_id, "enrichment_completed", enrichment_actor, {"results": intelligence})
            if proposed:
                self.audit(case_id, "response_proposed", "policy-engine", proposed)
            self.sync_case_to_splunk_soar(case_id, finding)
            return self.get_case(case_id), True

    def sync_case_to_splunk_soar(self, case_id: str, finding: dict[str, Any]) -> None:
        if splunk_soar_handoff_available(finding):
            return
        timestamp = now()
        self.connection.execute(
            """INSERT INTO handoff_queue(
                case_id,destination,status,attempts,last_error,created_at,updated_at
            ) VALUES(?,?,?,?,?,?,?)""",
            (
                case_id,
                "mock-splunk-soar",
                "queued",
                1,
                "mock Splunk SOAR API unavailable",
                timestamp,
                timestamp,
            ),
        )
        self.audit(
            case_id,
            "splunk_soar_handoff_queued",
            "handoff-worker",
            {
                "destination": "mock-splunk-soar",
                "reason": "mock Splunk SOAR API unavailable",
                "next_step": "retry when downstream service recovers",
            },
        )

    def retry_splunk_soar_handoffs(self, actor: str) -> list[dict[str, Any]]:
        with self.lock, self.connection:
            queued = self.connection.execute(
                "SELECT * FROM handoff_queue WHERE destination=? AND status=? ORDER BY id",
                ("mock-splunk-soar", "queued"),
            ).fetchall()
            delivered = []
            for row in queued:
                timestamp = now()
                self.connection.execute(
                    """UPDATE handoff_queue
                    SET status='delivered',attempts=attempts+1,last_error=NULL,updated_at=?
                    WHERE id=?""",
                    (timestamp, row["id"]),
                )
                detail = {
                    "destination": row["destination"],
                    "previous_attempts": row["attempts"],
                    "status": "delivered",
                }
                self.audit(row["case_id"], "splunk_soar_handoff_delivered", actor, detail)
                delivered.append(self.get_case(row["case_id"]))
            return delivered

    def capture_dead_letter(
        self,
        source: str,
        payload: dict[str, Any],
        error_code: str,
        error_message: str,
    ) -> dict[str, Any]:
        timestamp = now()
        with self.lock, self.connection:
            cursor = self.connection.execute(
                """INSERT INTO dead_letter_events(
                    source,status,error_code,error_message,payload_json,created_at,updated_at
                ) VALUES(?,?,?,?,?,?,?)""",
                (
                    source,
                    "open",
                    error_code,
                    error_message,
                    json.dumps(payload),
                    timestamp,
                    timestamp,
                ),
            )
            return self.get_dead_letter_event(cursor.lastrowid)

    def list_dead_letter_events(self) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT id FROM dead_letter_events ORDER BY id"
        ).fetchall()
        return [self.get_dead_letter_event(row["id"]) for row in rows]

    def get_dead_letter_event(self, event_id: int) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM dead_letter_events WHERE id=?", (event_id,)
        ).fetchone()
        if not row:
            raise KeyError("dead-letter event not found")
        return {
            "id": row["id"],
            "source": row["source"],
            "status": row["status"],
            "error_code": row["error_code"],
            "error_message": row["error_message"],
            "payload": json.loads(row["payload_json"]),
            "redrive_case_id": row["redrive_case_id"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def redrive_dead_letter_event(
        self, event_id: int, corrected_payload: dict[str, Any], actor: str
    ) -> list[dict[str, Any]]:
        with self.lock, self.connection:
            event = self.get_dead_letter_event(event_id)
            if event["status"] != "open":
                raise ValueError(f"dead-letter event cannot be redriven from status {event['status']}")
            findings = normalize_securityhub(corrected_payload)
            cases = []
            for finding in findings:
                case, _created = self.ingest(finding)
                cases.append(case)
            case_id = cases[0]["id"] if cases else None
            timestamp = now()
            self.connection.execute(
                """UPDATE dead_letter_events
                SET status='redriven',payload_json=?,redrive_case_id=?,updated_at=?
                WHERE id=?""",
                (json.dumps(corrected_payload), case_id, timestamp, event_id),
            )
            for case in cases:
                self.audit(
                    case["id"],
                    "dead_letter_redriven",
                    actor,
                    {"dead_letter_id": event_id, "source": event["source"]},
                )
            return [self.get_case(case["id"]) for case in cases]

    def approve(self, case_id: str, actor: str, decision: str, note: str) -> dict[str, Any]:
        if decision not in {"approved", "rejected"}:
            raise ValueError("decision must be approved or rejected")
        with self.lock, self.connection:
            case = self.get_case(case_id)
            if not case["proposed_action"]:
                raise ValueError("case has no proposed action")
            if case["status"] not in {"awaiting_approval", "approved", "rejected"}:
                raise ValueError(f"case cannot be reviewed from status {case['status']}")
            approval = {"status": decision, "actor": actor, "note": note, "decided_at": now()}
            self.connection.execute(
                "UPDATE cases SET approval_json=?,status=?,updated_at=? WHERE id=?",
                (json.dumps(approval), decision, now(), case_id),
            )
            self.audit(case_id, f"response_{decision}", actor, approval)
            return self.get_case(case_id)

    def execute(self, case_id: str, actor: str) -> dict[str, Any]:
        with self.lock:
            case = self.get_case(case_id)
            if case["status"] != "approved" or not case["approval"]:
                with self.connection:
                    self.audit(
                        case_id,
                        "response_execution_denied",
                        actor,
                        {
                            "reason": "an approved analyst decision is required",
                            "case_status": case["status"],
                        },
                    )
                raise PermissionError("an approved analyst decision is required")
            action = case["proposed_action"]
            if action.get("mode") != "simulation":
                with self.connection:
                    self.audit(
                        case_id,
                        "response_execution_denied",
                        actor,
                        {
                            "reason": "local playground permits simulation only",
                            "case_status": case["status"],
                        },
                    )
                raise PermissionError("local playground permits simulation only")
            execution = {
                "status": "simulated",
                "action": action["action"],
                "target": action["target"],
                "executed_by": actor,
                "executed_at": now(),
                "verification": verification_message(action),
                "rollback": action["rollback"],
            }
            with self.connection:
                self.connection.execute(
                    "UPDATE cases SET execution_json=?,status='contained',updated_at=? WHERE id=?",
                    (json.dumps(execution), now(), case_id),
                )
                self.audit(case_id, "response_simulated", actor, execution)
                self.audit(case_id, "response_verified", "verification-engine", {"result": "pass"})
            return self.get_case(case_id)

    def rollback(self, case_id: str, actor: str, rationale: str) -> dict[str, Any]:
        if len(rationale.strip()) < 15:
            raise ValueError("rollback rationale must contain at least 15 characters")
        with self.lock, self.connection:
            case = self.get_case(case_id)
            if case["status"] != "contained" or not case["execution"]:
                raise ValueError("only a contained case with an executed response can be rolled back")
            if case["rollback"]:
                raise ValueError("case response has already been rolled back")
            action = case["proposed_action"]
            if action.get("mode") != "simulation":
                raise PermissionError("local playground permits simulation-only rollback")
            rollback = {
                "status": "simulated",
                "action": f"rollback_{action['action']}",
                "target": action["target"],
                "rolled_back_by": actor,
                "rolled_back_at": now(),
                "rationale": rationale,
                "instructions": action["rollback"],
                "verification": rollback_verification_message(action),
            }
            self.connection.execute(
                "UPDATE cases SET rollback_json=?,status='rolled_back',updated_at=? WHERE id=?",
                (json.dumps(rollback), now(), case_id),
            )
            self.audit(case_id, "response_rolled_back", actor, rollback)
            self.audit(
                case_id,
                "response_rollback_verified",
                "verification-engine",
                {"result": "pass", "verification": rollback["verification"]},
            )
            return self.get_case(case_id)

    def close(self, case_id: str, actor: str, resolution: str) -> dict[str, Any]:
        with self.lock, self.connection:
            case = self.get_case(case_id)
            if case["status"] not in {
                "contained",
                "rejected",
                "investigating",
                "awaiting_approval",
                "rolled_back",
            }:
                raise ValueError(f"case cannot be closed from status {case['status']}")
            self.connection.execute(
                "UPDATE cases SET status='closed',updated_at=? WHERE id=?", (now(), case_id)
            )
            self.audit(case_id, "case_closed", actor, {"resolution": resolution})
            return self.get_case(case_id)

    def disposition(
        self, case_id: str, actor: str, classification: str, rationale: str
    ) -> dict[str, Any]:
        allowed = {"true_positive", "false_positive", "benign_positive", "undetermined"}
        if classification not in allowed:
            raise ValueError(f"classification must be one of {sorted(allowed)}")
        if len(rationale.strip()) < 15:
            raise ValueError("disposition rationale must contain at least 15 characters")
        with self.lock, self.connection:
            case = self.get_case(case_id)
            if case["status"] not in {"investigating", "awaiting_approval"}:
                raise ValueError(
                    f"case cannot be classified from status {case['status']}"
                )
            self.audit(
                case_id,
                "case_dispositioned",
                actor,
                {"classification": classification, "rationale": rationale},
            )
            return self.get_case(case_id)

    def list_cases(self) -> list[dict[str, Any]]:
        rows = self.connection.execute("SELECT id FROM cases ORDER BY created_at DESC").fetchall()
        return [self.get_case(row["id"]) for row in rows]

    def get_case(self, case_id: str) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not row:
            raise KeyError("case not found")
        audits = self.connection.execute(
            "SELECT event_type,actor,detail_json,created_at FROM audit_events WHERE case_id=? ORDER BY id",
            (case_id,),
        ).fetchall()
        handoffs = self.connection.execute(
            """SELECT destination,status,attempts,last_error,created_at,updated_at
            FROM handoff_queue WHERE case_id=? ORDER BY id""",
            (case_id,),
        ).fetchall()
        return {
            "id": row["id"],
            "incident_key": row["incident_key"],
            "title": row["title"],
            "severity": row["severity"],
            "status": row["status"],
            "source": row["source"],
            "finding": json.loads(row["finding_json"]),
            "enrichment": json.loads(row["enrichment_json"]),
            "proposed_action": json.loads(row["proposed_action_json"]) if row["proposed_action_json"] else None,
            "approval": json.loads(row["approval_json"]) if row["approval_json"] else None,
            "execution": json.loads(row["execution_json"]) if row["execution_json"] else None,
            "rollback": json.loads(row["rollback_json"]) if row["rollback_json"] else None,
            "duplicate_count": row["duplicate_count"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "audit": [
                {"event_type": item["event_type"], "actor": item["actor"], "detail": json.loads(item["detail_json"]), "created_at": item["created_at"]}
                for item in audits
            ],
            "handoffs": [dict(item) for item in handoffs],
        }


HTML = """<!doctype html><html><head><meta charset='utf-8'><title>SOAR Playground</title>
<style>body{font-family:system-ui;background:#0b1220;color:#e5e7eb;margin:2rem}h1{color:#67e8f9}.card{background:#172033;padding:1rem;margin:1rem 0;border-radius:8px;border-left:4px solid #22d3ee}code{color:#fde68a}.status{font-weight:bold;color:#86efac}button{padding:.5rem;margin:.2rem}pre{white-space:pre-wrap}</style></head>
<body><h1>SOAR Playground</h1><p>Local, simulation-only security orchestration lab.</p><div id='cases'>Loading…</div>
<script>async function load(){let r=await fetch('/api/cases'),d=await r.json(),e=document.getElementById('cases');e.innerHTML=d.cases.length?'':'<p>No cases yet. Run the exercise script.</p>';for(let c of d.cases){let x=document.createElement('div');x.className='card';x.innerHTML=`<h2>${c.title}</h2><p>Status: <span class='status'>${c.status}</span> | Severity: ${c.severity}</p><p>Case: <code>${c.id}</code></p><p>Audit events: ${c.audit.length} | Duplicates: ${c.duplicate_count}</p><details><summary>Case evidence</summary><pre>${JSON.stringify(c,null,2)}</pre></details>`;e.appendChild(x)}}load();setInterval(load,5000)</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    store: Store

    def log_message(self, fmt: str, *args: Any) -> None:
        print(json.dumps({"event": "http_access", "message": fmt % args}))

    def send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 1_000_000:
            raise ValueError("request exceeds 1 MB")
        return json.loads(self.rfile.read(length) or b"{}")

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        try:
            if path == "/health":
                self.send_json(HTTPStatus.OK, {"status": "healthy", "mode": "simulation"})
            elif path == "/api/cases":
                self.send_json(HTTPStatus.OK, {"cases": self.store.list_cases()})
            elif match := re.fullmatch(r"/api/cases/([0-9a-f-]+)", path):
                self.send_json(HTTPStatus.OK, self.store.get_case(match.group(1)))
            elif path == "/":
                body = HTML.encode()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
        except KeyError as exc:
            self.send_json(HTTPStatus.NOT_FOUND, {"error": str(exc)})
        except Exception as exc:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        try:
            payload = self.body()
            if path == "/api/findings/securityhub":
                findings = normalize_securityhub(payload)
                if not findings:
                    raise ValueError("no Security Hub findings supplied")
                cases = []
                for finding in findings:
                    case, created = self.store.ingest(finding)
                    cases.append({"created": created, "case": case})
                self.send_json(HTTPStatus.CREATED, {"results": cases})
                return
            match = re.fullmatch(r"/api/cases/([0-9a-f-]+)/(approve|execute|close)", path)
            if not match:
                self.send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            case_id, action = match.groups()
            actor = str(payload.get("actor", "local-analyst"))[:128]
            if action == "approve":
                result = self.store.approve(case_id, actor, payload.get("decision", "approved"), str(payload.get("note", ""))[:1000])
            elif action == "execute":
                result = self.store.execute(case_id, actor)
            else:
                result = self.store.close(case_id, actor, str(payload.get("resolution", "Exercise completed"))[:1000])
            self.send_json(HTTPStatus.OK, result)
        except PermissionError as exc:
            self.send_json(HTTPStatus.FORBIDDEN, {"error": str(exc)})
        except KeyError as exc:
            self.send_json(HTTPStatus.NOT_FOUND, {"error": str(exc)})
        except (ValueError, json.JSONDecodeError) as exc:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except Exception as exc:
            print(json.dumps({"event": "request_error", "error": type(exc).__name__}))
            self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal error"})


def main() -> None:
    database = os.environ.get("DATABASE_PATH", "/data/soar.db")
    Handler.store = Store(database)
    server = ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), Handler)
    print(json.dumps({"event": "playground_started", "port": server.server_port, "mode": "simulation"}))
    server.serve_forever()


if __name__ == "__main__":
    main()
