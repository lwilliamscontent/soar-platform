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
                observables.append(
                    {"type": observable["Type"].lower(), "value": observable["Value"]}
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


class Store:
    def __init__(self, path: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.lock = threading.Lock()
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
                """
            )

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
                (item for item in intelligence if item["verdict"] in {"malicious", "suspicious"}),
                None,
            )
            proposed = None
            status = "investigating"
            if actionable:
                proposed = {
                    "action": "block_ip",
                    "target": actionable["value"],
                    "mode": "simulation",
                    "reason": f"Mock intelligence classified the observable as {actionable['verdict']}",
                    "rollback": f"Remove temporary block for {actionable['value']}",
                }
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
            self.audit(case_id, "enrichment_completed", "mock-virustotal", {"results": intelligence})
            if proposed:
                self.audit(case_id, "response_proposed", "policy-engine", proposed)
            return self.get_case(case_id), True

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
                "verification": "Mock control reports the temporary block as active",
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

    def close(self, case_id: str, actor: str, resolution: str) -> dict[str, Any]:
        with self.lock, self.connection:
            case = self.get_case(case_id)
            if case["status"] not in {
                "contained",
                "rejected",
                "investigating",
                "awaiting_approval",
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
            "duplicate_count": row["duplicate_count"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "audit": [
                {"event_type": item["event_type"], "actor": item["actor"], "detail": json.loads(item["detail_json"]), "created_at": item["created_at"]}
                for item in audits
            ],
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
