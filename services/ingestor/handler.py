"""Normalize security findings and create/update a Splunk SOAR container."""

from __future__ import annotations

import hashlib
import json
import os
import urllib.request
from datetime import datetime, timezone
from typing import Any


SEVERITY_MAP = {
    "INFORMATIONAL": "informational",
    "LOW": "low",
    "MEDIUM": "medium",
    "HIGH": "high",
    "CRITICAL": "critical",
}


def _incident_key(source: str, source_id: str) -> str:
    return hashlib.sha256(f"{source}:{source_id}".encode()).hexdigest()


def normalize_securityhub(event: dict[str, Any]) -> list[dict[str, Any]]:
    findings = event.get("detail", {}).get("findings", [])
    normalized = []
    for finding in findings:
        source_id = finding["Id"]
        resources = finding.get("Resources", [])
        normalized.append(
            {
                "schema_version": "1.0",
                "incident_key": _incident_key("aws-securityhub", source_id),
                "source": "aws-securityhub",
                "source_id": source_id,
                "title": finding.get("Title", "AWS security finding")[:512],
                "description": finding.get("Description", "")[:10000],
                "severity": SEVERITY_MAP.get(
                    finding.get("Severity", {}).get("Label", "INFORMATIONAL"),
                    "informational",
                ),
                "confidence": int(finding.get("Confidence", 50)),
                "observed_at": finding.get(
                    "UpdatedAt", datetime.now(timezone.utc).isoformat()
                ),
                "account_id": finding.get("AwsAccountId"),
                "region": finding.get("Region"),
                "resource_arns": [
                    r["Id"][:2048] for r in resources if r.get("Id")
                ][:100],
                "observables": [],
                "labels": ["aws", "securityhub"],
            }
        )
    return normalized


def _secret(secret_id: str) -> dict[str, Any]:
    import boto3

    value = boto3.client("secretsmanager").get_secret_value(SecretId=secret_id)
    return json.loads(value["SecretString"])


def send_to_soar(finding: dict[str, Any]) -> dict[str, Any]:
    config = _secret(os.environ["SOAR_SECRET_ARN"])
    payload = {
        "name": finding["title"],
        "label": "aws_security_finding",
        "severity": finding["severity"],
        "source_data_identifier": finding["incident_key"],
        "description": finding.get("description", ""),
        "custom_fields": {"canonical_finding": json.dumps(finding)},
    }
    request = urllib.request.Request(
        f"{config['server'].rstrip('/')}/rest/container",
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "ph-auth-token": config["ph-auth-token"],
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read())


def lambda_handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    records = event.get("Records", [])
    processed = 0
    failures = []
    for record in records:
        try:
            body = json.loads(record["body"])
            for finding in normalize_securityhub(body):
                if os.environ.get("DISPATCH_MODE", "log") == "soar":
                    send_to_soar(finding)
                else:
                    print(json.dumps({"event": "normalized_finding", **finding}))
                processed += 1
        except Exception as exc:  # Lambda partial batch failure contract
            print(json.dumps({"event": "processing_error", "error": type(exc).__name__}))
            failures.append({"itemIdentifier": record.get("messageId", "unknown")})
    return {"processed": processed, "batchItemFailures": failures}
