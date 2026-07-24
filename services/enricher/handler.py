"""VirusTotal API v3 indicator enrichment with safe hash-first defaults."""

from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from typing import Any


PATHS = {
    "sha256": "files",
    "sha1": "files",
    "md5": "files",
    "ip": "ip_addresses",
    "domain": "domains",
    "url": "urls",
}


def _api_key() -> str:
    import boto3

    secret = boto3.client("secretsmanager").get_secret_value(
        SecretId=os.environ["VT_SECRET_ARN"]
    )
    return json.loads(secret["SecretString"])["api_key"]


def _identifier(kind: str, value: str) -> str:
    if kind == "url":
        import base64

        return base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
    return urllib.parse.quote(value, safe="")


def lookup(kind: str, value: str) -> dict[str, Any]:
    if kind not in PATHS:
        return {"status": "unsupported", "type": kind}
    request = urllib.request.Request(
        f"https://www.virustotal.com/api/v3/{PATHS[kind]}/{_identifier(kind, value)}",
        headers={"x-apikey": _api_key(), "Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        result = json.loads(response.read())
    attrs = result.get("data", {}).get("attributes", {})
    return {
        "status": "ok",
        "type": kind,
        "value": value,
        "reputation": attrs.get("reputation"),
        "last_analysis_stats": attrs.get("last_analysis_stats", {}),
        "last_analysis_date": attrs.get("last_analysis_date"),
    }


def lambda_handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    return lookup(event["type"], event["value"])
