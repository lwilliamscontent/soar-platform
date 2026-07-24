"""Narrow, approval-gated AWS response actions."""

from __future__ import annotations

import os
from typing import Any


ALLOWED_ACTIONS = {"disable_access_key", "quarantine_instance"}


def _authorize(event: dict[str, Any]) -> None:
    if os.environ.get("RESPONSE_MODE", "disabled") != "enabled":
        raise PermissionError("response mode is disabled")
    if event.get("approval", {}).get("status") != "approved":
        raise PermissionError("approved SOAR decision is required")
    if event.get("action") not in ALLOWED_ACTIONS:
        raise PermissionError("action is not allowlisted")
    allowed_accounts = set(filter(None, os.environ.get("ALLOWED_ACCOUNTS", "").split(",")))
    if event.get("account_id") not in allowed_accounts:
        raise PermissionError("account is not allowlisted")


def disable_access_key(params: dict[str, Any]) -> dict[str, Any]:
    import boto3

    iam = boto3.client("iam")
    iam.update_access_key(
        UserName=params["user_name"],
        AccessKeyId=params["access_key_id"],
        Status="Inactive",
    )
    return {"rollback": "Set the access key status to Active after owner validation."}


def quarantine_instance(params: dict[str, Any]) -> dict[str, Any]:
    import boto3

    ec2 = boto3.client("ec2", region_name=params["region"])
    eni = ec2.describe_instances(InstanceIds=[params["instance_id"]])["Reservations"][0][
        "Instances"
    ][0]["NetworkInterfaces"]
    previous = {item["NetworkInterfaceId"]: [g["GroupId"] for g in item["Groups"]] for item in eni}
    for interface_id in previous:
        ec2.modify_network_interface_attribute(
            NetworkInterfaceId=interface_id,
            Groups=[params["quarantine_security_group_id"]],
        )
    return {"previous_security_groups": previous}


def lambda_handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    _authorize(event)
    if event["action"] == "disable_access_key":
        result = disable_access_key(event["parameters"])
    else:
        result = quarantine_instance(event["parameters"])
    return {"status": "executed", "action": event["action"], "result": result}
