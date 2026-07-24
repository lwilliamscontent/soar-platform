import importlib.util
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "services" / "ingestor" / "handler.py"
SPEC = importlib.util.spec_from_file_location("ingestor", MODULE_PATH)
ingestor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ingestor)


def test_securityhub_normalization_is_deterministic():
    event = {
        "detail": {
            "findings": [
                {
                    "Id": "finding-1",
                    "Title": "Test",
                    "Description": "Description",
                    "Severity": {"Label": "HIGH"},
                    "AwsAccountId": "123456789012",
                    "Region": "us-east-1",
                    "UpdatedAt": "2026-01-01T00:00:00Z",
                    "Resources": [{"Id": "arn:aws:ec2:us-east-1:123456789012:instance/i-1"}],
                }
            ]
        }
    }
    first = ingestor.normalize_securityhub(event)[0]
    second = ingestor.normalize_securityhub(event)[0]
    assert first["incident_key"] == second["incident_key"]
    assert first["severity"] == "high"
    assert first["account_id"] == "123456789012"
