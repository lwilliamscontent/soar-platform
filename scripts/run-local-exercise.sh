#!/usr/bin/env bash
set -euo pipefail

base_url="${SOAR_PLAYGROUND_URL:-http://127.0.0.1:8080}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "1/6 Checking playground health"
curl --fail --silent "${base_url}/health" | jq .

echo "2/6 Ingesting synthetic Security Hub finding"
ingest="$(curl --fail --silent -X POST "${base_url}/api/findings/securityhub" \
  -H 'Content-Type: application/json' \
  --data-binary "@${repo_root}/exercises/suspicious-ip-finding.json")"
case_id="$(jq -r '.results[0].case.id' <<<"${ingest}")"
jq '.results[0] | {created, case: {id: .case.id, status: .case.status, enrichment: .case.enrichment, proposed_action: .case.proposed_action}}' <<<"${ingest}"

echo "3/6 Sending duplicate to verify idempotency"
curl --fail --silent -X POST "${base_url}/api/findings/securityhub" \
  -H 'Content-Type: application/json' \
  --data-binary "@${repo_root}/exercises/suspicious-ip-finding.json" \
  | jq '.results[0] | {created, duplicate_count: .case.duplicate_count}'

echo "4/6 Approving simulated response"
curl --fail --silent -X POST "${base_url}/api/cases/${case_id}/approve" \
  -H 'Content-Type: application/json' \
  -d '{"actor":"student-analyst","decision":"approved","note":"Synthetic evidence reviewed for exercise"}' \
  | jq '{status, approval}'

echo "5/6 Executing and verifying simulated containment"
curl --fail --silent -X POST "${base_url}/api/cases/${case_id}/execute" \
  -H 'Content-Type: application/json' \
  -d '{"actor":"student-analyst"}' \
  | jq '{status, execution}'

echo "6/6 Closing case and checking audit trail"
closed="$(curl --fail --silent -X POST "${base_url}/api/cases/${case_id}/close" \
  -H 'Content-Type: application/json' \
  -d '{"actor":"student-analyst","resolution":"Validated simulated block and rollback data"}')"
jq '{id, status, duplicate_count, audit_events: [.audit[].event_type]}' <<<"${closed}"

test "$(jq -r '.status' <<<"${closed}")" = "closed"
test "$(jq -r '.execution.status' <<<"${closed}")" = "simulated"
test "$(jq -r '.duplicate_count' <<<"${closed}")" -ge 1
echo "PASS: suspicious-IP exercise completed for case ${case_id}"
