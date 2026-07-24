# Phase 6 — Testing

Required test layers:

- Unit tests for normalization, redaction, deduplication, and policy.
- Contract tests using recorded, sanitized provider payloads.
- Integration tests against non-production SOAR and AWS accounts.
- Failure injection for timeouts, HTTP 429, malformed JSON, duplicate events,
  DLQ behavior, and partial response failures.
- Tabletop exercises for credential compromise and cloud quarantine.
- Restore tests for infrastructure, configuration, evidence, and playbooks.

Production tests use synthetic indicators and dedicated test resources. Never
use live malware, unauthorized targets, or uncontrolled exploit payloads.

Exit criteria include successful rollback, complete audit records, bounded
retries, no duplicate actions, and alerting on every intentionally induced
failure.
