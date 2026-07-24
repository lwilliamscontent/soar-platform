# Phase 4 — Playbooks

## PB-001 Malicious observable

Trigger: supported observable in a high-priority finding.

1. Validate and classify the observable.
2. Check cache, then query VirusTotal when allowed.
3. Correlate with asset criticality and internal telemetry.
4. Add evidence and confidence to the SOAR case.
5. If policy threshold is met, propose a scoped block.
6. Obtain approval, execute, verify, and document expiration or rollback.

## PB-002 Compromised IAM credential

Trigger: GuardDuty or Security Hub credential-compromise finding.

1. Identify principal, account, recent API activity, and business owner.
2. Collect CloudTrail evidence and active access-key metadata.
3. Propose disabling only the implicated key.
4. Require approval unless an emergency policy explicitly authorizes action.
5. Disable the key, preserve prior status, notify owner, and verify no further
   use. Never delete the key during initial containment.

## PB-003 Exposed EC2 instance

Trigger: high-confidence malicious activity or dangerous exposure.

1. Confirm instance identity, owner, criticality, and autoscaling context.
2. Snapshot relevant metadata and network state.
3. Propose replacing security groups with a pre-created quarantine group.
4. Require approval, change only the targeted interfaces, and verify.
5. Preserve rollback data and avoid stopping or terminating the instance.

## PB-004 Burp critical issue

Trigger: confirmed high-severity issue on an approved target.

1. Deduplicate by application, scan, issue type, and location.
2. Sanitize evidence; do not reproduce active exploit payloads automatically.
3. Correlate ownership and deployment metadata.
4. Create or update the SOAR case and engineering ticket.
5. Retest only after remediation approval and within the authorized scan scope.

## Scoring

Risk is computed from source confidence, technical severity, asset criticality,
exposure, threat intelligence, and compensating controls. No single external
score may authorize a destructive response.
