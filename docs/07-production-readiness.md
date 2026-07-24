# Phase 7 — Production Readiness

Before go-live, verify:

- Named owners, escalation paths, and 24x7 expectations.
- Vendor licensing, API quotas, support tiers, and data-processing agreements.
- KMS rotation, secret rotation, certificate validation, and egress controls.
- Least-privilege IAM reviewed with access analysis.
- Dashboards and alerts for throughput, latency, errors, DLQ, throttles, cost,
  approval age, and response outcomes.
- Tested backup, restore, regional rebuild, and provider-outage procedures.
- Playbook versioning and two-person approval for high-impact changes.
- Retention and privacy controls for evidence and audit logs.
- Monthly playbook review and quarterly incident-response exercise.

## SLOs

- Ingestion availability: 99.9% monthly.
- P95 source-to-case latency: under five minutes.
- No untracked response mutations.
- DLQ messages acknowledged within 15 minutes and remediated within four hours.

## Known deployment prerequisites

The customer must supply Splunk SOAR and Burp endpoint details, licensed API
features, VirusTotal tier and key, AWS account topology, target Regions, network
connectivity, identity provider, notification/ticketing systems, data
classification, and the approved response-action matrix.
