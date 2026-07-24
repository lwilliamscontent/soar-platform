# Phase 3 — Integration Configuration

## Splunk SOAR

Create a dedicated automation user restricted by source IP and least-privilege
role. Store its token in Secrets Manager. Configure labels:

- `aws_security_finding`
- `burp_dast_finding`
- `threat_intel_enrichment`

Create modular playbooks:

1. Normalize and deduplicate.
2. Extract observables.
3. Enrich supported observables.
4. Score confidence and business impact.
5. Request approval when response is eligible.
6. Execute through the AWS response workflow.
7. Verify, document, and close or escalate.

Use the `ph-auth-token` request header over verified HTTPS. Restrict the
automation user to only the required REST objects and network ranges.

## VirusTotal

Use API v3 hash, URL, domain, and IP lookup endpoints. Apply a local cache and
rate limiter appropriate to the purchased tier. Do not treat a single engine
detection as conclusive. Capture provider timestamp, reputation, analysis
statistics, and a permalink in the case.

## Burp Suite

Use Burp Suite Enterprise/DAST APIs or webhooks available in the licensed
edition. The adapter accepts a generic issue payload so vendor-version changes
remain isolated. Require an authenticated source, map scan and issue IDs into
the incident key, and route only in-scope targets.

Burp Suite Professional is an analyst testing tool and should not be exposed as
an unattended production scanner unless the license and deployment model
explicitly support that use.

## AWS

Enable organization-level CloudTrail, GuardDuty, Security Hub, AWS Config, IAM
Access Analyzer, Inspector, and centralized findings where available. Forward
Security Hub findings through EventBridge. Use delegated administrator
accounts and cross-account response roles with external IDs and resource-level
conditions.

## Splunk SIEM

Send platform metrics and audit events through HEC or supported AWS ingestion.
Keep operational logs separate from sensitive evidence. Alert on DLQ depth,
failed enrichments, unauthorized action attempts, latency, and unusual volume.
