# Phase 1 — Architecture

## Event flow

```text
Security Hub / GuardDuty / Burp
              |
          EventBridge
              |
         encrypted SQS ----> DLQ
              |
       Normalizer Lambda
          /          \
 VirusTotal       Splunk SOAR
 enrichment      case + artifacts
                       |
                approval playbook
                       |
               Step Functions
                       |
                Responder Lambda
                       |
        AWS quarantine / credential action
```

## Trust boundaries

- Internet-facing sources terminate at authenticated endpoints protected by
  AWS WAF, throttling, schema validation, and replay protection.
- Workloads run in private subnets when VPC attachment is required. AWS service
  access uses VPC endpoints where practical.
- Secrets are fetched at runtime from Secrets Manager and decrypted with KMS.
- Splunk SOAR is reached over HTTPS with certificate verification enabled.
- Every queue uses server-side encryption and a dead-letter queue.

## Canonical finding

All sources are transformed into the schema in
`schemas/canonical-finding.schema.json`. The `incident_key` is stable across
retries and updates. Raw source payloads are retained only in a restricted,
encrypted evidence store when policy permits.

## Availability model

EventBridge and SQS decouple producers from processors. Lambda retries
transient failures; poison messages move to a DLQ. Idempotency records prevent
duplicate cases and actions. Multi-Region disaster recovery is a later phase;
the initial release uses one primary Region and infrastructure-as-code rebuild.

## Production decisions

- Splunk SOAR owns incident state and analyst approvals.
- AWS Step Functions owns cloud-response execution state.
- VirusTotal verdicts are evidence, not sole authorization for containment.
- Burp issues are normalized as findings; scans are launched only from approved
  CI/CD or application-security workflows.
