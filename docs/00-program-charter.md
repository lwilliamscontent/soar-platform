# Phase 0 — Program Charter

## Objective

Create a resilient SOAR capability that reduces investigation time, preserves
evidence, and performs controlled response actions without allowing a malformed
alert or compromised integration to cause broad environmental damage.

## Initial use cases

1. AWS Security Hub or GuardDuty high-severity finding.
2. Malicious file hash, URL, domain, or IP enrichment with VirusTotal.
3. Burp DAST high-confidence application vulnerability.
4. Suspicious IAM activity and potentially compromised access keys.
5. Publicly exposed cloud resource or dangerous security-group change.

## Success measures

- At least 95% of eligible findings reach Splunk SOAR within five minutes.
- Enrichment succeeds for at least 99% of supported indicators, excluding
  provider rate limits and outages.
- Duplicate cases are reduced using a deterministic incident key.
- Every automated mutation is attributable, reversible where possible, and
  recorded in CloudTrail and the SOAR case.
- No destructive action runs without policy authorization.

## Non-goals for the first release

- Replacing Splunk Enterprise Security or every existing SIEM.
- Automated malware detonation of untrusted binaries inside the control plane.
- Unattended deletion of cloud resources.
- Sending confidential files to public threat-intelligence services.

## Governance

The platform owner approves architecture and budgets. The SOC owner approves
playbooks and response policy. Cloud security approves IAM and containment
actions. Application security owns Burp scan policy. Privacy and legal approve
external enrichment data classes.

Promotion requires development, staging, and production environments with
separate AWS accounts, secrets, queues, SOAR tenants or labels, and approval
roles.
