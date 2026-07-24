# Phase 5 — Deployment

## Environments

Use separate development, staging, and production AWS accounts. Use a security
tooling account for the event bus and orchestration plane. Production findings
must not enter development.

## Pipeline gates

1. Format and static checks.
2. Unit and contract tests.
3. Dependency and secret scanning.
4. Terraform validation and policy checks.
5. Build an immutable, signed artifact.
6. Deploy to development and run synthetic events.
7. Promote the same artifact to staging.
8. Require security approval for production.

## Terraform

Provide variables through environment-specific tfvars that contain identifiers
only. Secrets are created out of band or populated securely after provisioning.
Use a remote S3 backend with versioning, KMS encryption, and DynamoDB-compatible
state locking where supported by the chosen Terraform version.

## Rollout

Start in monitor-only mode. Then enable automatic enrichment and case creation.
Next enable approval-gated containment for a small account allowlist. Expand
only after measuring false positives, rollback success, provider limits, and
analyst workload.
