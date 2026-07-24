# Phase 9 — Terraform and CI/CD

## Infrastructure policy

All AWS infrastructure is declared in Terraform. Console changes are emergency
exceptions and must be imported or reverted immediately. Production uses a
versioned, KMS-encrypted S3 state backend with state locking, restricted bucket
policy, access logging, and a dedicated deployment role.

Provider and module versions are constrained. Terraform plans are generated
from immutable source revisions. Production applies use the saved plan produced
after validation and execute through a protected CI/CD environment.

## Pull-request pipeline

The CI workflow performs:

1. Python unit tests and byte-code compilation.
2. EX-01 through EX-06 workflow regression tests.
3. JSON fixture and canonical-schema parsing.
4. Shell-script syntax checks.
5. Terraform formatting and validation.
6. IaC policy/security scanning.
7. Secret scanning.
8. Reproducible Lambda zip packaging.

The workflow applies timeouts and concurrency cancellation so stale or hung
runs do not consume runner capacity indefinitely.

A branch-protection rule must require all jobs and at least two reviewers for
changes to response policy, IAM, networking, KMS, or production playbooks.
Add CODEOWNERS entries for cloud security and SOC engineering.

## Deployment pipeline

Deployments use GitHub Actions OIDC federation to assume a short-lived AWS role;
no long-lived AWS access keys are stored in CI. Each Lambda zip is addressed by
its SHA-256 digest and uploaded under an immutable key.

GitHub environments provide separation:

- `dev`: automatic or low-friction approval.
- `staging`: SOC or cloud-security approval.
- `prod`: two-person approval, restricted branches, and change ticket.

The workflow packages a selected commit, uploads immutable artifacts, creates a
Terraform saved plan, and applies that exact plan. Production should additionally
archive the plan, machine-readable plan JSON, test evidence, artifact digests,
and approval metadata to the audit account.

## Bootstrap

The state bucket, GitHub OIDC provider, and deployment roles form a small
bootstrap layer. Provision them once with a separately reviewed Terraform
configuration. Deployment roles must be environment-specific and unable to
modify their own trust policy or permissions boundary.

## Required repository settings

- Environments: `dev`, `staging`, and `prod`.
- Variables per environment: `AWS_DEPLOY_ROLE_ARN`, `AWS_ACCOUNT_ID`,
  `AWS_REGION`, `ARTIFACT_BUCKET`.
- Protected `main` branch with required checks.
- Tag or release protection for production revisions.
- Dependabot or Renovate for reviewed dependency updates.

No API provider secret is stored in GitHub. Runtime provider secrets remain in
AWS Secrets Manager and are populated through an approved operational process.

The initial CI baseline and passing-gate evidence are recorded in
`docs/14-ci-confirmation.md`.
