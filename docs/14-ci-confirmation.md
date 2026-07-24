# CI Confirmation

## Confirmed baseline

- Repository: `https://github.com/lwilliamscontent/soar-platform`
- Visibility: private
- Branch: `main`
- Confirmed commit: `1805264`
- GitHub Actions run: `30109758173`
- Result: success
- Confirmation date: 2026-07-24

## Passing gates

### Test

- Python dependency installation.
- Source compilation.
- JSON fixture and canonical-schema parsing.
- EX-01 through EX-06 regression suite.
- Ingestor and responder service tests.
- Shell-script syntax validation.

### Terraform

- Formatting check.
- Provider initialization without backend access.
- Terraform configuration validation.

### Security

- Checkov: 55 passed, 0 failed, 8 documented exceptions.
- Gitleaks: passed with no detected committed secrets.

The documented Checkov exceptions cover the standard account-administration KMS
statement, SQS-owned dead-letter handling, current public egress architecture,
vendor-aware secret rotation, and the tracked Lambda code-signing gap. These are
not silent suppressions; their rationale is colocated with the affected
Terraform resources and production-readiness documentation.

### Package

- Reproducible ZIP packaging for ingestor, enricher, and responder Lambdas.
- Successful CI artifact upload.

## Non-blocking warnings

GitHub reported that some third-party action releases still target the
deprecated Node.js 20 action runtime and were automatically run with Node.js 24.
Track and upgrade those actions when compatible releases are available. Do not
set `ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION`.

## Repository safety

The project is now an independent Git repository. Its remote uses a clean HTTPS
URL, and GitHub authentication is stored by the system credential manager rather
than embedded in the remote.

An unrelated parent repository previously contained a token-bearing remote URL.
That old personal access token must remain revoked and must not be reused.

## Next repository controls

- Require the `test`, `terraform`, `security`, and `package` checks on `main`.
- Require pull requests for changes after the initial learning phase.
- Require CODEOWNERS review for responder, IAM, KMS, workflow, and playbook
  changes when a second reviewer is available.
- Disallow force pushes and branch deletion.
- Enable Dependabot or Renovate for action and dependency updates.
