# Phase 10 — Single-Account Playground

## Selected target

- AWS account: `589528729991`
- Region: `us-east-1`
- Environment: `dev`
- Initial dispatch mode: `log`
- Initial response mode: `disabled`

The account ID is an identifier, not a secret. Terraform requires it as an
input and configures the AWS provider with `allowed_account_ids`. This causes a
plan or apply to fail if the active AWS credentials point at another account.

## Local identity check

Before every local plan:

```bash
aws sts get-caller-identity --region us-east-1
aws configure get region
```

The expected account is `589528729991`. Do not continue if the ARN contains
`root` or the account differs.

## Configuration

Copy the example without committing the result:

```bash
cp infra/terraform/dev.tfvars.example infra/terraform/dev.tfvars
```

Fill in the artifact bucket and immutable artifact keys. Add an email address
for budget alerts. Keep `allowed_response_accounts` empty during monitor-only
deployment.

## Credential improvement

The current local identity is the IAM user `terraform-manager`. This is
acceptable only as a temporary bootstrap identity. Replace static credentials
with IAM Identity Center or an assumed deployment role. GitHub Actions must use
OIDC and short-lived role credentials, never this user's access keys.
