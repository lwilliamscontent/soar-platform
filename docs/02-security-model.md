# Phase 2 — Security and Threat Model

## Primary threats

- Forged webhooks and replayed events.
- API-token theft.
- Prompt, payload, or log injection through attacker-controlled finding text.
- Queue flooding and provider rate exhaustion.
- Over-privileged response roles.
- Duplicate or out-of-order events.
- Supply-chain compromise in Lambda packages.
- Sensitive-data leakage to VirusTotal or logs.

## Controls

- HMAC or OAuth authentication, timestamp validation, nonce storage, WAF, and
  per-source throttling for inbound webhooks.
- Secrets Manager rotation and distinct credentials per environment.
- Strict JSON Schema validation and size limits before processing.
- Structured logs that redact tokens, authorization headers, URLs with query
  strings, and raw file contents.
- Separate read/enrich and mutate/respond IAM roles.
- Explicit allowlists for accounts, Regions, resource types, and actions.
- Human approval for isolation, credential disablement, blocking, or rollback.
- Reserved concurrency, SQS backpressure, exponential retry, and circuit
  breakers for external providers.
- Signed build artifacts, pinned dependencies, SAST, dependency scanning, and
  IaC scanning in CI.

## Data handling

Never upload customer files, source code, credentials, session tokens, private
URLs, or regulated data to VirusTotal without documented authorization. Hash
lookups are the default. Evidence retention, legal hold, and deletion schedules
must be configured by data classification.

## Response safety

Every action has four states: proposed, approved, executing, and verified.
Actions must be idempotent. The responder records pre-change state and a
rollback instruction. Broad actions such as deleting resources, changing
organization-wide policy, or disabling many identities are prohibited.
