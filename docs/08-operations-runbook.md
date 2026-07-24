# Operations Runbook

## DLQ alarm

1. Open the associated SOAR operational incident.
2. Inspect message metadata without copying secrets or raw sensitive payloads.
3. Classify as transient dependency failure, schema error, authorization error,
   poison payload, or code defect.
4. Fix the cause in staging.
5. Redrive only validated messages in bounded batches.

## VirusTotal outage or throttling

Open the circuit breaker, retain findings in the queue, mark enrichment as
pending, and continue case creation without a verdict. Do not bypass provider
limits or silently treat missing enrichment as benign.

## Splunk SOAR outage

SQS retains findings. Alert before retention risk. After recovery, process in
order where possible and rely on the incident key to prevent duplicates.

## Suspected credential compromise

Disable the affected integration credential, rotate it in Secrets Manager,
invalidate old provider tokens, review CloudTrail and provider audit logs, and
replay only confirmed-safe queued messages.

## Emergency stop

Set response mode to `disabled`, remove Step Functions invoke permission from
the dispatcher, and leave ingestion/case creation active. Record who invoked
the stop and why. Re-enable only after two-person review.
