# Phase 12 — Local SOAR Playground

## Purpose

The local playground exercises the real normalization, case, approval,
idempotency, simulation, verification, and audit logic without contacting AWS,
VirusTotal, Splunk SOAR, or a firewall.

## Start the environment

```bash
docker compose up -d
docker compose ps
curl http://127.0.0.1:8080/health
```

Open `http://127.0.0.1:8080` to view the analyst dashboard.

## Run the first exercise

```bash
./scripts/run-local-exercise.sh
```

The script ingests a synthetic Security Hub finding containing the documentation
address `198.51.100.66`. The deterministic mock intelligence provider classifies
it as malicious. The workflow creates one case, detects a duplicate, requests
approval, simulates an IP block, verifies the mock control, records rollback
instructions, closes the case, and prints the audit sequence.

No network control or AWS resource is changed.

## Useful commands

```bash
docker compose logs -f playground
curl http://127.0.0.1:8080/api/cases | jq .
docker compose restart playground
docker compose down
```

Data persists in the Docker volume `soar-platform_playground-data`. Use
`docker compose down -v` only when intentionally resetting all local cases.

## API summary

- `GET /health`
- `GET /api/cases`
- `GET /api/cases/{case_id}`
- `POST /api/findings/securityhub`
- `POST /api/cases/{case_id}/approve`
- `POST /api/cases/{case_id}/execute`
- `POST /api/cases/{case_id}/close`

This API is bound to `127.0.0.1` and has no production authentication. It must
not be exposed to a network or used with real security findings.
