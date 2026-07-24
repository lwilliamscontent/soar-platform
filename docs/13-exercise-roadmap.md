# SOAR Playground Exercise Roadmap

## Purpose

This is the canonical hands-on curriculum for the project. Exercises are
completed gradually and in order. Docker, CI/CD, and cloud deployment support
the curriculum but do not replace blue-team investigation practice.

Each exercise follows the incident lifecycle:

```text
detect → validate → normalize → enrich → investigate → decide
       → approve → respond or reject → verify → document → close
```

## Progress

| ID | Exercise | Primary skill | Status |
|---|---|---|---|
| EX-01 | Suspicious IP investigation and approved simulated containment | Basic triage and response lifecycle | Completed 2026-07-20 |
| EX-02 | Reject a proposed response because evidence is insufficient | Analyst judgment and false-positive safety | Completed 2026-07-20 |
| EX-03 | Attempt response without approval | Authorization and control validation | Completed 2026-07-23 |
| EX-04 | Benign observable and false-positive closure | Evidence-based disposition | Completed 2026-07-23 |
| EX-05 | Duplicate alert handling | Deduplication and case correlation | Completed 2026-07-23 |
| EX-06 | Malformed finding validation | Input validation and safe failure | Completed 2026-07-24 |
| EX-07 | VirusTotal timeout or rate limit | Provider outage and degraded operation | Planned |
| EX-08 | Splunk SOAR outage | Queueing, continuity, and recovery | Planned |
| EX-09 | Dead-letter queue investigation and redrive | Failed-event operations | Planned |
| EX-10 | Malicious file-hash investigation | File intelligence and evidence handling | Planned |
| EX-11 | Compromised IAM access key | Identity investigation and reversible containment | Planned |
| EX-12 | Exposed EC2 instance | Cloud resource triage and quarantine planning | Planned |
| EX-13 | Burp critical web vulnerability | Application-security triage and ownership routing | Planned |
| EX-14 | Approved response followed by rollback | Recovery, verification, and change reversal | Planned |

## Exercise rules

- Use synthetic findings and documentation-only indicators locally.
- Never use live malware or unauthorized targets.
- Keep all local actions in simulation mode.
- Record the evidence supporting every analyst decision.
- Require approval before every simulated mutation unless the exercise is
  specifically testing approval enforcement.
- Preserve pre-change state and rollback instructions.
- Review the complete audit sequence before marking an exercise complete.
- Repeat failed exercises after correcting the control or workflow.

## Standard completion evidence

An exercise is complete only when it produces:

1. A validated and normalized finding.
2. One case with a stable incident key.
3. Relevant enrichment or a documented degraded-mode result.
4. An analyst decision with rationale.
5. An authorized simulated response, rejection, or safe failure.
6. Verification and rollback information where applicable.
7. A complete, ordered audit trail.
8. A passing automated regression test.
9. A short lesson-learned entry.

## EX-01 passing criteria

The suspicious-IP exercise passes when:

- A synthetic Security Hub finding is accepted.
- `198.51.100.66` is extracted as an IP observable.
- Mock threat intelligence classifies it as malicious.
- One case is created with a stable incident key.
- A temporary IP block is proposed in simulation mode.
- The analyst records an approval rationale.
- The simulated block is executed and verified.
- Rollback instructions are present.
- The case is closed with all audit events visible.

### EX-01 result

- Case: `9c625efb-65ce-4685-99b2-3059c9c60bc9`
- Analyst: `student-analyst`
- Decision: approved
- Response: temporary IP block simulated and verified
- Rollback: remove the temporary block for `198.51.100.66`
- Final state: closed
- Result: pass

Lesson learned: severity alone is not sufficient authorization. The analyst
used source confidence, multiple threat-intelligence detections, action scope,
reversibility, and expected impact to justify a temporary containment decision.
Approval, execution, and verification remained separate audited events.

## EX-02 result

- Case: `b2a01994-b05f-4ed6-9b07-4201646130fe`
- Analyst: `student-analyst`
- Decision: rejected
- Response: execution denied by the approval control
- Final state: closed
- Result: pass

Lesson learned: automation recommendations must be challenged when evidence is
weak or conflicting. Low source confidence, one malicious vote against 50
harmless results, and no corroborating internal activity did not justify even a
temporary containment recommendation. Rejection prevented execution and became
an auditable successful outcome.

## EX-03 result

- Case: `033df10b-1cf2-4462-8037-efc5258776c1`
- Invocation actor: `unauthorized-automation`
- Approval record: none
- Enforcement result: denied
- Execution record: none
- Final state: closed
- Result: pass

Lesson learned: strong evidence does not replace authorization. Even though the
finding was high severity, high confidence, and enriched as malicious, the
response layer independently required an approved analyst decision. The denied
attempt was recorded for investigation without changing case or response state.

## EX-04 result

- Case: `6bee9b52-5531-422f-93ed-e0782cc3b140`
- Analyst: `student-analyst`
- Disposition: false positive
- Response proposed: no
- Execution record: none
- Final state: closed
- Result: pass

Lesson learned: benign findings still require an explicit, evidence-based
disposition. Low source confidence, unanimous harmless enrichment, and no
corroborating activity justified false-positive closure. The absence of a
response proposal was verified rather than assumed.

## EX-05 result

- Case: `9d66026c-2b0c-4967-8b6e-629c4d7c7a0c`
- Finding submissions: four
- Cases created: one
- Duplicate count: three
- Enrichment runs: one
- Response proposals: one
- Response executions: zero
- Final state: closed
- Result: pass

Lesson learned: a stable incident key prevents alert floods from creating
parallel investigations or repeated response recommendations. Repeated events
still remain visible as audited case activity, preserving frequency information
without multiplying analyst workload or containment risk.

## EX-06 result

- Malformed scenarios submitted: four
- Expected validation failures: four
- Partial cases created: zero
- Enrichments triggered: zero
- Response proposals triggered: zero
- Response executions triggered: zero
- Result: pass

Sanitized validation codes:

- `MISSING_FINDING_ID`
- `INVALID_CONFIDENCE`
- `FINDINGS_NOT_ARRAY`
- `DESCRIPTION_TOO_LONG`

Lesson learned: external security findings are untrusted input. Validation must
finish before normalization side effects, enrichment, case creation, or
response logic. Safe error codes support operations without reflecting
attacker-controlled payload content into logs.

### EX-01 commands

Prepare and review the evidence:

```bash
python3 exercises/ex01_suspicious_ip.py prepare
```

After documenting the analyst decision, record it with either `approved` or
`rejected` and a meaningful rationale:

```bash
python3 exercises/ex01_suspicious_ip.py decide \
  --decision approved \
  --analyst student-analyst \
  --rationale "Explain which evidence supports this decision"
```

Display the full case record:

```bash
python3 exercises/ex01_suspicious_ip.py show
```

## Recommended learning cadence

Complete one exercise at a time:

1. Read the scenario and identify the evidence.
2. Predict what the workflow should do.
3. Run the exercise manually.
4. Review the case and audit trail.
5. Explain why the action was approved, rejected, or blocked.
6. Run the automated regression test.
7. Record the lesson learned and update the status table.

After EX-06, introduce basic CI so the completed local exercises run on every
change. After EX-10, repeat selected exercises using AWS development services.
Real response actions remain disabled until the approval, rollback, and outage
exercises pass reliably.
