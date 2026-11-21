# xdr-triage-bridge

Turns a Microsoft Defender XDR incident into a Jira ticket — with containment proposed by a table, drafted by a model, and filed only by a named human.

## The shape of the problem

The tempting version of this tool closes incidents. That version is a fraud control a phishing email can talk out of the way: a compliant model plus a hostile alert equals a suppressed ticket, and nobody is told.

So the designer's question is not "can the model triage?" It is "what is the model allowed to decide?" Here, nothing that matters.

```
Graph incident ──► normalise ──► containment table ──► recommendations
                                          │
                                          ▼
                                 model drafts the summary
                                          │
                                          ▼
                        host/IP check ──► pending ticket
                                          │
                              named human approves
                                          │
                                          ▼
                                   Jira issue created
```

## The containment table

| Condition | Actions proposed | Irreversible |
|---|---|---|
| `severity=high` and a named host | `isolate_host` | yes |
| credential access or privilege escalation | `revoke_sessions`, `reset_password` | yes |
| lateral movement | `isolate_host` | yes |
| collection or exfiltration | `block_indicator` | no |
| an external IP in the incident | `block_indicator` | no |
| nothing matched | `monitor` | no |

If any proposed action is irreversible, the ticket cannot be filed without an approval naming a person. `agent`, `system`, `model`, `bot` and `automation` are refused as approvers — the thing that proposed the action is not allowed to be the thing that accepts it.

## What the model is allowed to do

- Write the four-sentence analyst summary that goes into the ticket.
- That is the whole list.

It cannot add an entity, change a severity, choose a containment action, or approve anything. Every host (`fs-01`, `ws-1042`) and IP the summary names must exist in the incident; a summary that invents one is discarded and the deterministic template is used instead. Alert titles are control-stripped and fenced as data before they reach a prompt.

## Run it

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt

python -m app.cli fixtures/incident_high.json

export SECOPS_API_KEYS=dev-key-change-me
uvicorn app.main:app --port 8000

# open a review (creates a pending ticket, files nothing)
curl -s localhost:8000/v1/incidents -H "x-api-key: dev-key-change-me" \
  -H 'content-type: application/json' \
  -d "{\"incident\": $(cat fixtures/incident_high.json)}"

# approve it as a person
curl -s -X POST localhost:8000/v1/tickets/T-0001/approve -H "x-api-key: dev-key-change-me" \
  -H 'content-type: application/json' -d '{"approver":"kelvin.odarikpe"}'
```

Without Jira credentials the client writes the exact issue payload to `evidence/jira_outbox.jsonl`, so the integration is testable without a tenant. With `JIRA_BASE_URL`, `JIRA_EMAIL` and `JIRA_TOKEN` set, it posts to `/rest/api/3/issue`.

## What this does not claim

Defender XDR is mocked in tests and in CI: the fixtures are real Graph Security API shapes, but no tenant is contacted. There is no auto-containment execution either — the bridge proposes and files, it does not call the isolate-device action. That gap is deliberate: an execute path is a different control with a different approval model, and pretending one endpoint covers both is how this kind of tool gets someone's file server taken offline at 2am.
