# SOP — Operating the XDR triage bridge

**Service:** `xdr-triage-bridge`
**Owner:** security operations
**Audience:** tier-2 analysts, the SOC lead who approves, the service owner
**Review cadence:** quarterly, or after any containment policy change

---

## 1. Purpose and scope

This procedure covers how a Defender XDR incident becomes a triaged Jira ticket with a proposed containment plan and a named human approval.

**In scope:** incident intake, review, approval, filing, and what to do when any of those fail.
**Out of scope, deliberately:** executing containment. This bridge proposes and files. It does not isolate a device, revoke a session or disable an account. Those actions live in the XDR console under a different approval model.

Anyone who asks the bridge to "just isolate it" is asking for a different control with a different SOP, and the answer is no.

---

## 2. Roles and approval authority

| Role | Owns |
|---|---|
| Tier-2 analyst | runs the review, reads the summary, files |
| SOC lead / duty manager | approves irreversible containment |
| Service owner | containment table, severity mapping, releases |
| Incident commander (P1) | may approve, and must be informed of every P1 ticket |

**Approver eligibility.** The approver must be a named person with an account in the SOC. The service refuses `agent`, `system`, `model`, `bot` and `automation` as approvers — the thing that proposed an action is never the thing that accepts it.

**Separation of duties.** The analyst who wrote the review may approve it only if they are the duty manager. If the analyst and the approver are the same person and that person is not the duty manager, the ticket waits.

---

## 3. Standard flow

```bash
export SECOPS_API_KEYS="$(openssl rand -hex 24)"
export JIRA_BASE_URL="https://example.atlassian.net"
export JIRA_EMAIL="soc-bot@example.com"
export JIRA_TOKEN="..."          # from the secret manager, never a shell history file

uvicorn app.main:app --port 8000
```

1. **Review.** Take the incident from the Defender portal (or the Graph API), submit it, and read the returned `summary`, `recommendation.actions` and `approval_required`.

```bash
curl -s localhost:8000/v1/incidents -H "x-api-key: $SECOPS_API_KEYS" \
  -H 'content-type: application/json' \
  -d "{\"incident\": $(cat incident.json)}"
```

2. **Check the proposal against the evidence.** The table proposes; you decide whether the proposal fits. `isolate_host` on a domain controller during business hours is a business decision, not a technical one, and the table cannot know that.
3. **Approve as a person.** Record who approved and why in the ticket comment, not just the API call.
4. **File.** The response carries the Jira key. If it starts with `LOCAL-`, the filing did **not** reach Jira — see §7.
5. **Update the incident.** The bridge does not change the Defender incident status. Set it yourself, or the ticket and the console will disagree within a day.

---

## 4. Reading the recommendation

| Field | Meaning |
|---|---|
| `actions[].action` | what the table proposes |
| `actions[].irreversible` | true means a human approval is required before filing |
| `approval_required` | true if any proposed action is irreversible |
| `blast_radius` | hosts + accounts + IPs in the incident |
| `summary_source` | `template` or verified `model` output |

An incident with `approval_required: false` still produces a ticket in `awaiting_approval`. Nothing is auto-filed, even when nothing irreversible is proposed — because "nothing irreversible" is a claim about a table, and someone should look.

---

## 5. Containment table — current version

| Condition | Proposal |
|---|---|
| high severity + named host | `isolate_host` |
| credential access / privilege escalation | `revoke_sessions`, `reset_password` |
| lateral movement | `isolate_host` |
| collection / exfiltration | `block_indicator` |
| external IP present | `block_indicator` |
| nothing matched | `monitor` |

Changes to this table are a security-operations decision, not an engineering one. They require sign-off from the SOC lead and a note in the change log, because the first time the table is wrong a customer will ask who approved it.

---

## 6. Jira field mapping

| Jira field | Source |
|---|---|
| summary | `[SEVERITY] incident display name` |
| description | analyst summary, recommended actions, approver, incident id |
| issue type | `Incident` |
| labels | `xdr`, `severity-<level>`, up to three tactic labels |
| project | `JIRA_PROJECT`, default `SOC` |

The description is generated from the deterministic template at approval time, so the ticket always states what was approved — not what a model said earlier.

---

## 7. Failure modes

| Symptom | Likely cause | First response |
|---|---|---|
| `issue_key` starts with `LOCAL-` | Jira credentials not configured | **treat as failed filing.** File manually, then fix the configuration |
| `403 the agent that proposed the action cannot approve it` | approver name is `agent`/`system`/`bot` | use the person's own name |
| `422 not a Graph security incident` | wrong object submitted (alert instead of incident) | submit the incident object |
| `summary_source: template` with `summary_rejected` | model named a host or IP not in the incident | send the template, open a defect with the prompt and response |
| ticket created twice | two analysts reviewed the same incident | check for an open Jira issue by incident id before approving |
| Jira returns 401/403 at approval | expired API token | rotate at the secret manager, then retry the approval; the ticket stays `awaiting_approval`, so nothing is lost |

**The service never reports success it did not achieve.** The local outbox is a test facility; in production its presence in a response is an error condition.

---

## 8. Data handling

Incidents carry personal data: account names, hostnames, and sometimes mailbox subjects.

- The service stores nothing: tickets live in memory for the process lifetime, and the outbox file exists only when Jira is not configured.
- Do not send incident objects to a third-party model provider unless the SOC's data-protection assessment permits it. If it does not, run with `use_model: false` — the template summary is the supported production path, not a degraded one.
- Incident objects in fixtures and tests are synthetic. Never commit a real incident export.
- Retain Jira tickets per the customer's retention policy, not this repo's.

---

## 9. Metrics worth watching

| Metric | Why |
|---|---|
| `http_requests_rejected_total{reason="bad_key"}` | a misconfigured collector, or someone probing |
| ratio of `summary_source=template` to `model` | if it drifts to 100% template unexpectedly, the provider is down |
| approval latency (ticket created → approved) | a backlog hiding in the queue |
| tickets with `LOCAL-` keys | filing is broken and someone is filing by hand |

---

## 10. Known limits

- Defender XDR is mocked in tests. No tenant is contacted by this repo, and the Graph shapes are the contract you must validate on first connection.
- No containment execution, by design (§1).
- Severity comes from the incident, not from a risk model. An over-graded incident produces an over-graded proposal.
- The summary is capped at four sentences; complex multi-stage incidents need an analyst narrative on top.
- It has run against fixtures, not against a live SOC queue. First week in production should be shadow-mode: file tickets, do not act on them.

---

## 11. Escalation

| Situation | Route |
|---|---|
| Proposed containment looks wrong for the business | SOC lead; record the override and the reason |
| Model summary contains a host or IP not in the incident | service owner; keep the template |
| Jira filing fails during a P1 | file by hand immediately, fix the bridge after |
| Approver unavailable and containment is time-critical | incident commander approves; record it |
| Suspected token compromise | rotate the Jira token and the API key; review access logs |
