import os

os.environ.setdefault("SERVICE_NAME", "xdr-triage-bridge")
os.environ.setdefault("SERVICE_VERSION", "1.0.0")

from pathlib import Path  # noqa: E402

from fastapi import FastAPI, HTTPException  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402

from . import llm  # noqa: E402
from .runtime import configure_logging, install_runtime  # noqa: E402
from .xdr import JiraClient, Ticket, normalise, recommend  # noqa: E402

BLOCKED_APPROVERS = {"agent", "system", "model", "bot", "automation"}

configure_logging()
app = FastAPI(title="xdr-triage-bridge", version="1.0.0")
install_runtime(app)

OUTBOX = Path(__file__).resolve().parent.parent / "evidence" / "jira_outbox.jsonl"
JIRA = JiraClient(outbox=OUTBOX)
TICKETS: dict[str, Ticket] = {}


class IncidentRequest(BaseModel):
    incident: dict = Field(description="Graph Security API incident object")
    use_model: bool = False


class ApprovalRequest(BaseModel):
    approver: str = Field(min_length=3)


@app.post("/v1/incidents")
def review_incident(request: IncidentRequest):
    try:
        incident = normalise(request.incident)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    recommendation = recommend(incident)
    provider = llm.provider_from_env() if request.use_model else None
    summary = llm.build_summary(incident, recommendation, provider)

    ticket_id = f"T-{len(TICKETS) + 1:04d}"
    ticket = Ticket(
        ticket_id=ticket_id, incident=incident, recommendation=recommendation
    )
    TICKETS[ticket_id] = ticket

    payload = ticket.as_dict()
    payload["summary"] = summary["text"]
    payload["summary_source"] = summary["source"]
    if summary["rejected"]:
        payload["summary_rejected"] = summary["rejected"]
    return payload


@app.get("/v1/tickets/{ticket_id}")
def get_ticket(ticket_id: str):
    ticket = TICKETS.get(ticket_id)
    if ticket is None:
        raise HTTPException(status_code=404, detail="unknown ticket")
    return ticket.as_dict()


@app.post("/v1/tickets/{ticket_id}/approve")
def approve_ticket(ticket_id: str, request: ApprovalRequest):
    ticket = TICKETS.get(ticket_id)
    if ticket is None:
        raise HTTPException(status_code=404, detail="unknown ticket")
    approver = request.approver.strip()
    if approver.lower() in BLOCKED_APPROVERS:
        raise HTTPException(
            status_code=403,
            detail="the agent that proposed the action cannot approve it",
        )
    if ticket.state == "approved":
        return ticket.as_dict()

    summary = llm.template_summary(ticket.incident, ticket.recommendation)
    actions = ", ".join(a["action"] for a in ticket.recommendation["actions"])
    description = (
        f"{summary}\n\n"
        f"Recommended actions: {actions}\n"
        f"Approved by: {approver}\n"
        f"Incident: {ticket.incident.incident_id}"
    )
    labels = [
        "xdr",
        f"severity-{ticket.incident.severity}",
        *[t.replace(" ", "-").lower() for t in ticket.incident.tactics[:3]],
    ]
    ticket.issue_key = JIRA.create_issue(
        summary=f"[{ticket.incident.severity.upper()}] {ticket.incident.name}",
        description=description,
        labels=labels,
    )
    ticket.state = "approved"
    ticket.approver = approver
    return ticket.as_dict()
