"""Defender XDR incident to Jira ticket, with a gate the model cannot open.

Three rules, and they are the whole design:

1. Severity and containment come from a table, not from a model.
2. Nothing irreversible happens without a named human approver.
3. The model writes the summary and the ticket body. It cannot add an entity,
   a host or an indicator that was not in the incident.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

SEVERITY_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3}
HOST_RE = re.compile(r"\b[a-z]{2,}[a-z0-9]*-[0-9]{1,6}\b", re.IGNORECASE)
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

CREDENTIAL_TACTICS = {"credential access", "credentialaccess", "privilege escalation"}
LATERAL_TACTICS = {"lateral movement", "lateralmovement"}
EXFIL_TACTICS = {"exfiltration", "collection"}


@dataclass
class Alert:
    alert_id: str
    title: str
    severity: str
    tactics: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)


@dataclass
class Incident:
    incident_id: str
    name: str
    severity: str
    status: str
    created: str
    alerts: list[Alert] = field(default_factory=list)
    accounts: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)

    @property
    def tactics(self) -> list[str]:
        seen: list[str] = []
        for alert in self.alerts:
            for tactic in alert.tactics:
                normalised = tactic.lower()
                if normalised not in seen:
                    seen.append(normalised)
        return seen

    @property
    def blast_radius(self) -> int:
        return len(self.hosts) + len(self.accounts) + len(self.ips)

    def as_dict(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "name": self.name,
            "severity": self.severity,
            "status": self.status,
            "created": self.created,
            "tactics": sorted(self.tactics),
            "techniques": sorted({t for a in self.alerts for t in a.techniques}),
            "entities": {
                "accounts": sorted(self.accounts),
                "hosts": sorted(self.hosts),
                "ips": sorted(self.ips),
            },
            "blast_radius": self.blast_radius,
        }


def normalise(payload: dict) -> Incident:
    """Accept the Graph Security API shape, and refuse anything else loudly."""
    if "id" not in payload or "alerts" not in payload:
        raise ValueError("not a Graph security incident: 'id' and 'alerts' are required")
    entities = payload.get("entities", {})
    alerts = [
        Alert(
            alert_id=str(alert.get("id", "")),
            title=str(alert.get("title", "untitled")),
            severity=str(alert.get("severity", "informational")).lower(),
            tactics=list(alert.get("tactics", [])),
            techniques=list(alert.get("techniques", [])),
        )
        for alert in payload["alerts"]
    ]
    severity = str(payload.get("severity", "informational")).lower()
    if severity not in SEVERITY_ORDER:
        severity = "informational"
    return Incident(
        incident_id=str(payload["id"]),
        name=str(payload.get("displayName", "unnamed incident")),
        severity=severity,
        status=str(payload.get("status", "active")),
        created=str(payload.get("createdDateTime", "")),
        alerts=alerts,
        accounts=[str(a) for a in entities.get("accounts", [])],
        hosts=[str(h) for h in entities.get("hosts", [])],
        ips=[str(i) for i in entities.get("ips", [])],
    )


def recommend(incident: Incident) -> dict:
    """The containment table. Deterministic, reviewable, and boring on purpose."""
    actions: list[dict] = []
    tactics = set(incident.tactics)

    def add(action: str, reason: str, irreversible: bool) -> None:
        if not any(a["action"] == action for a in actions):
            actions.append(
                {"action": action, "reason": reason, "irreversible": irreversible}
            )

    if incident.severity == "high" and incident.hosts:
        add("isolate_host", "high-severity activity on a named host", True)

    if tactics & CREDENTIAL_TACTICS:
        add("revoke_sessions", "credential access present: existing tokens are suspect", True)
        add("reset_password", "credential access present: the password may be known", True)

    if tactics & LATERAL_TACTICS:
        add("isolate_host", "lateral movement observed between hosts", True)

    if tactics & EXFIL_TACTICS:
        add("block_indicator", "collection or exfiltration indicators present", False)

    if incident.ips:
        add("block_indicator", "external indicator present in the incident", False)

    if not actions:
        add("monitor", "no containment trigger met; keep the incident open and watch", False)

    irreversible = any(a["irreversible"] for a in actions)
    return {
        "actions": actions,
        "approval_required": irreversible,
        "blast_radius": incident.blast_radius,
        "severity": incident.severity,
    }


def invented_entities(text: str, incident: Incident) -> set[str]:
    allowed_hosts = {h.lower() for h in incident.hosts}
    allowed_ips = set(incident.ips)
    found_hosts = {m.lower() for m in HOST_RE.findall(text)}
    found_ips = set(IP_RE.findall(text))
    return (found_hosts - allowed_hosts) | (found_ips - allowed_ips)


class JiraClient:
    """Real when configured, local outbox otherwise. Never silently does nothing."""

    def __init__(self, outbox: Path | None = None) -> None:
        self.base_url = os.environ.get("JIRA_BASE_URL", "").rstrip("/")
        self.email = os.environ.get("JIRA_EMAIL", "")
        self.token = os.environ.get("JIRA_TOKEN", "")
        self.project = os.environ.get("JIRA_PROJECT", "SOC")
        self.outbox = outbox or Path("evidence/jira_outbox.jsonl")

    @property
    def live(self) -> bool:
        return bool(self.base_url and self.email and self.token)

    def create_issue(self, summary: str, description: str, labels: list[str]) -> str:
        payload = {
            "fields": {
                "project": {"key": self.project},
                "summary": summary[:250],
                "description": description,
                "issuetype": {"name": "Incident"},
                "labels": labels,
            }
        }
        if not self.live:
            self.outbox.parent.mkdir(parents=True, exist_ok=True)
            with self.outbox.open("a") as handle:
                handle.write(json.dumps(payload) + "\n")
            return f"LOCAL-{sum(1 for _ in self.outbox.open())}"

        request = urllib.request.Request(
            f"{self.base_url}/rest/api/3/issue",
            data=json.dumps(payload).encode(),
            headers={
                "content-type": "application/json",
                "authorization": "Basic "
                + __import__("base64").b64encode(f"{self.email}:{self.token}".encode()).decode(),
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                body = json.loads(response.read())
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"jira create failed: {exc}") from exc
        return str(body.get("key", "UNKNOWN"))


@dataclass
class Ticket:
    ticket_id: str
    incident: Incident
    recommendation: dict
    state: str = "awaiting_approval"
    approver: str | None = None
    issue_key: str | None = None

    def as_dict(self) -> dict:
        return {
            "ticket_id": self.ticket_id,
            "state": self.state,
            "approver": self.approver,
            "issue_key": self.issue_key,
            "approval_required": self.recommendation["approval_required"],
            "actions": self.recommendation["actions"],
            "incident": self.incident.as_dict(),
        }
