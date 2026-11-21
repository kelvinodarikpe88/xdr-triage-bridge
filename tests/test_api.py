import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
KEY = {"x-api-key": "test-key"}


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


def incident(name: str = "incident_high.json") -> dict:
    return json.loads((FIXTURES / name).read_text())


def test_incidents_need_a_key(client):
    assert client.post("/v1/incidents", json={"incident": incident()}).status_code == 401


def test_high_incident_opens_a_pending_ticket(client):
    response = client.post("/v1/incidents", headers=KEY, json={"incident": incident()})
    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "awaiting_approval"
    assert body["approval_required"] is True
    assert body["issue_key"] is None
    assert body["summary_source"] == "template"


def test_agent_cannot_approve_its_own_recommendation(client):
    ticket = client.post(
        "/v1/incidents", headers=KEY, json={"incident": incident()}
    ).json()
    response = client.post(
        f"/v1/tickets/{ticket['ticket_id']}/approve",
        headers=KEY,
        json={"approver": "agent"},
    )
    assert response.status_code == 403


def test_a_named_human_approves_and_the_issue_is_created(client):
    ticket = client.post(
        "/v1/incidents", headers=KEY, json={"incident": incident()}
    ).json()
    response = client.post(
        f"/v1/tickets/{ticket['ticket_id']}/approve",
        headers=KEY,
        json={"approver": "kelvin.odarikpe"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "approved"
    assert body["approver"] == "kelvin.odarikpe"
    assert body["issue_key"].startswith("LOCAL-")


def test_approval_is_idempotent(client):
    ticket = client.post(
        "/v1/incidents", headers=KEY, json={"incident": incident()}
    ).json()
    first = client.post(
        f"/v1/tickets/{ticket['ticket_id']}/approve",
        headers=KEY,
        json={"approver": "kelvin"},
    ).json()
    second = client.post(
        f"/v1/tickets/{ticket['ticket_id']}/approve",
        headers=KEY,
        json={"approver": "kelvin"},
    ).json()
    assert first["issue_key"] == second["issue_key"]


def test_low_incident_requires_no_approval_but_still_is_not_auto_filed(client):
    response = client.post(
        "/v1/incidents", headers=KEY, json={"incident": incident("incident_low.json")}
    )
    body = response.json()
    assert body["approval_required"] is False
    assert body["state"] == "awaiting_approval"
    assert body["issue_key"] is None


def test_unknown_ticket_is_404(client):
    assert client.get("/v1/tickets/T-9999", headers=KEY).status_code == 404


def test_malformed_incident_is_422(client):
    response = client.post("/v1/incidents", headers=KEY, json={"incident": {"foo": "bar"}})
    assert response.status_code == 422
