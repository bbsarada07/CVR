"""Proof at the tool boundary: a blocked action never reaches the tool function or the ledger."""

import pytest
from fastapi.testclient import TestClient

import ledger
from main import app
from orchestrator import Orchestrator
from seed_data import email_by_id


@pytest.fixture
def orch():
    return Orchestrator()


def test_a1_protection_on_leaves_ledger_unchanged(orch, capsys):
    before = ledger.size()
    res = orch.process(email_by_id("A1"), sentinel_enabled=True)
    out = capsys.readouterr().out

    assert res.verdict == "BLOCK"
    assert ledger.size() == before
    assert not ledger.has_run(res.run_id)
    assert f"NOT EXECUTED  run={res.run_id}  update_payment_details  refused by {res.rule_id}" in out
    assert "EXECUTED  run=" not in out.replace("NOT EXECUTED", "")


def test_a1_protection_off_adds_one_ledger_entry(orch, capsys):
    before = ledger.size()
    res = orch.process(email_by_id("A1"), sentinel_enabled=False)
    out = capsys.readouterr().out

    assert ledger.size() == before + 1
    entry = ledger.entries()[-1]
    assert entry["run_id"] == res.run_id
    assert entry["tool"] == "update_payment_details"
    assert f"EXECUTED  run={res.run_id}  update_payment_details(" in out


def test_confirm_runs_tool_once_and_refuses_blocked_runs():
    client = TestClient(app)
    b1 = client.post("/api/process", json={"email_id": "B1", "sentinel_enabled": True}).json()["result"]
    before = ledger.size()
    body = {"run_id": b1["run_id"], "confirmed": True}
    assert client.post("/api/confirm", json=body).status_code == 200
    assert client.post("/api/confirm", json=body).status_code == 200
    assert ledger.size() == before + 1

    a1 = client.post("/api/process", json={"email_id": "A1", "sentinel_enabled": True}).json()["result"]
    before = ledger.size()
    r = client.post("/api/confirm", json={"run_id": a1["run_id"], "confirmed": True})
    assert r.status_code == 409
    assert ledger.size() == before
    assert client.get("/api/ledger").json()["count"] == ledger.size()
