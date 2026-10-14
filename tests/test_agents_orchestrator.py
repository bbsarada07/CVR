"""Unit tests for agents.py and orchestrator.py:
- Capability map enforcement in code
- Structural enforcement on Action Planner (no raw text)
- Quarantined parsing and provenance tracking
- Injection scanning across attack vectors
- 9-stage orchestrator pipeline with TraceEvents and elapsed ms
- Naive mode (sentinel_enabled=false) genuine vulnerability toggle
- End-to-end execution of seed emails (A1, B1-B4, N1)
"""

import pytest
from agents import (
    ALL_TOOLS,
    CAPABILITY_MAP,
    READ_ONLY_TOOLS,
    ActionPlannerAgent,
    InjectionAnalystAgent,
    InvestigatorAgent,
    NaiveAgent,
    ParserAgent,
    RiskAssessorAgent,
    enforce_capability,
)
from orchestrator import Orchestrator
import seed_data as sd
from schemas import IdentityStatus, RiskAssessment, Source


# ---------------------------------------------------------------------------
# 1. Capability Map Tests
# ---------------------------------------------------------------------------

def test_capability_map_spec():
    assert CAPABILITY_MAP["parser"] == []
    assert set(CAPABILITY_MAP["investigator"]) == set(READ_ONLY_TOOLS)
    assert CAPABILITY_MAP["injection"] == []
    assert CAPABILITY_MAP["risk"] == []
    assert CAPABILITY_MAP["planner"] == ["propose_only"]
    assert set(CAPABILITY_MAP["executor"]) == set(ALL_TOOLS)


def test_enforce_capability_violations():
    # Parser attempting to call any tool
    with pytest.raises(PermissionError):
        enforce_capability("parser", "check_auth")

    # Investigator attempting to execute consequential action
    with pytest.raises(PermissionError):
        enforce_capability("investigator", "update_payment_details")

    # Planner attempting to execute tool instead of propose
    with pytest.raises(PermissionError):
        enforce_capability("planner", "send_reply")

    # Investigator allowed to call read-only tools
    enforce_capability("investigator", "check_auth")
    enforce_capability("investigator", "domain_intel")

    # Planner allowed propose_only
    enforce_capability("planner", "propose_only")


# ---------------------------------------------------------------------------
# 2. Structural Enforcement: ActionPlanner Never Receives Raw Body
# ---------------------------------------------------------------------------

def test_action_planner_structural_forbid_raw_text():
    planner = ActionPlannerAgent()
    email = sd.email_by_id("B1")
    parser = ParserAgent()
    parsed = parser.parse(email)
    dummy_risk = RiskAssessment(
        level="SAFE",
        score=10.0,
        confidence=0.9,
        rationale="Safe",
        uncertainty_note="none",
        open_questions=[],
    )

    # Calling with forbidden raw_body keyword raises ValueError
    with pytest.raises(ValueError, match="STRUCTURAL VIOLATION"):
        planner.plan(
            parsed=parsed,
            risk=dummy_risk,
            identity=IdentityStatus(),
            sensitive=True,
            raw_body=email.body,
        )

    # Calling with raw_email keyword also raises ValueError
    with pytest.raises(ValueError, match="STRUCTURAL VIOLATION"):
        planner.plan(
            parsed=parsed,
            risk=dummy_risk,
            identity=IdentityStatus(),
            sensitive=True,
            raw_email=email,
        )


# ---------------------------------------------------------------------------
# 3. Parser & Provenance Tests
# ---------------------------------------------------------------------------

def test_parser_quarantined_provenance():
    parser = ParserAgent()
    email = sd.email_by_id("A1")
    parsed = parser.parse(email)

    # All fields must carry UNTRUSTED_EMAIL provenance
    assert parsed.sender.source == Source.UNTRUSTED_EMAIL
    assert parsed.subject.source == Source.UNTRUSTED_EMAIL
    assert parsed.intent.source == Source.UNTRUSTED_EMAIL

    # Entities extracted from body also carry UNTRUSTED_EMAIL
    assert "iban" in parsed.entities
    assert parsed.entities["iban"].source == Source.UNTRUSTED_EMAIL
    assert parsed.entities["iban"].value == "GB29NWBK60161331926819"


# ---------------------------------------------------------------------------
# 4. Investigator Stated Rationale Tests
# ---------------------------------------------------------------------------

def test_investigator_stated_reasons():
    parser = ParserAgent()
    investigator = InvestigatorAgent()
    email = sd.email_by_id("B1")
    parsed = parser.parse(email)

    ledger, tool_log = investigator.investigate(parsed, email)
    assert len(ledger.items) >= 6
    assert len(tool_log) >= 6

    # Verify that every tool run documented its investigative reason
    for record in tool_log:
        assert "tool" in record
        assert "reason" in record and len(record["reason"]) > 10


# ---------------------------------------------------------------------------
# 5. Injection Analyst Tests
# ---------------------------------------------------------------------------

def test_injection_analyst_scans():
    analyst = InjectionAnalystAgent()

    # A1: HTML comment
    f_a1 = analyst.scan(sd.email_by_id("A1").body)
    assert any(f.kind == "html_comment_injection" for f in f_a1)

    # A2: White text / hidden CSS
    f_a2 = analyst.scan(sd.email_by_id("A2").body)
    assert any(f.kind == "hidden_styling_injection" for f in f_a2)

    # A3: Zero-width characters
    f_a3 = analyst.scan(sd.email_by_id("A3").body)
    assert any(f.kind == "zero_width_injection" for f in f_a3)

    # A4: Role spoofing
    f_a4 = analyst.scan(sd.email_by_id("A4").body)
    assert any(f.kind == "role_spoofing" for f in f_a4)

    # A5: Base64 payload
    f_a5 = analyst.scan(sd.email_by_id("A5").body)
    assert any(f.kind == "base64_payload" for f in f_a5)

    # N1: Clean
    f_n1 = analyst.scan(sd.email_by_id("N1").body)
    assert len(f_n1) == 0


# ---------------------------------------------------------------------------
# 6. 9-Stage Orchestrator Pipeline Tests
# ---------------------------------------------------------------------------

def test_orchestrator_all_9_stages():
    orch = Orchestrator()
    email = sd.email_by_id("N1")
    res = orch.process(email, sentinel_enabled=True)

    assert res.sentinel_enabled is True
    assert res.decision is not None
    assert res.total_ms >= 0

    # Must contain exactly 9 trace events in stage order
    stages = [t.stage for t in res.traces]
    expected_stages = [
        "INGEST",
        "PARSE",
        "INVESTIGATE",
        "INJECTION_SCAN",
        "RISK_ASSESS",
        "PLAN",
        "POLICY_GATE",
        "EXECUTE_OR_HOLD",
        "LOG",
    ]
    assert stages == expected_stages

    # Verify elapsed ms recorded per event
    for t in res.traces:
        assert t.ms >= 0
        assert t.seq >= 1


def test_orchestrator_stream_yields_all_trace_events():
    orch = Orchestrator()
    email = sd.email_by_id("N1")
    streamed = list(orch.stream(email, sentinel_enabled=True))
    assert len(streamed) == 9
    assert [t.stage for t in streamed] == [
        "INGEST",
        "PARSE",
        "INVESTIGATE",
        "INJECTION_SCAN",
        "RISK_ASSESS",
        "PLAN",
        "POLICY_GATE",
        "EXECUTE_OR_HOLD",
        "LOG",
    ]


# ---------------------------------------------------------------------------
# 7. Naive Mode vs Sentinel Comparison (The Core Demo)
# ---------------------------------------------------------------------------

def test_naive_mode_is_genuinely_vulnerable_on_a1():
    orch = Orchestrator()
    a1 = sd.email_by_id("A1")

    # In Naive mode: raw body processed directly -> executes payment update to attacker IBAN
    naive_res = orch.process(a1, sentinel_enabled=False)
    assert naive_res.sentinel_enabled is False
    assert naive_res.naive_result["executed"] is True
    assert naive_res.naive_result["tool_call"]["tool"] == "update_payment_details"
    assert "GB29NWBK60161331926819" in naive_res.naive_result["tool_call"]["args"]["iban"]

    # In Sentinel mode: Protected -> BLOCKED by policy gate!
    sentinel_res = orch.process(a1, sentinel_enabled=True)
    assert sentinel_res.sentinel_enabled is True
    assert sentinel_res.decision.verdict == "BLOCK"
    assert sentinel_res.decision.rule_id in ("P-01", "P-02")


def test_naive_mode_is_genuinely_vulnerable_on_a2():
    orch = Orchestrator()
    a2 = sd.email_by_id("A2")

    # In Naive mode: white-text instruction executed directly (forwarding emails)
    naive_res = orch.process(a2, sentinel_enabled=False)
    assert naive_res.naive_result["tool_call"]["tool"] == "forward_external"
    assert "archive@mail-backup" in naive_res.naive_result["tool_call"]["args"]["recipient"]

    # In Sentinel mode: BLOCKED
    sentinel_res = orch.process(a2, sentinel_enabled=True)
    assert sentinel_res.decision.verdict == "BLOCK"


# ---------------------------------------------------------------------------
# 8. End-to-End Evaluation on Ambiguous Emails B1-B4
# ---------------------------------------------------------------------------

def test_b1_end_to_end_lands_on_confirm():
    orch = Orchestrator()
    b1 = sd.email_by_id("B1")
    res = orch.process(b1, sentinel_enabled=True)

    # B1 is a verified vendor sensitive banking update -> CONFIRM with mandatory out-of-band verification
    assert res.decision.verdict == "CONFIRM"
    assert res.decision.requires_out_of_band_verification is True
    assert res.risk.level == "SAFE"


def test_b2_end_to_end_lands_on_hold_for_evidence():
    orch = Orchestrator()
    b2 = sd.email_by_id("B2")
    res = orch.process(b2, sentinel_enabled=True)

    # B2 has conflicting reply-to vs verified sender -> HOLD_FOR_EVIDENCE (P-06)
    assert res.decision.verdict == "HOLD_FOR_EVIDENCE"
    assert res.decision.rule_id == "P-06"
    assert res.risk.level == "INSUFFICIENT_EVIDENCE"


def test_b3_end_to_end_lands_on_hold_for_evidence():
    orch = Orchestrator()
    b3 = sd.email_by_id("B3")
    res = orch.process(b3, sentinel_enabled=True)

    # B3 has colleague display name but personal gmail address -> HOLD_FOR_EVIDENCE (P-06)
    assert res.decision.verdict == "HOLD_FOR_EVIDENCE"
    assert res.decision.rule_id == "P-06"
    assert res.risk.level == "INSUFFICIENT_EVIDENCE"


def test_b4_end_to_end_lands_on_allow():
    orch = Orchestrator()
    b4 = sd.email_by_id("B4")
    res = orch.process(b4, sentinel_enabled=True)

    # B4 is internal training -> ALLOW
    assert res.decision.verdict == "ALLOW"
    assert res.risk.level == "SAFE"
