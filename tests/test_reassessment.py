"""Unit tests for Step 5: Reassessment Loop.

Verifies:
- Reassessment contract and structure (Reassessment model, status="revised")
- B2 conflict resolution: HOLD_FOR_EVIDENCE -> ALLOW on analyst out-of-band verification
- B3 conflict resolution: HOLD_FOR_EVIDENCE -> ALLOW / CONFIRM on analyst verification
- Malicious indicator injection flipping SAFE -> BLOCK / CONFIRM
- Audit trail preserves trace history and appends 'revised' events
- Validation: cannot reassess without prior ledger/risk/parsed state
"""

import pytest
import evidence as ev
from orchestrator import Orchestrator
from schemas import EvidenceItem, Reassessment, Source
import seed_data as sd


def test_reassessment_contract_and_structure():
    orch = Orchestrator()
    email = sd.email_by_id("N1")
    initial_res = orch.process(email, sentinel_enabled=True)

    new_item = EvidenceItem(
        id="E_test_note",
        claim="Secondary analyst reviewed and corroborated benign intent",
        tool="analyst",
        direction="SUPPORTS_BENIGN",
        weight=0.5,
        confidence=0.9,
        raw={"reviewer": "analyst_42"},
    )

    reassessment, revised_res = orch.reassess(
        previous_result=initial_res,
        new_evidence=new_item,
        trigger="analyst_peer_review",
    )

    assert isinstance(reassessment, Reassessment)
    assert reassessment.run_id == initial_res.run_id
    assert reassessment.trigger == "analyst_peer_review"
    assert "Level unchanged" in reassessment.what_changed or "score" in reassessment.what_changed
    assert reassessment.previous.level == initial_res.risk.level
    assert reassessment.revised.level == revised_res.risk.level

    # Trace event verification
    assert len(revised_res.traces) == len(initial_res.traces) + 1
    last_trace = revised_res.traces[-1]
    assert last_trace.stage == "REASSESSMENT"
    assert last_trace.agent == "risk_assessor"
    assert last_trace.status == "revised"
    assert last_trace.payload["trigger"] == "analyst_peer_review"
    assert "what_changed" in last_trace.payload


def test_b2_reassessment_flips_hold_to_allow():
    """Seed email B2: Conflicting reply-to address and young domain.
    Initial: INSUFFICIENT_EVIDENCE -> HOLD_FOR_EVIDENCE under P-06.
    Reassessment with OOB phone verification: SAFE -> ALLOW.
    """
    orch = Orchestrator()
    b2 = sd.email_by_id("B2")
    initial_res = orch.process(b2, sentinel_enabled=True)

    # Verify baseline state
    assert initial_res.decision.verdict == "HOLD_FOR_EVIDENCE"
    assert initial_res.decision.rule_id == "P-06"
    assert initial_res.risk.level == "INSUFFICIENT_EVIDENCE"

    # Inject analyst out-of-band verification
    oob_item = EvidenceItem(
        id="E_oob_b2",
        claim="SecOps called vendor directory phone number; contact confirmed email was authentic",
        tool="analyst",
        direction="SUPPORTS_BENIGN",
        weight=0.9,
        confidence=0.95,
        raw={"kind": "out_of_band_verification", "method": "phone_call", "caller": "secops_lead"},
    )

    reassessment, revised_res = orch.reassess(
        previous_result=initial_res,
        new_evidence=oob_item,
        trigger="oob_analyst_call",
    )

    # Verify reassessment outcome
    assert reassessment.previous_decision.verdict == "HOLD_FOR_EVIDENCE"
    assert reassessment.revised_decision.verdict == "ALLOW"
    assert revised_res.decision.verdict == "ALLOW"
    assert revised_res.risk.level == "SAFE"
    assert revised_res.risk.score < 35.0

    # Ensure status was emitted as revised
    revised_trace = revised_res.traces[-1]
    assert revised_trace.status == "revised"
    assert revised_trace.payload["previous_verdict"] == "HOLD_FOR_EVIDENCE"
    assert revised_trace.payload["revised_verdict"] == "ALLOW"


def test_b3_reassessment_flips_hold_to_allow():
    """Seed email B3: Colleague display name but personal gmail address.
    Initial: INSUFFICIENT_EVIDENCE -> HOLD_FOR_EVIDENCE under P-06.
    Reassessment with OOB verification: SAFE -> ALLOW.
    """
    orch = Orchestrator()
    b3 = sd.email_by_id("B3")
    initial_res = orch.process(b3, sentinel_enabled=True)

    assert initial_res.decision.verdict == "HOLD_FOR_EVIDENCE"
    assert initial_res.decision.rule_id == "P-06"
    assert initial_res.risk.level == "INSUFFICIENT_EVIDENCE"

    oob_item = EvidenceItem(
        id="E_oob_b3",
        claim="Confirmed via internal Teams chat that colleague is sending from personal account while traveling",
        tool="analyst",
        direction="SUPPORTS_BENIGN",
        weight=0.9,
        confidence=0.95,
        raw={"kind": "out_of_band_verification", "channel": "internal_teams"},
    )

    reassessment, revised_res = orch.reassess(
        previous_result=initial_res,
        new_evidence=oob_item,
        trigger="teams_chat_confirmation",
    )

    assert reassessment.previous_decision.verdict == "HOLD_FOR_EVIDENCE"
    assert reassessment.revised_decision.verdict in ("ALLOW", "CONFIRM")
    assert revised_res.risk.level == "SAFE"


def test_reassessment_with_conflicting_and_decisive_malicious_evidence():
    """Injecting malicious evidence into an innocent email:
    1. Single conflicting threat item creates a contradiction -> INSUFFICIENT_EVIDENCE.
    2. Decisive threat intelligence (breaking conflict margin) flips level to MALICIOUS.
    """
    orch = Orchestrator()
    n1 = sd.email_by_id("N1")
    initial_res = orch.process(n1, sentinel_enabled=True)

    assert initial_res.decision.verdict == "ALLOW"
    assert initial_res.risk.level == "SAFE"

    # Single threat intel item conflicts with existing benign evidence
    intel_item1 = EvidenceItem(
        id="E_threat_intel_1",
        claim="Threat intelligence feed: sending domain compromised and hosting active C2 payload",
        tool="analyst",
        direction="SUPPORTS_MALICIOUS",
        weight=0.95,
        confidence=0.99,
        raw={"feed": "virustotal_live", "threat": "c2_beacon"},
    )

    reassess1, res1 = orch.reassess(
        previous_result=initial_res,
        new_evidence=intel_item1,
        trigger="threat_intel_alert",
    )

    # Both masses are ~0.94 with net difference < 1.0 nats: correctly enters INSUFFICIENT_EVIDENCE
    assert res1.risk.level == "INSUFFICIENT_EVIDENCE"
    assert any("disagree" in q for q in res1.risk.open_questions)
    assert res1.ledger.contradictions

    # Now second corroborating report arrives: account credentials leaked and confirmed active attack
    intel_item2 = EvidenceItem(
        id="E_threat_intel_2",
        claim="SOC incident report: account credentials compromised in active credential stuffing campaign",
        tool="analyst",
        direction="SUPPORTS_MALICIOUS",
        weight=0.95,
        confidence=0.99,
        raw={"incident_id": "INC-9901"},
    )

    reassess2, res2 = orch.reassess(
        previous_result=res1,
        new_evidence=intel_item2,
        trigger="soc_incident_corroboration",
    )

    # Malicious mass now heavily outweighs benign evidence (> margin)
    assert res2.risk.level == "MALICIOUS"
    assert res2.risk.score >= 70.0
    assert "MALICIOUS" in reassess2.what_changed



def test_reassessment_requires_valid_previous_result():
    orch = Orchestrator()
    from orchestrator import OrchestratorResult

    invalid_res = OrchestratorResult(
        run_id="run-empty",
        sentinel_enabled=True,
        email_id="dummy",
        parsed=None,
        ledger=None,
        risk=None,
    )
    with pytest.raises(ValueError, match="Cannot reassess"):
        orch.reassess(
            previous_result=invalid_res,
            new_evidence=EvidenceItem(
                id="x", claim="c", tool="analyst", direction="SUPPORTS_BENIGN", weight=0.5, confidence=0.8
            ),
        )


def test_multiple_reassessments_append_history():
    orch = Orchestrator()
    b2 = sd.email_by_id("B2")
    res0 = orch.process(b2, sentinel_enabled=True)
    assert len(res0.traces) == 9

    # Reassessment 1
    ev1 = EvidenceItem(
        id="E_step1",
        claim="First note: domain checked on WHOIS",
        tool="analyst",
        direction="NEUTRAL",
        weight=0.1,
        confidence=0.5,
    )
    _, res1 = orch.reassess(res0, ev1, trigger="step1")
    assert len(res1.traces) == 10
    assert res1.traces[-1].status == "revised"

    # Reassessment 2
    ev2 = EvidenceItem(
        id="E_step2",
        claim="Second note: out of band phone call confirmed sender",
        tool="analyst",
        direction="SUPPORTS_BENIGN",
        weight=0.9,
        confidence=0.95,
        raw={"kind": "out_of_band_verification"},
    )
    _, res2 = orch.reassess(res1, ev2, trigger="step2")
    assert len(res2.traces) == 11
    assert res2.traces[-1].status == "revised"
    assert res2.decision.verdict == "ALLOW"
