import math

import pytest
from pydantic import ValidationError

import evidence as ev
from schemas import EvidenceItem, RiskAssessment

MAL, BEN, NEU = "SUPPORTS_MALICIOUS", "SUPPORTS_BENIGN", "NEUTRAL"


def ledger_of(*specs):
    led = ev.new_ledger()
    for tool, direction, w, c, raw in specs:
        ev.record(led, claim=f"{tool} {direction}", tool=tool, direction=direction, weight=w, confidence=c, raw=raw)
    return led


def phishing_ledger():
    return ledger_of(
        ("check_auth", MAL, 0.6, 0.95, {"spf": "fail", "dkim": "fail", "dmarc": "fail"}),
        ("lookup_contact", MAL, 0.5, 0.9, {"known": False}),
        ("domain_intel", MAL, 0.7, 0.9, {}),
        ("analyze_links", MAL, 0.7, 0.9, {}),
    )


def benign_ledger():
    return ledger_of(
        ("check_auth", BEN, 0.4, 0.95, {"spf": "pass", "dkim": "pass", "dmarc": "pass"}),
        ("lookup_contact", BEN, 0.6, 0.9, {"known": True, "verified": True, "address_matches": True, "display_name_matches": True}),
        ("thread_history", BEN, 0.5, 0.9, {"has_thread": True, "fits_thread": True, "escalation": False}),
        ("domain_intel", BEN, 0.4, 0.9, {}),
    )


def conflict_ledger():
    # B2 shape: auth passes, contact known, but reply-to differs and domain is 6 days old.
    return ledger_of(
        ("check_auth", BEN, 0.3, 0.9, {"spf": "pass", "dkim": "pass", "dmarc": "pass"}),
        ("lookup_contact", BEN, 0.5, 0.9, {"known": True, "verified": True, "address_matches": False, "display_name_matches": True}),
        ("check_auth", MAL, 0.6, 0.9, {"spf": "pass", "dkim": "pass", "dmarc": "pass", "reply_to_differs": True}),
        ("domain_intel", MAL, 0.6, 0.9, {"age_days": 6}),
    )


# ---------------------------------------------------------------- math

def test_strength_and_nats():
    item = EvidenceItem(id="x", claim="c", tool="t", direction=MAL, weight=0.5, confidence=0.8)
    assert ev.strength(item) == pytest.approx(0.4)
    assert ev.to_nats(0.4) == pytest.approx(-math.log(0.6))
    assert ev.mass(ev.to_nats(0.4)) == pytest.approx(0.4)


def test_strength_capped_so_nats_stay_finite():
    item = EvidenceItem(id="x", claim="c", tool="t", direction=MAL, weight=1.0, confidence=1.0)
    assert ev.strength(item) == ev.S_CAP
    assert math.isfinite(ev.to_nats(ev.strength(item)))


def test_nats_add_like_noisy_or():
    s1, s2 = 0.3, 0.5
    combined = ev.mass(ev.to_nats(s1) + ev.to_nats(s2))
    assert combined == pytest.approx(1 - (1 - s1) * (1 - s2))


def test_score_is_order_independent():
    a = phishing_ledger()
    b = ev.new_ledger()
    for item in reversed(a.items):
        ev.add(b, item)
    assert ev.assess(a).score == ev.assess(b).score


def test_score_monotone_in_malicious_evidence():
    led = benign_ledger()
    prev = ev.assess(led).score
    for _ in range(4):
        ev.record(led, claim="more bad", tool="analyze_links", direction=MAL, weight=0.5, confidence=0.9)
        cur = ev.assess(led).score
        assert cur > prev
        prev = cur


def test_neutral_items_add_coverage_not_mass():
    led = ledger_of(("check_auth", MAL, 0.9, 0.9, {}), ("domain_intel", NEU, 0.9, 0.9, {}))
    before = ev.assess(led)
    assert before.level == "INSUFFICIENT_EVIDENCE"  # only 2 items
    ev.record(led, claim="n", tool="analyze_links", direction=NEU, weight=0.9, confidence=0.9)
    after = ev.assess(led)
    assert after.score == before.score
    assert after.level == "MALICIOUS"


# ---------------------------------------------------------- classification

def test_empty_ledger_is_insufficient_not_a_guess():
    ra = ev.assess(ev.new_ledger())
    assert ra.level == "INSUFFICIENT_EVIDENCE"
    assert ra.score == 50.0
    assert ra.open_questions


def test_too_few_items_is_insufficient_even_if_strong():
    ra = ev.assess(ledger_of(("check_auth", MAL, 0.9, 0.95, {}), ("domain_intel", MAL, 0.9, 0.95, {})))
    assert ra.level == "INSUFFICIENT_EVIDENCE"
    assert "at least 3" in ra.rationale


def test_weak_evidence_is_insufficient():
    ra = ev.assess(ledger_of(
        ("check_auth", MAL, 0.1, 0.9, {}), ("domain_intel", BEN, 0.1, 0.9, {}), ("analyze_links", MAL, 0.1, 0.9, {}),
    ))
    assert ra.level == "INSUFFICIENT_EVIDENCE"
    assert "nothing is decisive" in ra.rationale


def test_phishing_is_malicious_and_cites_ids():
    led = phishing_ledger()
    ra = ev.assess(led)
    assert ra.level == "MALICIOUS"
    assert ra.score >= ev.MALICIOUS_MIN
    assert ra.key_evidence_ids
    ids = {it.id for it in led.items}
    assert set(ra.key_evidence_ids) <= ids
    for eid in ra.key_evidence_ids:
        assert eid in ra.rationale
    assert ra.open_questions == []


def test_benign_is_safe():
    ra = ev.assess(benign_ledger())
    assert ra.level == "SAFE"
    assert ra.score < ev.SAFE_MAX


def test_moderate_lean_is_suspicious():
    ra = ev.assess(ledger_of(
        ("check_auth", MAL, 0.5, 0.9, {}), ("domain_intel", NEU, 0.5, 0.9, {}), ("analyze_links", NEU, 0.5, 0.9, {}),
    ))
    assert ra.level == "SUSPICIOUS"


def test_conflict_yields_insufficient_with_pairs_and_questions():
    led = conflict_ledger()
    ra = ev.assess(led)
    assert ra.level == "INSUFFICIENT_EVIDENCE"
    assert "contradictory" in ra.rationale or "refusing to force" in ra.rationale
    assert led.contradictions, "conflicting items must be paired for the UI"
    assert any("disagree" in q for q in ra.open_questions)
    assert 0.0 <= ra.confidence <= 1.0


def test_dominant_side_is_not_contradictory():
    # Both masses above threshold, but benign side dominates by > margin.
    led = ledger_of(
        ("check_auth", BEN, 0.9, 0.95, {}), ("lookup_contact", BEN, 0.9, 0.95, {}),
        ("thread_history", BEN, 0.8, 0.95, {}), ("check_sensitive_request", MAL, 0.5, 0.9, {}),
    )
    ra = ev.assess(led)
    assert ra.malicious_mass >= ev.CONFLICT_MASS
    assert ra.level == "SAFE"


def test_schema_refuses_insufficient_without_questions():
    with pytest.raises(ValidationError):
        RiskAssessment(level="INSUFFICIENT_EVIDENCE", score=50, confidence=0.5, rationale="r", uncertainty_note="u")


def test_weight_out_of_range_rejected():
    with pytest.raises(ValidationError):
        EvidenceItem(id="x", claim="c", tool="t", direction=MAL, weight=1.5, confidence=0.5)


# ----------------------------------------------------------- uncertainty

def test_band_contains_score():
    for led in (phishing_ledger(), benign_ledger(), conflict_ledger()):
        ra = ev.assess(led)
        lo, hi = ra.score_band
        assert lo <= ra.score <= hi


def test_full_confidence_gives_point_band_and_certainty():
    led = ledger_of(("check_auth", MAL, 0.6, 1.0, {}), ("domain_intel", MAL, 0.6, 1.0, {}), ("analyze_links", MAL, 0.6, 1.0, {}))
    ra = ev.assess(led)
    assert ra.score_band[0] == ra.score_band[1] == ra.score
    assert ra.confidence == 1.0


def test_lower_confidence_widens_band():
    sure = ev.assess(ledger_of(*[("check_auth", MAL, 0.6, 0.99, {})] * 4))
    unsure = ev.assess(ledger_of(*[("check_auth", MAL, 0.6, 0.6, {})] * 4))
    width = lambda r: r.score_band[1] - r.score_band[0]
    assert width(unsure) > width(sure)
    assert unsure.confidence < sure.confidence


def test_deterministic_including_monte_carlo_path():
    specs = [("analyze_links", MAL if i % 2 else BEN, 0.4, 0.7, {}) for i in range(ev.EXACT_MAX + 3)]
    a, b = ev.assess(ledger_of(*specs)), ev.assess(ledger_of(*specs))
    assert a.model_dump() == b.model_dump()


# ------------------------------------------------------------ ledger

def test_record_assigns_sequential_ids_and_rejects_duplicates():
    led = ev.new_ledger()
    e1 = ev.record(led, claim="a", tool="t", direction=NEU, weight=0.1, confidence=0.1)
    e2 = ev.record(led, claim="b", tool="t", direction=NEU, weight=0.1, confidence=0.1)
    assert (e1.id, e2.id) == ("E1", "E2")
    with pytest.raises(ValueError):
        ev.add(led, e1)


def test_contradictions_only_pair_same_subject():
    led = ledger_of(("analyze_links", MAL, 0.8, 0.9, {}), ("check_auth", BEN, 0.8, 0.9, {}))
    assert led.contradictions == []  # payload vs sender: not the same question
    ev.record(led, claim="known", tool="lookup_contact", direction=MAL, weight=0.8, confidence=0.9)
    assert ("E3", "E2") in led.contradictions


def test_analyst_evidence_can_conflict_with_anything():
    led = ledger_of(("analyze_links", BEN, 0.8, 0.9, {}))
    ev.record(led, claim="confirmed bad", tool="analyst", direction=MAL, weight=0.8, confidence=0.9)
    assert led.contradictions == [("E2", "E1")]


# ---------------------------------------------------------- reassessment

def test_reassessment_resolves_conflict_with_oob_verification():
    led = conflict_ledger()
    before = ev.assess(led)
    assert before.level == "INSUFFICIENT_EVIDENCE"
    new = ev.record(led, claim="Sender verified by phone using number on file", tool="analyst",
                    direction=BEN, weight=0.9, confidence=1.0, raw={"kind": "out_of_band_verification"})
    after = ev.assess(led)
    assert after.level == "SAFE"
    assert len(led.items) == 5  # nothing removed
    diff = ev.diff_assessments(before, after, [new])
    assert "INSUFFICIENT_EVIDENCE -> SAFE" in diff and new.id in diff


def test_reassessment_flips_safe_to_malicious_on_strong_new_evidence():
    led = benign_ledger()
    assert ev.assess(led).level == "SAFE"
    ev.record(led, claim="Domain confirmed malicious", tool="analyst", direction=MAL, weight=1.0, confidence=1.0)
    assert ev.assess(led).level == "MALICIOUS"


def test_weak_contrary_evidence_produces_uncertainty_not_flip():
    led = benign_ledger()
    ev.record(led, claim="Unconfirmed report", tool="analyst", direction=MAL, weight=0.85, confidence=0.9)
    assert ev.assess(led).level == "INSUFFICIENT_EVIDENCE"


# ---------------------------------------------------------- derived facts

def test_identity_verified_from_tools():
    st = ev.identity_from_ledger(benign_ledger())
    assert st.verified and st.failures == []


def test_identity_fails_closed_when_tools_missing():
    st = ev.identity_from_ledger(ev.new_ledger())
    assert not st.verified
    assert "check_auth not run" in st.failures


def test_identity_address_mismatch_not_verified():
    st = ev.identity_from_ledger(conflict_ledger())
    assert not st.verified
    assert any("address" in f for f in st.failures)


def test_oob_verification_overrides_and_can_be_revoked():
    led = conflict_ledger()
    ev.record(led, claim="phone ok", tool="analyst", direction=BEN, weight=0.9, confidence=1.0, raw={"kind": "out_of_band_verification"})
    assert ev.identity_from_ledger(led).verified
    ev.record(led, claim="phone: did not send", tool="analyst", direction=MAL, weight=0.9, confidence=1.0, raw={"kind": "out_of_band_verification"})
    assert not ev.identity_from_ledger(led).verified


def test_no_thread_is_not_an_identity_failure():
    led = benign_ledger()
    ev.record(led, claim="no thread", tool="thread_history", direction=NEU, weight=0.1, confidence=0.9, raw={"has_thread": False})
    st = ev.identity_from_ledger(led)
    assert st.thread_consistent is None and st.verified


def test_sensitive_defaults_to_true_when_unchecked():
    assert ev.sensitive_from_ledger(ev.new_ledger())[0] is True
    led = ledger_of(("check_sensitive_request", NEU, 0.1, 0.9, {"sensitive": False, "categories": []}))
    assert ev.sensitive_from_ledger(led) == (False, [])
