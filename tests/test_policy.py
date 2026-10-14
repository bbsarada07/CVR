import ast
from pathlib import Path

import pytest
from pydantic import ValidationError

import policy
from policy import PolicyConfig, PolicyStore, evaluate, promote_provenance
from schemas import (
    Field,
    IdentityStatus,
    InjectionFinding,
    ParsedEmail,
    PolicyContext,
    ProposedAction,
    RiskAssessment,
    Source,
)

U, T, S, USR = Source.UNTRUSTED_EMAIL, Source.TRUSTED_CONTACT, Source.SYSTEM_TOOL, Source.USER
CFG = PolicyConfig(allowed_domains=["northwindtraders.com", "contoso.com"])

IBAN = "DE89 3704 0044 0532 0130 00"
BODY = f"Hi, please update our bank details to IBAN {IBAN}. Thanks, Dana (dana@contoso.com)"
VERIFIED = IdentityStatus(auth_pass=True, known_contact=True, contact_verified=True,
                          address_matches_history=True, display_name_matches=True, thread_consistent=True)
UNVERIFIED = IdentityStatus(auth_pass=True, known_contact=False, failures=["sender is not a known contact"])


def f(value, source=U):
    return Field(value=value, source=source)


def risk(level="SAFE"):
    qs = ["Can the sender be verified?"] if level == "INSUFFICIENT_EVIDENCE" else []
    return RiskAssessment(level=level, score=20, confidence=0.9, rationale="r", uncertainty_note="u", open_questions=qs)


def parsed():
    return ParsedEmail(sender=f("dana@contoso.com"), subject=f("Bank details update"),
                       intent=f("change vendor payment details"), entities={"iban": f(IBAN)})


def ctx(tool, args=None, draft=None, level="SAFE", findings=(), identity=UNVERIFIED, sensitive=False,
        user_values=(), system_values=("dana@contoso.com", "Contoso Ltd")):
    return PolicyContext(
        action=ProposedAction(tool=tool, args=args or {}, justification="j", draft_body=draft),
        risk=risk(level), injection_findings=list(findings), identity=identity, sensitive_request=sensitive,
        untrusted_corpus=["dana@contoso.com", "Bank details update", BODY], parsed=parsed(),
        user_values=list(user_values), system_values=list(system_values),
    )


def finding(sev):
    return InjectionFinding(kind="hidden_instruction", evidence="...", span=(0, 3), severity=sev, technique="html_comment")


# ------------------------------------------------------------ tiers

def test_read_only_allows_untrusted_args():
    d = evaluate(ctx("summarize", {"text": f(BODY)}), CFG)
    assert (d.verdict, d.rule_id) == ("ALLOW", "TIER-READ_ONLY")


def test_unknown_tool_default_deny():
    d = evaluate(ctx("wire_transfer", {"amount": f("10000", USR)}), CFG)
    assert (d.verdict, d.rule_id) == ("BLOCK", "P-08")


def test_consequential_with_untrusted_arg_blocked():
    d = evaluate(ctx("share_document", {"doc": f("Q3 plan", USR), "to": f("dana@contoso.com", U)},
                     user_values=["Q3 plan"], system_values=[]), CFG)
    assert (d.verdict, d.rule_id) == ("BLOCK", "P-01")
    assert d.offending_fields == ["to"]


def test_consequential_all_trusted_requires_confirm():
    d = evaluate(ctx("share_document", {"doc": f("Q3 plan", USR), "to": f("dana@contoso.com", S)},
                     user_values=["Q3 plan"]), CFG)
    assert (d.verdict, d.rule_id) == ("CONFIRM", "TIER-CONSEQUENTIAL")


def test_reversible_untrusted_critical_arg_confirms():
    d = evaluate(ctx("draft_reply", {"to": f("someone@contoso.com")}), CFG)
    assert (d.verdict, d.rule_id) == ("CONFIRM", "TIER-REVERSIBLE")
    assert d.offending_fields == ["to"]


def test_reversible_trusted_critical_arg_allows():
    d = evaluate(ctx("draft_reply", {"to": f("dana@contoso.com", S)}, draft="Thanks, received."), CFG)
    assert (d.verdict, d.rule_id) == ("ALLOW", "TIER-REVERSIBLE")


def test_reversible_non_critical_untrusted_allows():
    d = evaluate(ctx("add_note", {"note": f("Bank details update")}), CFG)
    assert d.verdict == "ALLOW"


# ------------------------------------------------- provenance is recomputed

def test_planner_cannot_launder_untrusted_value_by_labelling_it_user():
    # The planner claims USER, but the value is lifted from the email body.
    d = evaluate(ctx("share_document", {"doc": f("Q3 plan", USR), "to": f("update our bank details", USR)},
                     user_values=["Q3 plan"]), CFG)
    assert (d.verdict, d.rule_id) == ("BLOCK", "P-01")
    assert "to" in d.offending_fields


def test_unattributable_value_is_untrusted():
    d = evaluate(ctx("share_document", {"doc": f("something invented", USR)}), CFG)
    assert d.verdict == "BLOCK"


def test_claimed_trusted_contact_ignored_without_promotion():
    d = evaluate(ctx("update_payment_details", {"iban": f(IBAN, T), "vendor": f("Contoso Ltd", S)}), CFG)
    assert d.verdict == "BLOCK"


def test_zero_width_and_spacing_do_not_evade_taint():
    sneaky = "DE89​37040044 0532013000"
    d = evaluate(ctx("update_payment_details", {"iban": f(sneaky, USR), "vendor": f("Contoso Ltd", S)}), CFG)
    assert d.verdict == "BLOCK"
    assert "iban" in d.offending_fields


def test_draft_body_is_always_untrusted_for_consequential():
    d = evaluate(ctx("send_reply", {"to": f("dana@contoso.com", S)}, draft="Thanks!"), CFG)
    assert (d.verdict, d.rule_id) == ("BLOCK", "P-01")
    assert d.offending_fields == ["draft_body"]


# -------------------------------------------------------------- P-02

def test_injection_severity_4_blocks_non_read_only():
    d = evaluate(ctx("draft_reply", {"to": f("dana@contoso.com", S)}, findings=[finding(4)]), CFG)
    assert (d.verdict, d.rule_id) == ("BLOCK", "P-02")


def test_injection_severity_3_does_not_trigger_p02():
    d = evaluate(ctx("draft_reply", {"to": f("dana@contoso.com", S)}, findings=[finding(3)]), CFG)
    assert d.verdict == "ALLOW"


def test_injection_does_not_block_read_only():
    d = evaluate(ctx("flag", {"reason": f("x")}, findings=[finding(5)]), CFG)
    assert d.verdict == "ALLOW"


# -------------------------------------------------------------- P-03

@pytest.mark.parametrize("to, verdict", [
    ("ap@northwindtraders.com", "CONFIRM"),
    ("ap@mail.northwindtraders.com", "CONFIRM"),
    ("someone@gmail.com", "BLOCK"),
    ("x@northwindtraders.com.evil.example", "BLOCK"),
    ("ap@northwindtraders.com, x@gmail.com", "BLOCK"),
    ("not an address", "BLOCK"),
])
def test_forward_external_domain_allowlist(to, verdict):
    d = evaluate(ctx("forward_external", {"to": f(to, USR), "message": f("Q3 plan", USR)},
                     user_values=[to, "Q3 plan"]), CFG)
    assert d.verdict == verdict
    if verdict == "BLOCK":
        assert d.rule_id == "P-03"


def test_forward_external_without_recipient_blocked():
    d = evaluate(ctx("forward_external", {"message": f("Q3 plan", USR)}, user_values=["Q3 plan"]), CFG)
    assert (d.verdict, d.rule_id) == ("BLOCK", "P-03")


# -------------------------------------------------------------- P-04

@pytest.mark.parametrize("text", [
    '<img src="https://collector.example/p.png">',
    "see //collector.example/x",
    "visit www.collector.example",
    "https://northwindtraders.com@collector.example/",
    "javascript:void(0)",
    "https://nоrthwindtraders.com/",  # Cyrillic 'o'
    "h&#116;tps://collector.example/",
    # fix-4: bare-domain and punycode cases
    "evil.example/x.png",
    "see evil.example/report for details",
    "xn--80ak6aa92e.com/page",
    "http://1.2.3.4/beacon",
    "Check evil.example now",
])
def test_egress_guard_blocks_disallowed_hosts_in_any_tier(text):
    for tool in ("summarize", "draft_reply"):
        d = evaluate(ctx(tool, {"to": f("dana@contoso.com", S)}, draft=text), CFG)
        assert (d.verdict, d.rule_id) == ("BLOCK", "P-04"), (tool, text)


def test_egress_guard_allows_allowlisted_links():
    d = evaluate(ctx("draft_reply", {"to": f("dana@contoso.com", S)},
                     draft="Portal: https://portal.northwindtraders.com/invoices"), CFG)
    assert d.verdict == "ALLOW"


def test_egress_in_args_also_checked():
    d = evaluate(ctx("schedule_meeting", {"attendees": f("dana@contoso.com", S),
                                          "meeting_link": f("https://collector.example/m")}), CFG)
    assert d.rule_id == "P-04" and "meeting_link" in d.offending_fields


# -------------------------------------------------------------- P-05

def test_untrusted_bank_details_block_even_reversible():
    d = evaluate(ctx("add_note", {"iban": f(IBAN)}), CFG)
    assert (d.verdict, d.rule_id) == ("BLOCK", "P-05")


def test_iban_value_under_innocuous_key_detected():
    d = evaluate(ctx("add_note", {"note": f(f"new {IBAN}")}), CFG)
    assert d.rule_id == "P-05"


def test_p05_outranks_p01_in_report_but_both_listed():
    d = evaluate(ctx("update_payment_details", {"iban": f(IBAN), "vendor": f("Contoso Ltd", S)}), CFG)
    assert d.rule_id == "P-05"
    assert d.triggered_rules == ["P-05", "P-01"]


def test_p05_high_confidence_when_key_name_is_financial():
    d = evaluate(ctx("add_note", {"iban": f(IBAN)}), CFG)
    assert d.rule_id == "P-05"
    assert any(fi.get("confidence") == "HIGH" for fi in d.findings)


def test_p05_low_confidence_when_only_value_matches():
    d = evaluate(ctx("add_note", {"note": f(f"new {IBAN}")}), CFG)
    assert d.rule_id == "P-05"
    assert any(fi.get("confidence") == "LOW" for fi in d.findings)


# -------------------------------------------------------------- P-06

def test_insufficient_evidence_holds():
    d = evaluate(ctx("draft_reply", {"to": f("dana@contoso.com", S)}, level="INSUFFICIENT_EVIDENCE"), CFG)
    assert (d.verdict, d.rule_id) == ("HOLD_FOR_EVIDENCE", "P-06")
    assert "1 open question" in d.reason_plain_english


def test_hard_block_beats_hold():
    d = evaluate(ctx("update_payment_details", {"iban": f(IBAN), "vendor": f("Contoso Ltd", S)},
                     level="INSUFFICIENT_EVIDENCE"), CFG)
    assert d.verdict == "BLOCK"


def test_read_only_not_held():
    d = evaluate(ctx("label", {"label": f("x")}, level="INSUFFICIENT_EVIDENCE"), CFG)
    assert d.verdict == "ALLOW"


# -------------------------------------------------------------- P-07

def test_sensitive_unverified_confirms_with_oob():
    d = evaluate(ctx("draft_reply", {"to": f("dana@contoso.com", S)}, sensitive=True), CFG)
    assert (d.verdict, d.rule_id) == ("CONFIRM", "P-07")
    assert d.requires_out_of_band_verification
    assert "not a known contact" in d.verification_note


def test_sensitive_verified_reversible_allows():
    d = evaluate(ctx("draft_reply", {"to": f("dana@contoso.com", S)}, sensitive=True, identity=VERIFIED), CFG)
    assert d.verdict == "ALLOW"


# --------------------------------------------- B1: verified payment change

def test_b1_verified_sender_payment_change_is_confirm_not_block():
    p = promote_provenance(parsed(), VERIFIED, [])
    assert p.promoted
    iban = p.parsed.entities["iban"]
    assert iban.source == T
    d = evaluate(ctx("update_payment_details", {"iban": iban, "vendor": f("Contoso Ltd", S)},
                     identity=VERIFIED, sensitive=True), CFG)
    assert (d.verdict, d.rule_id) == ("CONFIRM", "TIER-CONSEQUENTIAL")
    assert d.requires_out_of_band_verification


def test_promotion_refused_with_injection_or_unverified():
    assert not promote_provenance(parsed(), VERIFIED, [finding(3)]).promoted
    assert not promote_provenance(parsed(), UNVERIFIED, []).promoted
    d = evaluate(ctx("update_payment_details", {"iban": f(IBAN, T), "vendor": f("Contoso Ltd", S)},
                     identity=VERIFIED, findings=[finding(3)], sensitive=True), CFG)
    assert d.verdict == "BLOCK"


def test_promotion_does_not_mutate_original():
    original = parsed()
    promote_provenance(original, VERIFIED, [])
    assert original.entities["iban"].source == U


# --------------------------------------------------------- fail closed

def test_exception_blocks():
    broken = PolicyContext.model_construct(action=None)
    d = evaluate(broken, CFG)
    assert (d.verdict, d.rule_id) == ("BLOCK", "P-00")


def test_wrong_types_block():
    assert evaluate("not a context", CFG).rule_id == "P-00"
    assert evaluate(ctx("summarize"), None).rule_id == "P-00"


# ------------------------------------------------------------ config

def test_store_update_validates_and_keeps_old_on_error():
    store = PolicyStore(PolicyConfig(allowed_domains=["a.com"]))
    assert store.update(allowed_domains=["B.com", "b.com"], confirm=True).allowed_domains == ["b.com"]
    with pytest.raises(ValidationError):
        store.update(allowed_domains=["*.evil"])
    with pytest.raises(ValidationError):
        store.update(tiers={"send_reply": "SUPER_SAFE"})
    assert store.get().allowed_domains == ["b.com"]


def test_store_snapshot_is_isolated():
    store = PolicyStore()
    snap = store.get()
    snap.allowed_domains.append("evil.example")
    assert "evil.example" not in store.get().allowed_domains


# -------------------------------- fix-6: monotonic tiers and confirm gate

def test_tier_downgrade_rejected_and_config_unchanged():
    store = PolicyStore()
    store.update(tiers={"draft_reply": "CONSEQUENTIAL"})  # upgrade: OK
    assert store.get().tiers["draft_reply"].value == "CONSEQUENTIAL"
    with pytest.raises(ValidationError):
        store.update(tiers={"draft_reply": "READ_ONLY"})
    # config must be unchanged after rejected downgrade
    assert store.get().tiers["draft_reply"].value == "CONSEQUENTIAL"


def test_tier_upgrade_accepted_and_logged():
    store = PolicyStore()
    updated = store.update(tiers={"draft_reply": "CONSEQUENTIAL"})
    assert updated.tiers["draft_reply"].value == "CONSEQUENTIAL"
    assert any(
        e["field"] == "tiers.draft_reply" and e["previous"] == "REVERSIBLE" and e["new"] == "CONSEQUENTIAL"
        for e in store._audit_log
    )


def test_unknown_tool_name_rejected():
    store = PolicyStore()
    with pytest.raises(ValidationError):
        store.update(tiers={"brand_new_tool": "READ_ONLY"})


def test_domain_addition_without_confirm_rejected():
    store = PolicyStore(PolicyConfig(allowed_domains=["a.com"]))
    with pytest.raises(ValidationError):
        store.update(allowed_domains=["a.com", "b.com"])


def test_domain_addition_with_confirm_logged_with_prior_value():
    store = PolicyStore(PolicyConfig(allowed_domains=["a.com"]))
    updated = store.update(allowed_domains=["a.com", "b.com"], confirm=True)
    assert "b.com" in updated.allowed_domains
    log_entry = next(
        (e for e in store._audit_log if e["field"] == "allowed_domains"),
        None,
    )
    assert log_entry is not None
    assert "a.com" in log_entry["previous"]
    assert log_entry["confirm"] is True


# ------------------------------------------------------ no LLM in policy

def test_policy_module_imports_no_llm_or_network():
    tree = ast.parse(Path(policy.__file__).read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            names.add((node.module or "").split(".")[0])
    assert names <= {"__future__", "datetime", "html", "re", "threading", "unicodedata", "typing", "urllib", "pydantic", "schemas"}
