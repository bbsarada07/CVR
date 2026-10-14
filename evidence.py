"""Evidence ledger and deterministic risk scoring. No LLM.

Model
-----
Each item has strength s = weight x confidence (capped at S_CAP), converted to
evidence in nats: e = -ln(1 - s). Nats add across independent items, so for
each direction

    L_mal = sum of e over SUPPORTS_MALICIOUS items
    L_ben = sum of e over SUPPORTS_BENIGN items
    mass  = 1 - exp(-L)            (identical to noisy-OR of the strengths)
    net   = L_mal - L_ben
    score = 100 * sigmoid(net)     (50 = no lean either way)

Classification, in order:
    fewer than MIN_ITEMS items                               -> INSUFFICIENT (too few checks)
    max(mass_mal, mass_ben) < MIN_MASS                       -> INSUFFICIENT (nothing decisive)
    both masses >= CONFLICT_MASS and |net| < CONFLICT_MARGIN -> INSUFFICIENT (contradictory)
    score >= MALICIOUS_MIN -> MALICIOUS; score >= SAFE_MAX -> SUSPICIOUS; else SAFE

The margin is what lets the reassessment loop resolve a conflict: the ledger is
append-only, so a decisive new item has to be able to outweigh the old ones.

Uncertainty: each item is treated as valid with probability = its confidence
(full weight when valid, absent when not). The assessment is recomputed over
those reliability scenarios (exact for <= EXACT_MAX uncertain items, seeded
Monte Carlo beyond). score_band is the 10th-90th percentile of the score;
confidence is the probability that the scenario's level equals the reported one.
"""

from __future__ import annotations

import math
import random
import zlib
from itertools import product
from typing import Iterable, Optional

from schemas import (
    Direction,
    EvidenceItem,
    EvidenceLedger,
    IdentityStatus,
    RiskAssessment,
)

S_CAP = 0.99
MIN_ITEMS = 3
MIN_MASS = 0.40
CONFLICT_MASS = 0.40
CONFLICT_MARGIN_NATS = 1.0
SAFE_MAX = 35.0
MALICIOUS_MIN = 70.0
PAIR_MIN_STRENGTH = 0.25
BAND_QUANTILES = (0.10, 0.90)
EXACT_MAX = 12
MC_SAMPLES = 4096

MAL: Direction = "SUPPORTS_MALICIOUS"
BEN: Direction = "SUPPORTS_BENIGN"

TOOL_FACET = {
    "check_auth": "identity",
    "lookup_contact": "identity",
    "thread_history": "context",
    "domain_intel": "infrastructure",
    "analyze_links": "links",
    "inspect_attachments": "attachments",
    "detect_hidden_content": "content",
    "injection_scan": "content",
    "check_sensitive_request": "request",
}
FACET_CLUSTER = {
    "identity": "sender",
    "context": "sender",
    "infrastructure": "sender",
    "links": "payload",
    "attachments": "payload",
    "content": "payload",
    "request": "payload",
}
FACET_QUESTION = {
    "identity": "Can the sender be confirmed out-of-band using contact details on file (not details taken from this email)?",
    "context": "Does this request match what was previously agreed in the conversation, according to someone who was part of it?",
    "infrastructure": "Is the sending domain legitimately owned by the organisation it claims to represent?",
    "links": "Where do the links actually resolve, and is that destination expected for this sender?",
    "attachments": "Was this attachment expected, and can its contents be confirmed with the sender?",
    "content": "Is the hidden or instruction-like content harmless formatting, or an attempt to steer the assistant?",
    "request": "Has this kind of request been made through an approved channel before?",
    "external": "Can the analyst-supplied evidence be corroborated by a second source?",
}
CORE_FACETS = ("identity", "context", "infrastructure", "links", "attachments", "content", "request")


def facet_of(item: EvidenceItem) -> str:
    return TOOL_FACET.get(item.tool, "external")


def _cluster(facet: str) -> str:
    return FACET_CLUSTER.get(facet, "*")


def strength(item: EvidenceItem) -> float:
    return min(item.weight * item.confidence, S_CAP)


def to_nats(s: float) -> float:
    return -math.log1p(-min(max(s, 0.0), S_CAP))


def mass(nats: float) -> float:
    return 1.0 - math.exp(-nats)


def score_from_net(net: float) -> float:
    return 100.0 / (1.0 + math.exp(-net))


def _classify(l_mal: float, l_ben: float, n_items: int) -> tuple[str, str]:
    m_mal, m_ben = mass(l_mal), mass(l_ben)
    net = l_mal - l_ben
    if n_items < MIN_ITEMS:
        return "INSUFFICIENT_EVIDENCE", "too_few"
    if max(m_mal, m_ben) < MIN_MASS:
        return "INSUFFICIENT_EVIDENCE", "weak"
    if min(m_mal, m_ben) >= CONFLICT_MASS and abs(net) < CONFLICT_MARGIN_NATS:
        return "INSUFFICIENT_EVIDENCE", "contradictory"
    score = score_from_net(net)
    if score >= MALICIOUS_MIN:
        return "MALICIOUS", "malicious"
    if score >= SAFE_MAX:
        return "SUSPICIOUS", "suspicious"
    return "SAFE", "safe"


def _totals(items: Iterable[EvidenceItem], full_weight: bool) -> tuple[float, float, int]:
    l_mal = l_ben = 0.0
    n = 0
    for it in items:
        s = min(it.weight, S_CAP) if full_weight else strength(it)
        n += 1
        if it.direction == MAL:
            l_mal += to_nats(s)
        elif it.direction == BEN:
            l_ben += to_nats(s)
    return l_mal, l_ben, n


# ---------------------------------------------------------------- ledger ops

def new_ledger() -> EvidenceLedger:
    return EvidenceLedger()


def _next_id(ledger: EvidenceLedger) -> str:
    used = {it.id for it in ledger.items}
    n = len(ledger.items) + 1
    while f"E{n}" in used:
        n += 1
    return f"E{n}"


def add(ledger: EvidenceLedger, item: EvidenceItem) -> EvidenceItem:
    """Append-only. Ids are unique; nothing is ever replaced or removed."""
    if any(it.id == item.id for it in ledger.items):
        raise ValueError(f"evidence id {item.id!r} already in ledger")
    ledger.items.append(item)
    ledger.contradictions = find_contradictions(ledger.items)
    return item


def record(
    ledger: EvidenceLedger,
    *,
    claim: str,
    tool: str,
    direction: Direction,
    weight: float,
    confidence: float,
    raw: Optional[dict] = None,
) -> EvidenceItem:
    item = EvidenceItem(
        id=_next_id(ledger),
        claim=claim,
        tool=tool,
        raw=raw or {},
        direction=direction,
        weight=weight,
        confidence=confidence,
    )
    return add(ledger, item)


def find_contradictions(items: list[EvidenceItem]) -> list[tuple[str, str]]:
    """Pair each strong malicious item with the strongest benign item about the same
    subject (sender vs payload). Analyst/unknown-tool items can conflict with anything."""
    bens = [b for b in items if b.direction == BEN and strength(b) >= PAIR_MIN_STRENGTH]
    pairs: list[tuple[str, str]] = []
    for m in items:
        if m.direction != MAL or strength(m) < PAIR_MIN_STRENGTH:
            continue
        mc = _cluster(facet_of(m))
        rivals = [b for b in bens if mc == "*" or _cluster(facet_of(b)) in (mc, "*")]
        if rivals:
            best = max(rivals, key=strength)
            pairs.append((m.id, best.id))
    return pairs


# ---------------------------------------------------------- uncertainty

def _scenarios(items: list[EvidenceItem]):
    """Yield (probability, valid_items) over item-validity scenarios."""
    fixed = [it for it in items if it.confidence >= 1.0]
    uncertain = [it for it in items if 0.0 < it.confidence < 1.0]
    if len(uncertain) <= EXACT_MAX:
        for mask in product((True, False), repeat=len(uncertain)):
            p = 1.0
            valid = list(fixed)
            for it, ok in zip(uncertain, mask):
                p *= it.confidence if ok else 1.0 - it.confidence
                if ok:
                    valid.append(it)
            if p > 0.0:
                yield p, valid
        return
    seed = zlib.crc32("|".join(it.id for it in items).encode())
    rng = random.Random(seed)
    for _ in range(MC_SAMPLES):
        valid = list(fixed) + [it for it in uncertain if rng.random() < it.confidence]
        yield 1.0 / MC_SAMPLES, valid


def _weighted_quantile(pairs: list[tuple[float, float]], q: float) -> float:
    pairs = sorted(pairs)
    total = sum(p for _, p in pairs)
    acc = 0.0
    for value, p in pairs:
        acc += p
        if acc >= q * total - 1e-12:
            return value
    return pairs[-1][0]


def _uncertainty(items: list[EvidenceItem], level: str) -> tuple[tuple[float, float], float]:
    scores: list[tuple[float, float]] = []
    agree = 0.0
    total = 0.0
    for p, valid in _scenarios(items):
        l_mal, l_ben, n = _totals(valid, full_weight=True)
        scores.append((score_from_net(l_mal - l_ben), p))
        total += p
        if _classify(l_mal, l_ben, n)[0] == level:
            agree += p
    lo = _weighted_quantile(scores, BAND_QUANTILES[0])
    hi = _weighted_quantile(scores, BAND_QUANTILES[1])
    return (lo, hi), (agree / total if total else 0.0)


# ------------------------------------------------------------ assessment

def _fmt(it: EvidenceItem) -> str:
    return f"{it.id} \"{it.claim}\" (w{it.weight:.2f} x c{it.confidence:.2f})"


def _open_questions(items: list[EvidenceItem], reason: str, pairs: list[tuple[str, str]]) -> list[str]:
    by_id = {it.id: it for it in items}
    qs: list[str] = []
    if reason == "contradictory":
        for mid, bid in pairs:
            m, b = by_id[mid], by_id[bid]
            qs.append(f"{mid} and {bid} disagree: \"{m.claim}\" vs \"{b.claim}\". Which is true?")
            for f in (facet_of(m), facet_of(b)):
                q = FACET_QUESTION[f]
                if q not in qs:
                    qs.append(q)
        if not pairs:
            qs.append(
                "Sender checks and content checks point in opposite directions. "
                "Could a legitimate account have been compromised?"
            )
    else:
        covered = {facet_of(it) for it in items}
        missing = [f for f in CORE_FACETS if f not in covered]
        qs.append(
            f"Only {len(items)} check(s) produced evidence and none was decisive. "
            "More investigation is needed before deciding."
        )
        qs += [FACET_QUESTION[f] for f in missing[:3]]
        if not missing:
            qs.append(FACET_QUESTION["identity"])
    return qs


def assess(ledger: EvidenceLedger) -> RiskAssessment:
    items = list(ledger.items)
    l_mal, l_ben, n = _totals(items, full_weight=False)
    net = l_mal - l_ben
    score = score_from_net(net)
    level, reason = _classify(l_mal, l_ben, n)
    pairs = find_contradictions(items)
    band, confidence = _uncertainty(items, level)
    band = (min(band[0], score), max(band[1], score))

    mal = sorted((it for it in items if it.direction == MAL and strength(it) > 0), key=strength, reverse=True)
    ben = sorted((it for it in items if it.direction == BEN and strength(it) > 0), key=strength, reverse=True)
    if level == "INSUFFICIENT_EVIDENCE":
        key = mal[:2] + ben[:2]
    else:
        lead, other = (mal, ben) if net > 0 else (ben, mal)
        key = lead[:3] + [it for it in other[:1] if strength(it) >= PAIR_MIN_STRENGTH]

    m_mal, m_ben = mass(l_mal), mass(l_ben)
    parts = [
        f"{level} at score {score:.0f}/100.",
        f"Malicious evidence {l_mal:.2f} nats (mass {m_mal:.2f}) from [{', '.join(i.id for i in mal) or 'none'}];",
        f"benign evidence {l_ben:.2f} nats (mass {m_ben:.2f}) from [{', '.join(i.id for i in ben) or 'none'}].",
    ]
    if key:
        parts.append("Key evidence: " + "; ".join(_fmt(it) for it in key) + ".")
    if reason == "too_few":
        parts.append(f"Only {n} item(s) in the ledger; at least {MIN_ITEMS} independent checks are required.")
    elif reason == "weak":
        parts.append(f"Neither direction reaches mass {MIN_MASS:.2f}; nothing is decisive.")
    elif reason == "contradictory":
        parts.append(
            f"Both directions exceed mass {CONFLICT_MASS:.2f} and differ by only {abs(net):.2f} nats "
            f"(< {CONFLICT_MARGIN_NATS:.1f}); refusing to force a conclusion."
        )

    open_qs = _open_questions(items, reason, pairs) if level == "INSUFFICIENT_EVIDENCE" else []
    note = (
        f"80% band {band[0]:.0f}-{band[1]:.0f}. In {confidence:.0%} of evidence-reliability "
        f"scenarios the level stays {level}."
    )
    if pairs:
        note += f" {len(pairs)} conflicting pair(s): " + ", ".join(f"{a}<->{b}" for a, b in pairs) + "."

    return RiskAssessment(
        level=level,
        score=round(score, 2),
        confidence=round(confidence, 3),
        rationale=" ".join(parts),
        key_evidence_ids=[it.id for it in key],
        uncertainty_note=note,
        open_questions=open_qs,
        score_band=(round(band[0], 2), round(band[1], 2)),
        malicious_mass=round(m_mal, 4),
        benign_mass=round(m_ben, 4),
    )


def diff_assessments(previous: RiskAssessment, revised: RiskAssessment, new_items: list[EvidenceItem]) -> str:
    parts = []
    if previous.level != revised.level:
        parts.append(f"Level {previous.level} -> {revised.level}")
    else:
        parts.append(f"Level unchanged ({revised.level})")
    delta = revised.score - previous.score
    parts.append(f"score {previous.score:.0f} -> {revised.score:.0f} ({delta:+.0f})")
    parts.append(f"confidence {previous.confidence:.2f} -> {revised.confidence:.2f}")
    if new_items:
        parts.append("triggered by " + "; ".join(_fmt(it) for it in new_items))
    return ", ".join(parts) + "."


# --------------------------------------------- facts derived from tool output
#
# Raw-key contract that tools.py must emit (anything missing fails closed):
#   check_auth:              {"spf": "pass"|..., "dkim": ..., "dmarc": ...}
#   lookup_contact:          {"known": bool, "verified": bool, "address_matches": bool, "display_name_matches": bool}
#   thread_history:          {"has_thread": bool, "fits_thread": bool, "escalation": bool}
#   check_sensitive_request: {"sensitive": bool, "categories": [str]}
#   analyst (POST /api/evidence): {"kind": "out_of_band_verification"} with direction SUPPORTS_BENIGN,
#                                 or SUPPORTS_MALICIOUS to record a failed out-of-band check.

def _latest(items: list[EvidenceItem], tool: str) -> Optional[EvidenceItem]:
    found = [it for it in items if it.tool == tool]
    return found[-1] if found else None


def identity_from_ledger(ledger: EvidenceLedger) -> IdentityStatus:
    items = ledger.items
    st = IdentityStatus()
    failures: list[str] = []

    auth = _latest(items, "check_auth")
    if auth is None:
        failures.append("check_auth not run")
    else:
        results = {k: auth.raw.get(k) for k in ("spf", "dkim", "dmarc")}
        st.auth_pass = all(v == "pass" for v in results.values())
        if not st.auth_pass:
            failures.append("authentication not fully passing: " + ", ".join(f"{k}={v}" for k, v in results.items()))

    contact = _latest(items, "lookup_contact")
    if contact is None:
        failures.append("lookup_contact not run")
    else:
        r = contact.raw
        st.known_contact = r.get("known") is True
        st.contact_verified = r.get("verified") is True
        st.address_matches_history = r.get("address_matches") is True
        st.display_name_matches = r.get("display_name_matches") is True
        if not st.known_contact:
            failures.append("sender is not a known contact")
        else:
            if not st.contact_verified:
                failures.append("contact is not verified in the directory")
            if not st.address_matches_history:
                failures.append("sender address differs from the address on file")
            if not st.display_name_matches:
                failures.append("display name does not match the directory")

    thread = _latest(items, "thread_history")
    if thread is None:
        st.thread_consistent = False
        failures.append("thread_history not run")
    elif thread.raw.get("has_thread") is not True:
        st.thread_consistent = None
    else:
        st.thread_consistent = thread.raw.get("fits_thread") is True and thread.raw.get("escalation") is False
        if not st.thread_consistent:
            failures.append("request does not fit the existing thread or is a sudden escalation")

    oob = [it for it in items if it.tool == "analyst" and it.raw.get("kind") == "out_of_band_verification"]
    if oob:
        st.out_of_band_verified = oob[-1].direction == BEN
        if not st.out_of_band_verified:
            failures.append("out-of-band verification failed")

    st.failures = failures
    return st


def sensitive_from_ledger(ledger: EvidenceLedger) -> tuple[bool, list[str]]:
    item = _latest(ledger.items, "check_sensitive_request")
    if item is None:
        return True, ["unknown: check_sensitive_request not run"]
    cats = item.raw.get("categories")
    cats = [str(c) for c in cats] if isinstance(cats, list) else []
    return item.raw.get("sensitive") is not False, cats
