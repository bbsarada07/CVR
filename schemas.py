"""Pydantic v2 models shared by every SENTINEL component.

`Field` here is the provenance-carrying value from the spec; pydantic's own
field helper is imported as `PField` to avoid the name clash.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, model_validator
from pydantic import Field as PField


class Source(str, Enum):
    USER = "USER"
    TRUSTED_CONTACT = "TRUSTED_CONTACT"
    UNTRUSTED_EMAIL = "UNTRUSTED_EMAIL"
    SYSTEM_TOOL = "SYSTEM_TOOL"


# Higher = more trusted. Combining two sources always takes the lower rank.
TRUST_RANK: dict[Source, int] = {
    Source.UNTRUSTED_EMAIL: 0,
    Source.TRUSTED_CONTACT: 1,
    Source.SYSTEM_TOOL: 2,
    Source.USER: 3,
}


def least_trusted(*sources: Source) -> Source:
    return min(sources, key=lambda s: TRUST_RANK[s])


class Tier(str, Enum):
    READ_ONLY = "READ_ONLY"
    REVERSIBLE = "REVERSIBLE"
    CONSEQUENTIAL = "CONSEQUENTIAL"


Direction = Literal["SUPPORTS_MALICIOUS", "SUPPORTS_BENIGN", "NEUTRAL"]
RiskLevel = Literal["SAFE", "SUSPICIOUS", "MALICIOUS", "INSUFFICIENT_EVIDENCE"]
Verdict = Literal["ALLOW", "CONFIRM", "BLOCK", "HOLD_FOR_EVIDENCE"]
TraceStatus = Literal["running", "ok", "blocked", "revised", "error"]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _check_span(span: Optional[tuple[int, int]]) -> None:
    if span is not None and (span[0] < 0 or span[1] < span[0]):
        raise ValueError(f"invalid span {span}: need 0 <= start <= end")


class Field(BaseModel):
    # Frozen: provenance can only change by building a new Field, never in place.
    model_config = ConfigDict(frozen=True)

    value: str
    source: Source
    span: Optional[tuple[int, int]] = None  # char offsets into the raw body

    @model_validator(mode="after")
    def _span_valid(self) -> "Field":
        _check_span(self.span)
        return self


class EvidenceItem(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str = PField(min_length=1)
    claim: str
    tool: str
    raw: dict = PField(default_factory=dict)
    direction: Direction
    weight: float = PField(ge=0.0, le=1.0)
    confidence: float = PField(ge=0.0, le=1.0)
    timestamp: datetime = PField(default_factory=_utcnow)


class EvidenceLedger(BaseModel):
    items: list[EvidenceItem] = PField(default_factory=list)
    contradictions: list[tuple[str, str]] = PField(default_factory=list)  # (malicious_id, benign_id)


class ParsedEmail(BaseModel):
    sender: Field
    subject: Field
    intent: Field
    entities: dict[str, Field] = PField(default_factory=dict)
    requested_action: Optional[Field] = None
    links: list[Field] = PField(default_factory=list)
    attachments: list[Field] = PField(default_factory=list)

    def iter_fields(self) -> list[tuple[str, Field]]:
        out: list[tuple[str, Field]] = [
            ("sender", self.sender),
            ("subject", self.subject),
            ("intent", self.intent),
        ]
        out += [(f"entities.{k}", v) for k, v in self.entities.items()]
        if self.requested_action is not None:
            out.append(("requested_action", self.requested_action))
        out += [(f"links[{i}]", v) for i, v in enumerate(self.links)]
        out += [(f"attachments[{i}]", v) for i, v in enumerate(self.attachments)]
        return out


class InjectionFinding(BaseModel):
    kind: str
    evidence: str
    span: tuple[int, int]
    severity: int = PField(ge=1, le=5)
    technique: str

    @model_validator(mode="after")
    def _span_valid(self) -> "InjectionFinding":
        _check_span(self.span)
        return self


class RiskAssessment(BaseModel):
    level: RiskLevel
    score: float = PField(ge=0.0, le=100.0)
    confidence: float = PField(ge=0.0, le=1.0)
    rationale: str
    key_evidence_ids: list[str] = PField(default_factory=list)
    uncertainty_note: str
    open_questions: list[str] = PField(default_factory=list)
    score_band: tuple[float, float] = (0.0, 100.0)  # credible interval on score
    malicious_mass: float = PField(default=0.0, ge=0.0, le=1.0)
    benign_mass: float = PField(default=0.0, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _consistent(self) -> "RiskAssessment":
        lo, hi = self.score_band
        if not (0.0 <= lo <= hi <= 100.0):
            raise ValueError(f"invalid score_band {self.score_band}")
        if self.level == "INSUFFICIENT_EVIDENCE" and not self.open_questions:
            raise ValueError("INSUFFICIENT_EVIDENCE requires at least one open question")
        return self


class ProposedAction(BaseModel):
    tool: str
    args: dict[str, Field] = PField(default_factory=dict)
    justification: str
    draft_body: Optional[str] = None


class PolicyDecision(BaseModel):
    verdict: Verdict
    rule_id: str
    reason_plain_english: str
    offending_fields: list[str] = PField(default_factory=list)
    triggered_rules: list[str] = PField(default_factory=list)
    requires_out_of_band_verification: bool = False
    verification_note: Optional[str] = None
    findings: list[dict] = PField(default_factory=list)


class Reassessment(BaseModel):
    run_id: str
    previous: RiskAssessment
    revised: RiskAssessment
    trigger: str
    what_changed: str
    previous_decision: Optional[PolicyDecision] = None
    revised_decision: Optional[PolicyDecision] = None
    timestamp: datetime = PField(default_factory=_utcnow)


class TraceEvent(BaseModel):
    seq: int = PField(ge=0)
    stage: str
    agent: str
    status: TraceStatus
    payload: dict = PField(default_factory=dict)
    ms: int = PField(ge=0)


class IdentityStatus(BaseModel):
    """Outcome of T1-T3 (plus any analyst out-of-band check). Defaults fail closed."""

    auth_pass: bool = False
    known_contact: bool = False
    contact_verified: bool = False
    address_matches_history: bool = False
    display_name_matches: bool = False
    thread_consistent: Optional[bool] = False  # None = no prior thread exists
    out_of_band_verified: bool = False
    failures: list[str] = PField(default_factory=list)

    @property
    def verified(self) -> bool:
        if self.out_of_band_verified:
            return True
        return (
            self.auth_pass
            and self.known_contact
            and self.contact_verified
            and self.address_matches_history
            and self.display_name_matches
            and self.thread_consistent is not False
        )


class PolicyContext(BaseModel):
    """Everything the policy engine sees. It recomputes provenance from these
    registries itself; the source tags the planner put on args can only lower trust."""

    action: ProposedAction
    risk: RiskAssessment
    injection_findings: list[InjectionFinding] = PField(default_factory=list)
    identity: IdentityStatus = PField(default_factory=IdentityStatus)
    sensitive_request: bool = True  # unknown => sensitive (fail closed)
    untrusted_corpus: list[str] = PField(default_factory=list)  # raw headers, body, attachment names
    parsed: Optional[ParsedEmail] = None
    user_values: list[str] = PField(default_factory=list)  # values the user typed
    system_values: list[str] = PField(default_factory=list)  # values from directory / tool registries
