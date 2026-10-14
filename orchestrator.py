"""Pipeline orchestrator: coordinates stages from ingest to policy gate and execution.

Stages:
  INGEST → PARSE → INVESTIGATE → INJECTION_SCAN → RISK_ASSESS → PLAN → POLICY_GATE → EXECUTE_OR_HOLD → LOG
Emits a TraceEvent per stage with elapsed milliseconds.

NAIVE MODE (sentinel_enabled=false):
  Raw body straight into one LLM/agent with tool access, executes whatever comes back.
  Genuinely vulnerable — no policy gate or provenance checks. Core demo toggle.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Generator, Iterator, Optional, Union

import evidence as ev
import policy as pol
from agents import (
    ActionPlannerAgent,
    InjectionAnalystAgent,
    InvestigatorAgent,
    NaiveAgent,
    ParserAgent,
    RiskAssessorAgent,
)
from schemas import (
    EvidenceItem,
    EvidenceLedger,
    Field,
    IdentityStatus,
    InjectionFinding,
    ParsedEmail,
    PolicyContext,
    PolicyDecision,
    ProposedAction,
    Reassessment,
    RiskAssessment,
    Source,
    TraceEvent,
    TraceStatus,
)
from seed_data import SeedEmail

log = logging.getLogger("orchestrator")


@dataclass
class OrchestratorResult:
    run_id: str
    sentinel_enabled: bool
    email_id: Optional[str]
    parsed: Optional[ParsedEmail] = None
    ledger: Optional[EvidenceLedger] = None
    risk: Optional[RiskAssessment] = None
    injection_findings: list[InjectionFinding] = field(default_factory=list)
    action: Optional[ProposedAction] = None
    decision: Optional[PolicyDecision] = None
    naive_result: Optional[dict] = None
    traces: list[TraceEvent] = field(default_factory=list)
    total_ms: int = 0
    untrusted_corpus: list[str] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        if not self.sentinel_enabled:
            return "EXECUTED_WITHOUT_GATE"
        return self.decision.verdict if self.decision else "UNKNOWN"

    @property
    def rule_id(self) -> str:
        if not self.sentinel_enabled:
            return "NAIVE_MODE"
        return self.decision.rule_id if self.decision else "NONE"


class Orchestrator:
    def __init__(self) -> None:
        self.parser = ParserAgent()
        self.investigator = InvestigatorAgent()
        self.injection_analyst = InjectionAnalystAgent()
        self.risk_assessor = RiskAssessorAgent()
        self.action_planner = ActionPlannerAgent()
        self.naive_agent = NaiveAgent()

    def process(
        self,
        email: Union[SeedEmail, dict],
        sentinel_enabled: bool = True,
        user_values: Optional[list[str]] = None,
        system_values: Optional[list[str]] = None,
        policy_config: Optional[pol.PolicyConfig] = None,
    ) -> OrchestratorResult:
        """Run the complete pipeline synchronously, collecting all traces and decisions."""
        run_id = f"run-{uuid.uuid4().hex[:8]}"
        email_id = getattr(email, "id", None) or (email.get("id") if isinstance(email, dict) else None)
        traces: list[TraceEvent] = []
        overall_start = time.perf_counter()

        def emit(seq: int, stage: str, agent: str, status: TraceStatus, payload: dict, start_time: float) -> TraceEvent:
            elapsed_ms = max(0, int((time.perf_counter() - start_time) * 1000))
            event = TraceEvent(
                seq=seq,
                stage=stage,
                agent=agent,
                status=status,
                payload=payload,
                ms=elapsed_ms,
            )
            traces.append(event)
            return event

        # -------------------------------------------------------------------
        # Naive Mode (Toggle: sentinel_enabled = False)
        # -------------------------------------------------------------------
        if not sentinel_enabled:
            s_time = time.perf_counter()
            emit(
                1,
                "INGEST",
                "orchestrator",
                "ok",
                {"mode": "naive", "email_id": email_id, "sentinel_enabled": False},
                s_time,
            )

            naive_start = time.perf_counter()
            naive_out = self.naive_agent.process(email)
            emit(
                2,
                "NAIVE_EXECUTION",
                "naive_agent",
                "ok",
                naive_out,
                naive_start,
            )

            total_ms = int((time.perf_counter() - overall_start) * 1000)
            return OrchestratorResult(
                run_id=run_id,
                sentinel_enabled=False,
                email_id=email_id,
                naive_result=naive_out,
                traces=traces,
                total_ms=total_ms,
            )

        # -------------------------------------------------------------------
        # Sentinel Secure Pipeline
        # -------------------------------------------------------------------

        # 1. INGEST
        s1 = time.perf_counter()
        subject = getattr(email, "subject", "") or (email.get("subject", "") if isinstance(email, dict) else "")
        sender = getattr(email, "sender_address", "") or (email.get("sender_address", "") if isinstance(email, dict) else "")
        emit(
            1,
            "INGEST",
            "orchestrator",
            "ok",
            {"email_id": email_id, "subject": subject, "sender": sender, "sentinel_enabled": True},
            s1,
        )

        # 2. PARSE (Quarantined, zero tools)
        s2 = time.perf_counter()
        parsed = self.parser.parse(email)
        emit(
            2,
            "PARSE",
            "parser",
            "ok",
            {
                "sender": parsed.sender.model_dump(),
                "subject": parsed.subject.model_dump(),
                "intent": parsed.intent.model_dump(),
                "entities_count": len(parsed.entities),
                "entities": {k: v.model_dump() for k, v in parsed.entities.items()},
                "requested_action": parsed.requested_action.model_dump() if parsed.requested_action else None,
            },
            s2,
        )

        # 3. INVESTIGATE (Read-only tools chain)
        s3 = time.perf_counter()
        ledger, tool_log = self.investigator.investigate(parsed, email)
        identity = ev.identity_from_ledger(ledger)
        sensitive, sens_cats = ev.sensitive_from_ledger(ledger)
        emit(
            3,
            "INVESTIGATE",
            "investigator",
            "ok",
            {
                "tool_calls": tool_log,
                "evidence_count": len(ledger.items),
                "identity_verified": identity.verified,
                "identity_failures": identity.failures,
                "sensitive_request": sensitive,
                "sensitive_categories": sens_cats,
            },
            s3,
        )

        # 4. INJECTION_SCAN (Zero tools, raw body)
        s4 = time.perf_counter()
        raw_body = getattr(email, "body", "") or (email.get("body", "") if isinstance(email, dict) else "")
        injection_findings = self.injection_analyst.scan(raw_body)
        scan_status: TraceStatus = "blocked" if any(f.severity >= 4 for f in injection_findings) else "ok"
        emit(
            4,
            "INJECTION_SCAN",
            "injection_analyst",
            scan_status,
            {
                "findings_count": len(injection_findings),
                "findings": [f.model_dump() for f in injection_findings],
                "max_severity": max((f.severity for f in injection_findings), default=0),
            },
            s4,
        )

        # 5. RISK_ASSESS (Ledger only)
        s5 = time.perf_counter()
        risk = self.risk_assessor.assess(ledger)
        emit(
            5,
            "RISK_ASSESS",
            "risk_assessor",
            "ok",
            {
                "level": risk.level,
                "score": round(risk.score, 1),
                "confidence": round(risk.confidence, 2),
                "rationale": risk.rationale,
                "uncertainty_note": risk.uncertainty_note,
                "open_questions": risk.open_questions,
                "score_band": [round(risk.score_band[0], 1), round(risk.score_band[1], 1)],
            },
            s5,
        )

        # 6. PLAN (NEVER receives raw body — enforced structurally)
        s6 = time.perf_counter()
        action = self.action_planner.plan(
            parsed=parsed,
            risk=risk,
            identity=identity,
            sensitive=sensitive,
        )
        emit(
            6,
            "PLAN",
            "action_planner",
            "ok",
            {
                "tool": action.tool,
                "args": {k: v.model_dump() for k, v in action.args.items()},
                "justification": action.justification,
            },
            s6,
        )

        # 7. POLICY_GATE (Deterministic, NO LLM)
        s7 = time.perf_counter()
        # Evaluate provenance promotion if eligible
        promotion = pol.promote_provenance(parsed, identity, injection_findings)
        effective_action = action
        if promotion.promoted:
            # Promote matching action args to TRUSTED_CONTACT
            promoted_args = {}
            for k, f in action.args.items():
                if f.source == Source.UNTRUSTED_EMAIL:
                    promoted_args[k] = f.model_copy(update={"source": Source.TRUSTED_CONTACT})
                else:
                    promoted_args[k] = f
            effective_action = action.model_copy(update={"args": promoted_args})

        untrusted_corpus = [raw_body, subject]
        sys_vals = list(system_values or []) + [
            "Contoso Supply",
            "northwindtraders.com",
            "contoso-supply.com",
            "mailto:priya.raghavan@northwindtraders.com",
            "mailto:t.lind@contoso-supply.com",
            "mailto:d.ellis@contoso-supply.com",
            "mailto:a.prentice@northwindtraders.com",
            "priya.raghavan@northwindtraders.com",
            "t.lind@contoso-supply.com",
            "d.ellis@contoso-supply.com",
            "a.prentice@northwindtraders.com",
        ]
        ctx = PolicyContext(
            action=effective_action,
            risk=risk,
            injection_findings=injection_findings,
            identity=identity,
            sensitive_request=sensitive,
            untrusted_corpus=untrusted_corpus,
            parsed=parsed,
            user_values=user_values or [],
            system_values=sys_vals,
        )
        p_cfg = policy_config if policy_config is not None else pol.PolicyConfig()
        decision = pol.evaluate(ctx, p_cfg)

        gate_status: TraceStatus = "blocked" if decision.verdict == "BLOCK" else "ok"
        emit(
            7,
            "POLICY_GATE",
            "policy_engine",
            gate_status,
            {
                "verdict": decision.verdict,
                "rule_id": decision.rule_id,
                "reason": decision.reason_plain_english,
                "offending_fields": decision.offending_fields,
                "triggered_rules": decision.triggered_rules,
                "requires_oob": decision.requires_out_of_band_verification,
                "promoted_provenance": promotion.promoted,
            },
            s7,
        )

        # 8. EXECUTE_OR_HOLD
        s8 = time.perf_counter()
        exec_payload: dict[str, Any] = {"verdict": decision.verdict, "rule_id": decision.rule_id}
        exec_status: TraceStatus = "ok"

        if decision.verdict == "ALLOW":
            exec_payload["status"] = "executed"
            exec_payload["message"] = f"Action '{effective_action.tool}' permitted and executed successfully."
        elif decision.verdict == "CONFIRM":
            exec_payload["status"] = "held_for_confirmation"
            exec_payload["message"] = f"Action '{effective_action.tool}' requires human confirmation before execution."
            exec_payload["oob_verification_required"] = decision.requires_out_of_band_verification
        elif decision.verdict == "HOLD_FOR_EVIDENCE":
            exec_payload["status"] = "held_for_evidence"
            exec_payload["message"] = "Action held due to conflicting or insufficient evidence."
            exec_payload["open_questions"] = risk.open_questions
        else:  # BLOCK
            exec_status = "blocked"
            exec_payload["status"] = "blocked"
            exec_payload["message"] = f"Action refused under security rule {decision.rule_id}: {decision.reason_plain_english}"

        emit(
            8,
            "EXECUTE_OR_HOLD",
            "executor",
            exec_status,
            exec_payload,
            s8,
        )

        # 9. LOG
        s9 = time.perf_counter()
        total_ms = int((time.perf_counter() - overall_start) * 1000)
        emit(
            9,
            "LOG",
            "audit_logger",
            "ok",
            {
                "run_id": run_id,
                "email_id": email_id,
                "verdict": decision.verdict,
                "rule_id": decision.rule_id,
                "total_ms": total_ms,
                "stages_count": 9,
            },
            s9,
        )

        return OrchestratorResult(
            run_id=run_id,
            sentinel_enabled=True,
            email_id=email_id,
            parsed=parsed,
            ledger=ledger,
            risk=risk,
            injection_findings=injection_findings,
            action=effective_action,
            decision=decision,
            traces=traces,
            total_ms=total_ms,
            untrusted_corpus=untrusted_corpus,
        )

    def stream(
        self,
        email: Union[SeedEmail, dict],
        sentinel_enabled: bool = True,
        user_values: Optional[list[str]] = None,
        system_values: Optional[list[str]] = None,
        policy_config: Optional[pol.PolicyConfig] = None,
    ) -> Iterator[TraceEvent]:
        """Generator that runs the pipeline and yields each TraceEvent."""
        res = self.process(
            email=email,
            sentinel_enabled=sentinel_enabled,
            user_values=user_values,
            system_values=system_values,
            policy_config=policy_config,
        )
        for t in res.traces:
            yield t

    def reassess(
        self,
        previous_result: OrchestratorResult,
        new_evidence: Union[EvidenceItem, list[EvidenceItem]],
        trigger: str = "analyst_evidence",
        policy_config: Optional[pol.PolicyConfig] = None,
        user_values: Optional[list[str]] = None,
        system_values: Optional[list[str]] = None,
    ) -> tuple[Reassessment, OrchestratorResult]:
        """Inject new evidence into a previous run and re-run risk -> plan -> policy_gate.
        Emits a TraceEvent with status='revised' detailing previous vs revised and what changed.
        """
        if previous_result.ledger is None or previous_result.risk is None or previous_result.parsed is None:
            raise ValueError("Cannot reassess without previous ledger, risk, and parsed email")

        s_start = time.perf_counter()
        items_to_add = [new_evidence] if isinstance(new_evidence, EvidenceItem) else list(new_evidence)

        # Clone previous ledger (append-only) and insert new evidence
        revised_ledger = EvidenceLedger(
            items=list(previous_result.ledger.items),
            contradictions=list(previous_result.ledger.contradictions),
        )
        for item in items_to_add:
            if any(it.id == item.id for it in revised_ledger.items):
                item = item.model_copy(update={"id": ev._next_id(revised_ledger)})
            ev.add(revised_ledger, item)

        # 1. Re-evaluate RISK_ASSESS
        revised_risk = self.risk_assessor.assess(revised_ledger)

        # 2. Derive updated identity & sensitive status from ledger
        identity = ev.identity_from_ledger(revised_ledger)
        sensitive, sens_cats = ev.sensitive_from_ledger(revised_ledger)

        # 3. Re-run PLAN (Structurally safe: no raw body passed)
        revised_action = self.action_planner.plan(
            parsed=previous_result.parsed,
            risk=revised_risk,
            identity=identity,
            sensitive=sensitive,
        )

        # 4. Re-evaluate POLICY_GATE
        promotion = pol.promote_provenance(
            previous_result.parsed,
            identity,
            previous_result.injection_findings,
        )
        effective_action = revised_action
        if promotion.promoted:
            promoted_args = {}
            for k, f in revised_action.args.items():
                if f.source == Source.UNTRUSTED_EMAIL:
                    promoted_args[k] = f.model_copy(update={"source": Source.TRUSTED_CONTACT})
                else:
                    promoted_args[k] = f
            effective_action = revised_action.model_copy(update={"args": promoted_args})

        sys_vals = list(system_values or []) + [
            "Contoso Supply",
            "northwindtraders.com",
            "contoso-supply.com",
            "mailto:priya.raghavan@northwindtraders.com",
            "mailto:t.lind@contoso-supply.com",
            "mailto:d.ellis@contoso-supply.com",
            "mailto:a.prentice@northwindtraders.com",
            "priya.raghavan@northwindtraders.com",
            "t.lind@contoso-supply.com",
            "d.ellis@contoso-supply.com",
            "a.prentice@northwindtraders.com",
        ]

        untrusted = previous_result.untrusted_corpus or [
            previous_result.parsed.subject.value,
            previous_result.parsed.intent.value,
        ]
        ctx = PolicyContext(
            action=effective_action,
            risk=revised_risk,
            injection_findings=previous_result.injection_findings,
            identity=identity,
            sensitive_request=sensitive,
            untrusted_corpus=untrusted,
            parsed=previous_result.parsed,
            user_values=user_values or [],
            system_values=sys_vals,
        )
        p_cfg = policy_config if policy_config is not None else pol.PolicyConfig()
        revised_decision = pol.evaluate(ctx, p_cfg)

        what_changed = ev.diff_assessments(previous_result.risk, revised_risk, items_to_add)

        reassessment = Reassessment(
            run_id=previous_result.run_id,
            previous=previous_result.risk,
            revised=revised_risk,
            trigger=trigger,
            what_changed=what_changed,
            previous_decision=previous_result.decision,
            revised_decision=revised_decision,
        )

        elapsed_ms = max(0, int((time.perf_counter() - s_start) * 1000))
        trace_event = TraceEvent(
            seq=len(previous_result.traces) + 1,
            stage="REASSESSMENT",
            agent="risk_assessor",
            status="revised",
            payload={
                "trigger": trigger,
                "what_changed": what_changed,
                "previous_level": previous_result.risk.level,
                "previous_score": round(previous_result.risk.score, 1),
                "revised_level": revised_risk.level,
                "revised_score": round(revised_risk.score, 1),
                "previous_verdict": previous_result.decision.verdict if previous_result.decision else None,
                "revised_verdict": revised_decision.verdict,
                "previous_rule_id": previous_result.decision.rule_id if previous_result.decision else None,
                "revised_rule_id": revised_decision.rule_id,
                "promoted_provenance": promotion.promoted,
                "identity_verified": identity.verified,
                "requires_oob": revised_decision.requires_out_of_band_verification,
                "new_evidence_count": len(items_to_add),
            },
            ms=elapsed_ms,
        )

        revised_result = OrchestratorResult(
            run_id=previous_result.run_id,
            sentinel_enabled=True,
            email_id=previous_result.email_id,
            parsed=previous_result.parsed,
            ledger=revised_ledger,
            risk=revised_risk,
            injection_findings=previous_result.injection_findings,
            action=effective_action,
            decision=revised_decision,
            traces=list(previous_result.traces) + [trace_event],
            total_ms=previous_result.total_ms + elapsed_ms,
            untrusted_corpus=untrusted,
        )
        return reassessment, revised_result

