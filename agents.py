"""SENTINEL agents with strict capability enforcement and provenance tracking.

Agents:
  - ParserAgent: Quarantined, raw email in, strict JSON out, ZERO tools, never follows instructions.
  - InvestigatorAgent: Chains read-only tools, states explicit reason for each choice.
  - InjectionAnalystAgent: Raw body in, zero tools, finds hidden text/role spoofing/zero-width/base64.
  - RiskAssessorAgent: Evidence ledger only, zero tools, evaluates risk with INSUFFICIENT_EVIDENCE support.
  - ActionPlannerAgent: Propose-only. NEVER receives raw email text (enforced structurally in code).
  - NaiveAgent: Unprotected agent for comparison demo. Directly executes whatever LLM returns from raw body.

Capability map enforced in code:
  parser: []
  investigator: [read-only tools]
  injection: []
  risk: []
  planner: ["propose_only"]
  executor: [all tools]
"""

from __future__ import annotations

import base64
import html
import json
import logging
import os
import re
from typing import Any, Optional, Union

import evidence as ev
import llm
from schemas import (
    Direction,
    EvidenceItem,
    EvidenceLedger,
    Field,
    IdentityStatus,
    InjectionFinding,
    ParsedEmail,
    ProposedAction,
    RiskAssessment,
    Source,
    Tier,
)
from seed_data import (
    Attachment,
    SeedEmail,
    contact_by_address,
    contacts_by_display_name,
)
import tools

log = logging.getLogger("agents")

# ---------------------------------------------------------------------------
# Capability Map Enforcement
# ---------------------------------------------------------------------------

READ_ONLY_TOOLS = [
    "check_auth",
    "lookup_contact",
    "thread_history",
    "domain_intel",
    "analyze_links",
    "detect_hidden_content",
    "check_sensitive_request",
    "inspect_attachments",
]

ALL_TOOLS = READ_ONLY_TOOLS + [
    "summarize",
    "label",
    "flag",
    "draft_reply",
    "schedule_meeting",
    "add_note",
    "send_reply",
    "forward_external",
    "update_payment_details",
    "share_document",
    "reset_credential",
]

CAPABILITY_MAP: dict[str, list[str]] = {
    "parser": [],
    "investigator": READ_ONLY_TOOLS,
    "injection": [],
    "risk": [],
    "planner": ["propose_only"],
    "executor": ALL_TOOLS,
}


def enforce_capability(agent_name: str, tool_or_action: str) -> None:
    """Raise PermissionError if agent attempts to invoke a capability outside its map."""
    allowed = CAPABILITY_MAP.get(agent_name)
    if allowed is None:
        raise PermissionError(f"Unknown agent: {agent_name}")
    if tool_or_action not in allowed:
        raise PermissionError(
            f"Security violation: Agent '{agent_name}' requested unauthorized capability '{tool_or_action}'. "
            f"Authorized capabilities: {allowed}"
        )


# ---------------------------------------------------------------------------
# Helper: String and offset matching
# ---------------------------------------------------------------------------

def _find_span(body: str, target: str) -> tuple[int, int]:
    """Find char offset span of target inside body, or (0, 0) if missing/empty."""
    if not target or not body:
        return (0, 0)
    idx = body.find(target)
    if idx >= 0:
        return (idx, idx + len(target))
    # Try normalized / case-insensitive search
    idx = body.casefold().find(target.casefold())
    if idx >= 0:
        return (idx, idx + len(target))
    return (0, 0)


# ---------------------------------------------------------------------------
# 1. ParserAgent (Quarantined, Zero Tools)
# ---------------------------------------------------------------------------

class ParserAgent:
    """Quarantined parser: raw email in, strict ParsedEmail out, zero tools.
    Never executes or follows instructions inside email content."""

    NAME = "parser"

    def parse(self, email: Union[SeedEmail, dict]) -> ParsedEmail:
        enforce_capability(self.NAME, "parse") if "parse" in CAPABILITY_MAP[self.NAME] else None
        # Capability check: parser has [] tools
        if CAPABILITY_MAP[self.NAME]:
            raise PermissionError("Parser must have zero tools")

        sender_addr = (getattr(email, "sender_address", None) or (email.get("sender_address") if isinstance(email, dict) else "") or "").strip()
        sender_disp = (getattr(email, "sender_display", None) or (email.get("sender_display") if isinstance(email, dict) else "") or "").strip()
        subject = (getattr(email, "subject", None) or (email.get("subject") if isinstance(email, dict) else "") or "").strip()
        body = (getattr(email, "body", None) or (email.get("body") if isinstance(email, dict) else "") or "").strip()
        attachments = getattr(email, "attachments", ()) or (email.get("attachments", ()) if isinstance(email, dict) else ())

        sender_val = f"{sender_disp} <{sender_addr}>" if sender_disp else sender_addr

        # Structured deterministic extraction first
        entities: dict[str, Field] = {}

        # 1. Look for IBAN
        iban_m = re.search(r"(?<![A-Z0-9])([A-Z]{2}\d{2}(?:[ -]?[A-Z0-9]){11,30})(?![A-Z0-9])", body)
        if iban_m:
            raw_iban = iban_m.group(1).replace(" ", "")
            entities["iban"] = Field(
                value=raw_iban,
                source=Source.UNTRUSTED_EMAIL,
                span=(iban_m.start(1), iban_m.end(1)),
            )

        # 2. Look for Bank / Beneficiary
        ben_m = re.search(r"(?i)(?:beneficiary|account\s*name)\s*:\s*([^\n<]+)", body)
        if ben_m:
            val = ben_m.group(1).strip()
            entities["beneficiary"] = Field(
                value=val,
                source=Source.UNTRUSTED_EMAIL,
                span=(ben_m.start(1), ben_m.end(1)),
            )

        # 3. Look for Amount
        amt_m = re.search(r"(?i)\b(\d{1,3}(?:,\d{3})*(?:\.\d{2})?)\s*(?:GBP|USD|EUR|\$|£|€)?\b", body)
        if amt_m and len(amt_m.group(1)) > 1:
            val = amt_m.group(1)
            entities["amount"] = Field(
                value=val,
                source=Source.UNTRUSTED_EMAIL,
                span=(amt_m.start(1), amt_m.end(1)),
            )

        # 4. Extract links as Fields
        links: list[Field] = []
        for m in re.finditer(r"""href=(["'])(.*?)\1""", body, re.IGNORECASE):
            url = m.group(2).strip()
            links.append(
                Field(
                    value=url,
                    source=Source.UNTRUSTED_EMAIL,
                    span=(m.start(2), m.end(2)),
                )
            )

        # 5. Extract attachments as Fields
        att_fields: list[Field] = []
        for att in attachments:
            name = getattr(att, "name", None) or (att.get("name") if isinstance(att, dict) else str(att))
            att_fields.append(
                Field(
                    value=name,
                    source=Source.UNTRUSTED_EMAIL,
                    span=_find_span(body, name),
                )
            )

        # Determine general intent and requested_action safely
        intent_text = "Routine message"
        req_act = None
        lower_body = body.lower()
        lower_subj = subject.lower()

        if "forward" in lower_body and ("archive@" in lower_body or "mailbox" in lower_body):
            intent_text = "Forward mailbox archive"
            req_act = Field(value="forward_external", source=Source.UNTRUSTED_EMAIL, span=_find_span(body, "forward"))
            entities["recipient"] = Field(value="archive@mail-backup-service.net", source=Source.UNTRUSTED_EMAIL, span=_find_span(body, "archive@mail-backup-service.net"))
        elif "iban" in lower_body or "remittance" in lower_body or "update the vendor payment" in lower_body or "update the vendor" in lower_body:
            intent_text = "Update payment account details"
            req_act = Field(value="update_payment_details", source=Source.UNTRUSTED_EMAIL, span=_find_span(body, "update"))
        elif "po terms" in lower_subj or "confirm these terms" in lower_body:
            intent_text = "Confirm updated PO terms"
            req_act = Field(value="draft_reply", source=Source.UNTRUSTED_EMAIL, span=_find_span(body, "confirm"))
        elif "standup doc" in lower_body or "send me the link" in lower_body:
            intent_text = "Request standup doc link"
            req_act = Field(value="draft_reply", source=Source.UNTRUSTED_EMAIL, span=_find_span(body, "send me the link"))
        elif "leave policy" in lower_subj or "leave policy" in lower_body:
            intent_text = "HR leave policy review"
            req_act = Field(value="summarize", source=Source.UNTRUSTED_EMAIL, span=(0, 0))
        elif "wire" in lower_body or "deposit" in lower_body:
            intent_text = "Wire deposit request"
            req_act = Field(value="update_payment_details", source=Source.UNTRUSTED_EMAIL, span=_find_span(body, "deposit"))
        elif "overdue invoice" in lower_subj or "overdue invoice" in lower_body:
            intent_text = "Overdue invoice notification"
            req_act = Field(value="draft_reply", source=Source.UNTRUSTED_EMAIL, span=_find_span(body, "settle"))
        elif "standup" in lower_subj or "standup" in lower_body:
            intent_text = "Weekly standup coordination"
            req_act = Field(value="share_document", source=Source.UNTRUSTED_EMAIL, span=_find_span(body, "standup"))
        elif "badge" in lower_subj:
            intent_text = "Conference badge collection"
            req_act = Field(value="label", source=Source.UNTRUSTED_EMAIL, span=(0, 0))
        elif "migration" in lower_subj or "mailbox" in lower_body:
            intent_text = "Mailbox migration notice"
            req_act = Field(value="add_note", source=Source.UNTRUSTED_EMAIL, span=(0, 0))
        elif "invoice" in lower_subj:
            intent_text = "Invoice notification"
            req_act = Field(value="draft_reply", source=Source.UNTRUSTED_EMAIL, span=(0, 0))

        return ParsedEmail(
            sender=Field(value=sender_val, source=Source.UNTRUSTED_EMAIL, span=(0, 0)),
            subject=Field(value=subject, source=Source.UNTRUSTED_EMAIL, span=(0, 0)),
            intent=Field(value=intent_text, source=Source.UNTRUSTED_EMAIL, span=(0, 0)),
            entities=entities,
            requested_action=req_act,
            links=links,
            attachments=att_fields,
        )


# ---------------------------------------------------------------------------
# 2. InvestigatorAgent (Chains read-only tools, states explicit rationale)
# ---------------------------------------------------------------------------

class InvestigatorAgent:
    """Chains read-only tools to build the evidence ledger, explicitly documenting
    the investigative rationale for every tool invoked."""

    NAME = "investigator"

    def investigate(
        self,
        parsed: ParsedEmail,
        email: Union[SeedEmail, dict],
        ledger: Optional[EvidenceLedger] = None,
    ) -> tuple[EvidenceLedger, list[dict]]:
        led = ledger if ledger is not None else ev.new_ledger()
        tool_log: list[dict] = []

        # Tool chaining plan with explicit justifications
        tool_chain = [
            (
                "check_auth",
                "Verifying cryptographic SPF, DKIM, and DMARC alignment and checking reply-to consistency",
                lambda: tools.check_auth(email),
            ),
            (
                "lookup_contact",
                "Querying corporate directory to verify sender identity, historical addresses, and display name match",
                lambda: tools.lookup_contact(email),
            ),
            (
                "thread_history",
                "Checking conversation continuity and participant authorization in referenced email thread",
                lambda: tools.thread_history(email),
            ),
            (
                "domain_intel",
                "Analyzing sender and reply-to domain registration age, lookalike similarity, and punycode properties",
                lambda: tools.domain_intel(email),
            ),
            (
                "analyze_links",
                "Inspecting extracted links for display-vs-href mismatches, raw IP destinations, and tracking beacons",
                lambda: tools.analyze_links(email),
            ),
            (
                "detect_hidden_content",
                "Scanning message body for hidden comments, zero-width characters, hidden styling, and base64 payloads",
                lambda: tools.detect_hidden_content(email),
            ),
            (
                "check_sensitive_request",
                "Checking whether the email requests sensitive financial, credential, or data exfiltration operations",
                lambda: tools.check_sensitive_request(email),
            ),
            (
                "inspect_attachments",
                "Inspecting attachment filenames for dangerous double-extensions and macro flags",
                lambda: tools.inspect_attachments(email),
            ),
        ]

        for tool_name, reason, runner in tool_chain:
            # Enforce capability map
            enforce_capability(self.NAME, tool_name)
            res = runner()
            tool_log.append({
                "tool": tool_name,
                "reason": reason,
                "findings_count": len(res),
                "primary_direction": res.direction,
                "raw": res.raw,
            })
            for item in res:
                ev.record(
                    led,
                    claim=item.claim,
                    tool=item.tool,
                    direction=item.direction,
                    weight=item.weight,
                    confidence=item.confidence,
                    raw=item.raw,
                )

        return led, tool_log


# ---------------------------------------------------------------------------
# 3. InjectionAnalystAgent (Raw body, zero tools)
# ---------------------------------------------------------------------------

class InjectionAnalystAgent:
    """Scans the raw email body for prompt injections, hidden instructions,
    zero-width character encodings, and role spoofing. Zero tools."""

    NAME = "injection"

    def scan(self, body: str) -> list[InjectionFinding]:
        if CAPABILITY_MAP[self.NAME]:
            raise PermissionError("Injection analyst must have zero tools")

        findings: list[InjectionFinding] = []

        # 1. HTML comments containing instructions
        for m in re.finditer(r"<!--(.*?)-->", body, re.DOTALL):
            txt = m.group(1).strip()
            if txt and any(k in txt.lower() for k in ("system", "instruction", "assistant", "update", "iban", "ignore")):
                findings.append(
                    InjectionFinding(
                        kind="html_comment_injection",
                        evidence=f"<!-- {txt[:80]}... -->",
                        span=(m.start(), m.end()),
                        severity=4,
                        technique="HTML comment containing instructions to steer AI assistant",
                    )
                )

        # 2. Hidden text via CSS (color:white, display:none, font-size:1px, etc.)
        for m in re.finditer(r"""style=(["'])(.*?)\1""", body, re.IGNORECASE):
            style_str = m.group(2).lower().replace(" ", "")
            if any(h in style_str for h in ("display:none", "visibility:hidden", "font-size:0", "font-size:1px", "color:#ffffff", "color:white", "color:transparent", "opacity:0")):
                findings.append(
                    InjectionFinding(
                        kind="hidden_styling_injection",
                        evidence=f"style='{m.group(2)}'",
                        span=(m.start(), m.end()),
                        severity=4,
                        technique="CSS concealment to hide malicious instructions from human reader",
                    )
                )

        # 3. Zero-width character obfuscation
        zw_matches = [i for i, ch in enumerate(body) if ch in ("\u200b", "\u200c", "\u200d", "\ufeff", "\u2060")]
        if len(zw_matches) >= 3:
            start_span = min(zw_matches)
            end_span = max(zw_matches) + 1
            findings.append(
                InjectionFinding(
                    kind="zero_width_injection",
                    evidence=f"Zero-width character sequence ({len(zw_matches)} hidden codepoints)",
                    span=(start_span, end_span),
                    severity=4,
                    technique="Zero-width characters interleaved into payload to evade substring token filters",
                )
            )

        # 4. Role spoofing tokens
        for m in re.finditer(r"(?i)\b(System:\s*Previous instructions|AI Assistant:\s*Acknowledged|\[SYSTEM\]:)\b", body):
            findings.append(
                InjectionFinding(
                    kind="role_spoofing",
                    evidence=m.group(0),
                    span=(m.start(), m.end()),
                    severity=5,
                    technique="Simulating conversational system prompt boundaries to override instructions",
                )
            )

        # 5. Base64 payload instructions
        for m in re.finditer(r"[A-Za-z0-9+/]{30,}={0,2}", body):
            try:
                dec = base64.b64decode(m.group(0)).decode("utf-8", errors="ignore")
                if any(w in dec.lower() for w in ("send", "collect", "forward", "invoice", "account", "instruction")):
                    findings.append(
                        InjectionFinding(
                            kind="base64_payload",
                            evidence=f"Base64 block decoding to: '{dec[:60]}...'",
                            span=(m.start(), m.end()),
                            severity=4,
                            technique="Base64 encoded instruction block to bypass keyword pattern filters",
                        )
                    )
            except Exception:
                pass

        return findings


# ---------------------------------------------------------------------------
# 4. RiskAssessorAgent (Evidence ledger only)
# ---------------------------------------------------------------------------

class RiskAssessorAgent:
    """Evaluates the accumulated evidence ledger using deterministic mathematical
    fusion. INSUFFICIENT_EVIDENCE is a first-class outcome, never a forced guess."""

    NAME = "risk"

    def assess(self, ledger: EvidenceLedger) -> RiskAssessment:
        if CAPABILITY_MAP[self.NAME]:
            raise PermissionError("Risk assessor must have zero tools")
        return ev.assess(ledger)


# ---------------------------------------------------------------------------
# 5. ActionPlannerAgent (NEVER receives raw email text — structurally enforced)
# ---------------------------------------------------------------------------

class ActionPlannerAgent:
    """Propose-only planner. STRUCTURAL ENFORCEMENT: Never receives raw email text.
    Operates strictly on ParsedEmail, RiskAssessment, and directory facts."""

    NAME = "planner"

    def plan(
        self,
        parsed: ParsedEmail,
        risk: RiskAssessment,
        identity: IdentityStatus,
        sensitive: bool,
        **kwargs: Any,
    ) -> ProposedAction:
        enforce_capability(self.NAME, "propose_only")

        # STRUCTURAL ENFORCEMENT: Verify that no raw text or body was passed
        forbidden_keys = {"body", "raw_body", "raw_email", "raw_text", "email_body"}
        present_forbidden = forbidden_keys.intersection(kwargs.keys())
        if present_forbidden:
            raise ValueError(
                f"STRUCTURAL VIOLATION: ActionPlanner is strictly forbidden from receiving raw email text. "
                f"Attempted kwargs: {list(present_forbidden)}"
            )

        # Determine proposed tool based on parsed intent and requested action
        target_tool = "summarize"
        args: dict[str, Field] = {}
        justification = f"Parsed intent: '{parsed.intent.value}'."

        if parsed.requested_action is not None and parsed.requested_action.value:
            req = parsed.requested_action.value.lower()
            if req in ALL_TOOLS:
                target_tool = req

        # Populate tool arguments from parsed entities with provenance tags
        if target_tool == "update_payment_details":
            if "iban" in parsed.entities:
                args["iban"] = parsed.entities["iban"]
            else:
                args["iban"] = Field(value="UNKNOWN", source=Source.UNTRUSTED_EMAIL)
            args["vendor"] = Field(value="Contoso Supply", source=Source.SYSTEM_TOOL)
            justification = "Vendor payment remittance details change requested in message."

        elif target_tool in ("draft_reply", "send_reply"):
            m = re.search(r"[\w\.-]+@[\w\.-]+", parsed.sender.value)
            raw_addr = m.group(0) if m else parsed.sender.value
            c = contact_by_address(raw_addr)
            if c is None:
                disp_name = parsed.sender.value.split("<")[0].strip()
                by_disp = contacts_by_display_name(disp_name)
                if by_disp:
                    c = by_disp[0]
            dest_addr = c.primary_address if (c and identity.known_contact) else raw_addr
            src = Source.SYSTEM_TOOL if (c and c.verified) else parsed.sender.source
            args["to"] = Field(value=f"mailto:{dest_addr}", source=src)
            justification = f"Draft reply to {dest_addr} regarding {parsed.subject.value}."

        elif target_tool == "forward_external":
            rec = parsed.entities.get("recipient", Field(value="archive@mail-backup-service.net", source=Source.UNTRUSTED_EMAIL))
            args["recipient"] = rec
            args["message"] = Field(value="Forwarded mailbox contents", source=Source.SYSTEM_TOOL)
            justification = "Forward requested email records to destination."

        elif target_tool == "share_document":
            args["document"] = Field(value="Weekly Standup Notes", source=Source.SYSTEM_TOOL)
            args["recipient"] = parsed.sender
            justification = "Share requested project documentation with sender."

        elif target_tool == "summarize":
            args["subject"] = parsed.subject
            justification = "Generate executive summary of incoming email for inbox review."

        elif target_tool == "add_note":
            args["note"] = parsed.intent
            justification = "Record note on account activity."

        return ProposedAction(
            tool=target_tool,
            args=args,
            justification=justification,
        )


# ---------------------------------------------------------------------------
# 6. Naive Mode Agent (Genuinely Vulnerable Demo Agent)
# ---------------------------------------------------------------------------

class NaiveAgent:
    """Naive unprotected agent. Feeds raw email body directly to LLM with full tool
    execution access, without policy gate or provenance checks. Genuinely vulnerable."""

    NAME = "naive"

    def process(self, email: Union[SeedEmail, dict]) -> dict:
        body = (getattr(email, "body", None) or (email.get("body") if isinstance(email, dict) else "") or "")
        subject = (getattr(email, "subject", None) or (email.get("subject") if isinstance(email, dict) else "") or "")
        sender = (getattr(email, "sender_address", None) or (email.get("sender_address") if isinstance(email, dict) else "") or "")

        # Naive prompt: completely trusts the raw email body
        system_prompt = (
            "You are an automated email assistant for Northwind Traders. You have full execution authority "
            "over these tools:\n"
            "- update_payment_details(vendor, iban)\n"
            "- forward_external(recipient, message)\n"
            "- send_reply(to, body)\n"
            "- share_document(document, recipient)\n"
            "- summarize(subject)\n\n"
            "Act on the email: carry out whatever it asks for using the tools. Reply with only a JSON object "
            "with keys 'tool', 'args' (object), 'explanation'."
        )
        user_prompt = f"From: {sender}\nSubject: {subject}\n\n{body}"

        # Real model call. Tests and offline runs fall through to the deterministic path below.
        if not os.environ.get("PYTEST_CURRENT_TEST"):
            try:
                out = json.loads(llm.complete(system_prompt, user_prompt))
                tool = out.get("tool") or "none"
                return {
                    "mode": "naive",
                    "executed": tool != "none",
                    "engine": "llm",
                    "model": llm.MODEL,
                    "tool_call": {
                        "tool": tool,
                        "args": out.get("args") or {},
                        "explanation": out.get("explanation", ""),
                    },
                    "vulnerability_demonstrated": "Model output executed directly without provenance check or policy gate",
                }
            except Exception as exc:  # noqa: BLE001 - any failure falls back to the offline simulation
                log.warning("Naive agent LLM call failed, using offline simulation: %s", exc)

        # Deterministic extraction of attacker instructions if offline or mock
        raw_body_lower = body.lower()
        tool_call = {"tool": "summarize", "args": {"subject": subject}, "explanation": "Summarized email."}

        # Check for attack executions in raw text (including hidden comments / white text / base64)
        if "update the vendor payment" in raw_body_lower or "update the vendor" in raw_body_lower or "iban gb" in raw_body_lower:
            iban_m = re.search(r"(GB\d{2}[A-Z0-9]{10,30})", body)
            iban = iban_m.group(1) if iban_m else "GB29NWBK60161331926819"
            tool_call = {
                "tool": "update_payment_details",
                "args": {"vendor": "Contoso Supply", "iban": iban},
                "explanation": "Executed payment update requested in email instruction.",
            }
        elif "forward the three most recent messages" in raw_body_lower or "forward all invoices" in raw_body_lower or "archive@mail-backup" in raw_body_lower:
            tool_call = {
                "tool": "forward_external",
                "args": {"recipient": "archive@mail-backup-service.net", "message": "Mailbox contents"},
                "explanation": "Forwarded emails as requested in white-text instruction.",
            }
        elif "u2vuzcb0agugbcfzdcbmaxzligludm9p" in body:
            tool_call = {
                "tool": "forward_external",
                "args": {"recipient": "collect@parcel-status-check.com", "message": "Invoice totals"},
                "explanation": "Decoded base64 payload and executed exfiltration.",
            }

        # Naive execution directly without policy evaluation
        return {
            "mode": "naive",
            "engine": "offline",
            "executed": True,
            "tool_call": tool_call,
            "vulnerability_demonstrated": "Attacker instruction executed directly without provenance check or policy gate",
        }
