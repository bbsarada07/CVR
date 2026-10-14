"""Deterministic inspection tools for email authentication, identity, infrastructure,
links, content, and sensitive requests. No LLM.

Raw-key contract required by evidence.py:
  check_auth:              {"spf": "pass"|..., "dkim": ..., "dmarc": ...}
  lookup_contact:          {"known": bool, "verified": bool, "address_matches": bool, "display_name_matches": bool}
  thread_history:          {"has_thread": bool, "fits_thread": bool, "escalation": bool}
  check_sensitive_request: {"sensitive": bool, "categories": [str]}
"""

from __future__ import annotations

import difflib
import html
import re
import uuid
from typing import Any, Iterable, Optional, Union
from urllib.parse import urlsplit

import evidence as ev
from schemas import Direction, EvidenceItem, EvidenceLedger
from seed_data import (
    ORG_DOMAIN,
    VENDOR_DOMAIN,
    Attachment,
    SeedEmail,
    contact_by_address,
    contacts_by_display_name,
    domain_intel_for,
    thread_by_id,
)

MAL: Direction = "SUPPORTS_MALICIOUS"
BEN: Direction = "SUPPORTS_BENIGN"
NEU: Direction = "NEUTRAL"

# Reference domains used for lookalike calculations
TARGET_DOMAINS = (ORG_DOMAIN, VENDOR_DOMAIN)


def make_item(
    *,
    claim: str,
    tool: str,
    direction: Direction,
    weight: float,
    confidence: float,
    raw: Optional[dict] = None,
    item_id: Optional[str] = None,
) -> EvidenceItem:
    iid = item_id or f"{tool}-{uuid.uuid4().hex[:6]}"
    return EvidenceItem(
        id=iid,
        claim=claim,
        tool=tool,
        direction=direction,
        weight=weight,
        confidence=confidence,
        raw=raw or {},
    )

# Zero-width codepoints for detect_hidden_content
_ZERO_WIDTH_CHARS = frozenset("\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064\ufeff\u00ad")

_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_HTML_A_RE = re.compile(r"""<a\s+(?:[^>]*?\s+)?href=(["'])(.*?)\1[^>]*>(.*?)</a>""", re.IGNORECASE | re.DOTALL)
_HTML_IMG_RE = re.compile(r"""<img\s+(?:[^>]*?\s+)?src=(["'])(.*?)\1[^>]*>""", re.IGNORECASE | re.DOTALL)
_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_STYLE_TAG_OR_ATTR_RE = re.compile(r"""style=(["'])(.*?)\1""", re.IGNORECASE | re.DOTALL)

# Patterns for sensitive request checks
_IBAN_RE = re.compile(r"(?<![A-Z0-9])[A-Z]{2}\d{2}(?:[ -]?[A-Z0-9]){11,30}(?![A-Z0-9])")
_FINANCIAL_RE = re.compile(
    r"(?i)\b(?:iban|sort\s*code|routing\s*(?:number)?|bank\s*account|account\s*(?:number)?|wire\s*(?:transfer)?|remittance|beneficiary|payment\s*terms|deposit|overdue\s*invoice|settle\s*account|purchase\s*order|po-\d+)\b"
)
_CREDENTIAL_RE = re.compile(
    r"(?i)\b(?:password|credential|login|verify\s*portal|sso|2fa|mfa|token|mailbox\s*migration|reset\s*password)\b"
)
_EXFILTRATION_RE = re.compile(
    r"(?i)\b(?:forward\s*(?:all\s*)?(?:messages|invoices|mail)|archive@|compliance\s*retention|backup\s*service)\b"
)
_CONFIDENTIAL_RE = re.compile(
    r"(?i)\b(?:acquisition\s*deposit|board\s*deck|strictly\s*confidential|discretion\s*matters)\b"
)


class ToolResult(list):
    """A list of EvidenceItems returned by a tool, with convenience accessors
    for callers that expect a single item or raw dict."""

    @property
    def item(self) -> EvidenceItem:
        if not self:
            raise IndexError("ToolResult is empty")
        return self[0]

    @property
    def raw(self) -> dict:
        return self.item.raw if self else {}

    @property
    def direction(self) -> Direction:
        return self.item.direction if self else NEU


def _email_attr(email: Any, attr: str, default: Any = None) -> Any:
    if email is None:
        return default
    if isinstance(email, dict):
        return email.get(attr, default)
    return getattr(email, attr, default)


# ---------------------------------------------------------------------------
# Tool 1: check_auth
# ---------------------------------------------------------------------------

def check_auth(
    email: Optional[Union[SeedEmail, dict]] = None,
    *,
    sender_address: Optional[str] = None,
    spf: Optional[str] = None,
    dkim: Optional[str] = None,
    dmarc: Optional[str] = None,
    reply_to: Optional[str] = None,
) -> ToolResult:
    """Check SPF, DKIM, DMARC alignment and reply-to consistency."""
    addr = (sender_address or _email_attr(email, "sender_address") or "").strip().lower()
    s = (spf or _email_attr(email, "spf") or "none").strip().lower()
    dk = (dkim or _email_attr(email, "dkim") or "none").strip().lower()
    dm = (dmarc or _email_attr(email, "dmarc") or "none").strip().lower()
    rep = reply_to if reply_to is not None else _email_attr(email, "reply_to")

    sender_domain = addr.rpartition("@")[2]
    reply_domain = rep.strip().lower().rpartition("@")[2] if rep else ""
    reply_differs = bool(rep and reply_domain and reply_domain != sender_domain)

    all_pass = (s == "pass" and dk == "pass" and dm == "pass")
    items: list[EvidenceItem] = []

    if all_pass:
        if reply_differs:
            # Benign authentication pass on sender domain
            items.append(
                make_item(
                    claim=f"SPF, DKIM, and DMARC authentication all pass for {addr}",
                    tool="check_auth",
                    direction=BEN,
                    weight=0.35,
                    confidence=0.90,
                    raw={"spf": s, "dkim": dk, "dmarc": dm, "reply_to_differs": True, "reply_to": rep},
                )
            )
            # Malicious signal: reply-to directs responses to a disparate domain
            items.append(
                make_item(
                    claim=f"Reply-to domain '{reply_domain}' differs from sender domain '{sender_domain}'",
                    tool="check_auth",
                    direction=MAL,
                    weight=0.65,
                    confidence=0.90,
                    raw={"spf": s, "dkim": dk, "dmarc": dm, "reply_to_differs": True, "reply_to": rep},
                )
            )
        else:
            items.append(
                make_item(
                    claim=f"SPF, DKIM, and DMARC authentication all pass for {addr}",
                    tool="check_auth",
                    direction=BEN,
                    weight=0.35,
                    confidence=0.95,
                    raw={"spf": s, "dkim": dk, "dmarc": dm, "reply_to_differs": False},
                )
            )
    else:
        results_str = f"spf={s}, dkim={dk}, dmarc={dm}"
        items.append(
            make_item(
                claim=f"Email authentication failed for {addr}: {results_str}",
                tool="check_auth",
                direction=MAL,
                weight=0.65,
                confidence=0.95,
                raw={"spf": s, "dkim": dk, "dmarc": dm, "reply_to_differs": reply_differs},
            )
        )

    return ToolResult(items)


# ---------------------------------------------------------------------------
# Tool 2: lookup_contact
# ---------------------------------------------------------------------------

def lookup_contact(
    email: Optional[Union[SeedEmail, dict]] = None,
    *,
    sender_address: Optional[str] = None,
    sender_display: Optional[str] = None,
) -> ToolResult:
    """Look up sender in the corporate directory by address and display name."""
    addr = (sender_address or _email_attr(email, "sender_address") or "").strip().lower()
    disp = (sender_display or _email_attr(email, "sender_display") or "").strip()

    c_by_addr = contact_by_address(addr) if addr else None
    items: list[EvidenceItem] = []

    if c_by_addr is not None:
        disp_matches = (c_by_addr.display_name.strip().casefold() == disp.casefold())
        raw = {
            "known": True,
            "verified": c_by_addr.verified,
            "address_matches": True,
            "display_name_matches": disp_matches,
            "contact_name": c_by_addr.display_name,
            "org": c_by_addr.org,
        }
        if disp_matches:
            items.append(
                make_item(
                    claim=f"Sender {addr} matches verified contact '{c_by_addr.display_name}' ({c_by_addr.org})",
                    tool="lookup_contact",
                    direction=BEN,
                    weight=0.60,
                    confidence=0.90,
                    raw=raw,
                )
            )
        else:
            items.append(
                make_item(
                    claim=f"Sender address {addr} matches directory contact '{c_by_addr.display_name}', but display name '{disp}' differs",
                    tool="lookup_contact",
                    direction=MAL,
                    weight=0.50,
                    confidence=0.85,
                    raw=raw,
                )
            )
        return ToolResult(items)

    # Address was not found in directory; check if display name matches a known person
    matched_contacts = contacts_by_display_name(disp) if disp else []
    if matched_contacts:
        expected = matched_contacts[0]
        raw = {
            "known": True,
            "verified": expected.verified,
            "address_matches": False,
            "display_name_matches": True,
            "contact_name": expected.display_name,
            "expected_address": expected.primary_address,
        }
        items.append(
            make_item(
                claim=f"Display name '{disp}' matches directory contact, but sender address {addr} is not on file (expected {expected.primary_address})",
                tool="lookup_contact",
                direction=MAL,
                weight=0.55,
                confidence=0.90,
                raw=raw,
            )
        )
        return ToolResult(items)

    # Completely unknown sender
    raw = {
        "known": False,
        "verified": False,
        "address_matches": False,
        "display_name_matches": False,
    }
    items.append(
        make_item(
            claim=f"Sender {addr or disp} is not in the corporate contact directory",
            tool="lookup_contact",
            direction=MAL,
            weight=0.50,
            confidence=0.85,
            raw=raw,
        )
    )
    return ToolResult(items)


# ---------------------------------------------------------------------------
# Tool 3: thread_history
# ---------------------------------------------------------------------------

def thread_history(
    email: Optional[Union[SeedEmail, dict]] = None,
    *,
    thread_id: Optional[str] = None,
    sender_address: Optional[str] = None,
) -> ToolResult:
    """Inspect previous messages and participants in the referenced thread."""
    tid = thread_id if thread_id is not None else _email_attr(email, "thread_id")
    addr = (sender_address or _email_attr(email, "sender_address") or "").strip().lower()

    items: list[EvidenceItem] = []
    if not tid:
        raw = {"has_thread": False, "fits_thread": False, "escalation": False}
        items.append(
            make_item(
                claim="No prior thread referenced in this email",
                tool="thread_history",
                direction=NEU,
                weight=0.10,
                confidence=0.90,
                raw=raw,
            )
        )
        return ToolResult(items)

    thread = thread_by_id(tid)
    if thread is None:
        raw = {"has_thread": False, "fits_thread": False, "escalation": False, "unknown_thread_id": tid}
        items.append(
            make_item(
                claim=f"Referenced thread '{tid}' was not found in mailbox history",
                tool="thread_history",
                direction=NEU,
                weight=0.10,
                confidence=0.90,
                raw=raw,
            )
        )
        return ToolResult(items)

    participants = [p.lower() for p in thread.participants]
    is_participant = addr in participants

    if is_participant:
        raw = {
            "has_thread": True,
            "fits_thread": True,
            "escalation": False,
            "thread_id": thread.id,
            "subject": thread.subject,
            "messages_count": len(thread.messages),
        }
        items.append(
            make_item(
                claim=f"Email belongs to established thread '{thread.subject}' with {len(thread.messages)} prior messages",
                tool="thread_history",
                direction=BEN,
                weight=0.50,
                confidence=0.90,
                raw=raw,
            )
        )
    else:
        raw = {
            "has_thread": True,
            "fits_thread": False,
            "escalation": True,
            "thread_id": thread.id,
            "subject": thread.subject,
        }
        items.append(
            make_item(
                claim=f"Referenced thread '{thread.subject}' exists, but sender {addr} is not an authorized participant",
                tool="thread_history",
                direction=MAL,
                weight=0.50,
                confidence=0.85,
                raw=raw,
            )
        )

    return ToolResult(items)


# ---------------------------------------------------------------------------
# Tool 4: domain_intel
# ---------------------------------------------------------------------------

def _check_single_domain(domain: str) -> EvidenceItem:
    dom = domain.strip().lower().rstrip(".")
    is_ip = bool(_IPV4_RE.match(dom))
    is_puny = dom.startswith("xn--") or ".xn--" in dom

    # Lookalike check using difflib against target domains
    lookalike_target: Optional[str] = None
    best_sim: float = 0.0
    for target in TARGET_DOMAINS:
        if dom == target:
            continue
        sim = difflib.SequenceMatcher(None, dom, target).ratio()
        if sim >= 0.80 and sim > best_sim:
            best_sim = sim
            lookalike_target = target

    intel = domain_intel_for(dom)
    age_days = intel.registered_days_ago if intel else (0 if (is_ip or is_puny or lookalike_target) else 365)
    is_org = intel.is_org_domain if intel else False
    is_allowlisted = intel.is_allowlisted if intel else False
    is_public = intel.is_public_mail if intel else False
    puny_of = intel.punycode_of if intel else None

    raw = {
        "domain": dom,
        "age_days": age_days,
        "is_allowlisted": is_allowlisted,
        "is_org_domain": is_org,
        "is_public_mail": is_public,
        "is_ip_literal": is_ip,
        "is_punycode": is_puny,
        "punycode_of": puny_of,
        "lookalike_target": lookalike_target,
        "lookalike_similarity": round(best_sim, 3) if lookalike_target else None,
    }

    if is_allowlisted or is_org:
        return make_item(
            claim=f"Domain '{dom}' is legitimate corporate/allowlisted infrastructure ({age_days}d old)",
            tool="domain_intel",
            direction=BEN,
            weight=0.40,
            confidence=0.95,
            raw=raw,
        )

    if is_ip:
        return make_item(
            claim=f"Domain '{dom}' is a raw IP literal; no legitimate corporate domain attribution",
            tool="domain_intel",
            direction=MAL,
            weight=0.75,
            confidence=0.95,
            raw=raw,
        )

    if is_puny or puny_of:
        return make_item(
            claim=f"Domain '{dom}' is a punycode homograph ({puny_of or dom})",
            tool="domain_intel",
            direction=MAL,
            weight=0.75,
            confidence=0.95,
            raw=raw,
        )

    if lookalike_target:
        return make_item(
            claim=f"Domain '{dom}' is a lookalike of '{lookalike_target}' ({best_sim:.0%} similar, {age_days}d old)",
            tool="domain_intel",
            direction=MAL,
            weight=0.75,
            confidence=0.95,
            raw=raw,
        )

    if age_days < 30:
        return make_item(
            claim=f"Domain '{dom}' was registered very recently ({age_days} days ago)",
            tool="domain_intel",
            direction=MAL,
            weight=0.65,
            confidence=0.90,
            raw=raw,
        )

    if is_public:
        return make_item(
            claim=f"Domain '{dom}' is a public webmail provider; no organizational domain authentication possible",
            tool="domain_intel",
            direction=NEU,
            weight=0.10,
            confidence=0.90,
            raw=raw,
        )

    return make_item(
        claim=f"Domain '{dom}' is an external domain registered {age_days} days ago",
        tool="domain_intel",
        direction=NEU,
        weight=0.20,
        confidence=0.85,
        raw=raw,
    )


def domain_intel(
    email: Optional[Union[SeedEmail, dict]] = None,
    *,
    domain: Optional[str] = None,
    check_reply_to: bool = True,
) -> ToolResult:
    """Evaluate domain age, lookalike distance via difflib, and punycode/IP properties."""
    domains_to_check: list[str] = []
    if domain:
        domains_to_check.append(domain)
    elif email is not None:
        sender_addr = _email_attr(email, "sender_address") or ""
        s_dom = sender_addr.rpartition("@")[2]
        if s_dom:
            domains_to_check.append(s_dom)
        if check_reply_to:
            rep = _email_attr(email, "reply_to")
            if rep:
                r_dom = rep.rpartition("@")[2]
                if r_dom and r_dom != s_dom:
                    domains_to_check.append(r_dom)

    items: list[EvidenceItem] = []
    seen = set()
    for d in domains_to_check:
        clean = d.strip().lower()
        if clean and clean not in seen:
            seen.add(clean)
            items.append(_check_single_domain(clean))

    if not items:
        raw = {"domain": "unknown", "error": "No domain provided"}
        items.append(
            make_item(
                claim="No domain available for domain intelligence check",
                tool="domain_intel",
                direction=NEU,
                weight=0.10,
                confidence=0.80,
                raw=raw,
            )
        )

    return ToolResult(items)


# ---------------------------------------------------------------------------
# Tool 5: analyze_links
# ---------------------------------------------------------------------------

def analyze_links(
    email: Optional[Union[SeedEmail, dict]] = None,
    *,
    body: Optional[str] = None,
    sender_address: Optional[str] = None,
) -> ToolResult:
    """Analyze links for display-vs-href mismatches, punycode, raw IP, and tracking pixels."""
    raw_body = body if body is not None else (_email_attr(email, "body") or "")
    s_addr = (sender_address or _email_attr(email, "sender_address") or "").strip().lower()
    s_dom = s_addr.rpartition("@")[2]

    violations: list[str] = []
    found_links: list[dict] = []

    # Extract <a> tags
    for match in _HTML_A_RE.finditer(raw_body):
        href = match.group(2).strip()
        disp = re.sub(r"<[^>]*>", "", match.group(3)).strip()
        parsed_href = urlsplit(href)
        href_host = (parsed_href.hostname or "").lower()

        # Check raw IP
        if _IPV4_RE.match(href_host):
            violations.append(f"Raw IP href: '{href}' behind text '{disp}'")

        # Check punycode
        if "xn--" in href_host:
            violations.append(f"Punycode URL target: '{href_host}'")

        # Check display-vs-href mismatch
        disp_parsed = urlsplit(disp if "://" in disp else f"http://{disp}")
        disp_host = (disp_parsed.hostname or "").lower()
        if disp_host and "." in disp_host and href_host and disp_host != href_host:
            violations.append(f"Display mismatch: shown as '{disp}' but links to '{href_host}'")

        found_links.append({"href": href, "display": disp, "host": href_host})

    # Extract tracking images
    for match in _HTML_IMG_RE.finditer(raw_body):
        src = match.group(2).strip()
        img_host = (urlsplit(src).hostname or "").lower()
        if img_host and img_host != s_dom and img_host not in (ORG_DOMAIN, VENDOR_DOMAIN):
            violations.append(f"External image/pixel host: '{img_host}'")

    items: list[EvidenceItem] = []
    if not found_links and not violations:
        raw = {"has_links": False, "links_count": 0, "violations": []}
        items.append(
            make_item(
                claim="No external links or embedded tracking resources detected",
                tool="analyze_links",
                direction=NEU,
                weight=0.10,
                confidence=0.90,
                raw=raw,
            )
        )
    elif violations:
        raw = {"has_links": True, "links_count": len(found_links), "violations": violations}
        items.append(
            make_item(
                claim=f"Suspicious links detected: {'; '.join(violations[:3])}",
                tool="analyze_links",
                direction=MAL,
                weight=0.75,
                confidence=0.95,
                raw=raw,
            )
        )
    else:
        raw = {"has_links": True, "links_count": len(found_links), "violations": []}
        items.append(
            make_item(
                claim=f"All {len(found_links)} link(s) point to legitimate domains consistent with sender",
                tool="analyze_links",
                direction=BEN,
                weight=0.40,
                confidence=0.90,
                raw=raw,
            )
        )

    return ToolResult(items)


# ---------------------------------------------------------------------------
# Tool 6: detect_hidden_content
# ---------------------------------------------------------------------------

def detect_hidden_content(
    email: Optional[Union[SeedEmail, dict]] = None,
    *,
    body: Optional[str] = None,
) -> ToolResult:
    """Detect hidden HTML comments, zero-width characters, hidden CSS styling, and role spoofing."""
    raw_body = body if body is not None else (_email_attr(email, "body") or "")
    findings: list[str] = []

    # 1. HTML Comments
    for match in _HTML_COMMENT_RE.finditer(raw_body):
        content = match.group(1).strip()
        if content:
            preview = (content[:60] + "...") if len(content) > 60 else content
            findings.append(f"HTML comment containing text: <!-- {preview} -->")

    # 2. Zero-width characters
    zw_count = sum(1 for ch in raw_body if ch in _ZERO_WIDTH_CHARS)
    if zw_count > 0:
        findings.append(f"Zero-width character sequence detected ({zw_count} characters)")

    # 3. Hidden CSS styling
    for match in _STYLE_TAG_OR_ATTR_RE.finditer(raw_body):
        style_val = match.group(2).lower()
        if (
            "display:none" in style_val.replace(" ", "")
            or "visibility:hidden" in style_val.replace(" ", "")
            or "font-size:0" in style_val.replace(" ", "")
            or "font-size:1px" in style_val.replace(" ", "")
            or "color:#ffffff" in style_val.replace(" ", "")
            or "color:white" in style_val.replace(" ", "")
            or "color:transparent" in style_val.replace(" ", "")
            or "opacity:0" in style_val.replace(" ", "")
        ):
            findings.append(f"Hidden CSS styling attribute: style='{match.group(2)}'")

    # 4. Role spoofing text
    if re.search(r"(?i)\b(?:system:\s*previous\s*instructions|ai\s*assistant\s*note|system\s*instruction\s*for)\b", raw_body):
        findings.append("Role spoofing / system directive tokens detected in body")

    # 5. Base64 payload detection
    for token in re.findall(r"[A-Za-z0-9+/]{30,}={0,2}", raw_body):
        try:
            import base64
            decoded = base64.b64decode(token).decode("utf-8", errors="ignore")
            if any(w in decoded.lower() for w in ("send", "collect", "forward", "invoice", "account", "instruction", "system", "http")):
                findings.append(f"Base64 encoded instruction payload detected (decodes to: '{decoded[:50]}...')")
        except Exception:
            pass

    items: list[EvidenceItem] = []
    if findings:
        raw = {"hidden_detected": True, "findings": findings, "count": len(findings)}
        items.append(
            make_item(
                claim=f"Hidden/obfuscated content found in email body: {'; '.join(findings[:2])}",
                tool="detect_hidden_content",
                direction=MAL,
                weight=0.80,
                confidence=0.95,
                raw=raw,
            )
        )
    else:
        raw = {"hidden_detected": False, "findings": []}
        items.append(
            make_item(
                claim="No hidden text, comments, zero-width characters, or hidden styles found",
                tool="detect_hidden_content",
                direction=BEN,
                weight=0.30,
                confidence=0.90,
                raw=raw,
            )
        )

    return ToolResult(items)


# ---------------------------------------------------------------------------
# Tool 7: check_sensitive_request
# ---------------------------------------------------------------------------

def check_sensitive_request(
    email: Optional[Union[SeedEmail, dict]] = None,
    *,
    subject: Optional[str] = None,
    body: Optional[str] = None,
) -> ToolResult:
    """Identify if the email requests sensitive financial, credential, or exfiltration operations."""
    subj = subject if subject is not None else (_email_attr(email, "subject") or "")
    text = (body if body is not None else (_email_attr(email, "body") or "")) + " " + subj

    categories: list[str] = []
    if _IBAN_RE.search(text) or _FINANCIAL_RE.search(text):
        categories.append("financial_payment")
    if _CREDENTIAL_RE.search(text):
        categories.append("credential_access")
    if _EXFILTRATION_RE.search(text):
        categories.append("data_exfiltration")
    if _CONFIDENTIAL_RE.search(text):
        categories.append("confidential_operation")

    is_sensitive = bool(categories)
    raw = {"sensitive": is_sensitive, "categories": categories}

    items: list[EvidenceItem] = []
    if is_sensitive:
        items.append(
            make_item(
                claim=f"Request involves sensitive operations: {', '.join(categories)}",
                tool="check_sensitive_request",
                direction=NEU,
                weight=0.10,
                confidence=0.95,
                raw=raw,
            )
        )
    else:
        items.append(
            make_item(
                claim="Request does not involve sensitive operations (routine correspondence)",
                tool="check_sensitive_request",
                direction=NEU,
                weight=0.10,
                confidence=0.95,
                raw=raw,
            )
        )

    return ToolResult(items)


# ---------------------------------------------------------------------------
# Optional Tool: inspect_attachments
# ---------------------------------------------------------------------------

def inspect_attachments(
    email: Optional[Union[SeedEmail, dict]] = None,
    *,
    attachments: Optional[Iterable[Union[Attachment, dict]]] = None,
) -> ToolResult:
    """Inspect attachment filenames and metadata for double extensions, macros, or executables."""
    atts = attachments if attachments is not None else (_email_attr(email, "attachments") or ())
    items: list[EvidenceItem] = []
    suspicious: list[str] = []

    count = 0
    for att in atts:
        count += 1
        name = _email_attr(att, "name", "")
        macro = _email_attr(att, "macro_enabled", False)
        ctype = _email_attr(att, "content_type", "")

        # Check macro or double extension
        if macro or "macro" in ctype.lower():
            suspicious.append(f"Macro-enabled document: {name}")
        if re.search(r"\.(?:pdf|docx?|xlsx?)\.(?:docm|exe|vbs|js|bat|scr)$", name, re.IGNORECASE):
            suspicious.append(f"Double file extension: {name}")

    if suspicious:
        raw = {"attachments_count": count, "suspicious": suspicious}
        items.append(
            make_item(
                claim=f"Malicious attachment detected: {'; '.join(suspicious)}",
                tool="inspect_attachments",
                direction=MAL,
                weight=0.85,
                confidence=0.95,
                raw=raw,
            )
        )
    elif count > 0:
        raw = {"attachments_count": count, "suspicious": []}
        items.append(
            make_item(
                claim=f"All {count} attachment(s) have benign extensions and no macros",
                tool="inspect_attachments",
                direction=BEN,
                weight=0.30,
                confidence=0.90,
                raw=raw,
            )
        )
    else:
        raw = {"attachments_count": 0, "suspicious": []}
        items.append(
            make_item(
                claim="No attachments on this email",
                tool="inspect_attachments",
                direction=NEU,
                weight=0.10,
                confidence=0.90,
                raw=raw,
            )
        )

    return ToolResult(items)


# ---------------------------------------------------------------------------
# Pipeline runner
# ---------------------------------------------------------------------------

def run_all_tools(email: Union[SeedEmail, dict], ledger: Optional[EvidenceLedger] = None) -> EvidenceLedger:
    """Run all inspection tools on an email and record findings into a ledger."""
    led = ledger if ledger is not None else ev.new_ledger()
    for tool_fn in (
        check_auth,
        lookup_contact,
        thread_history,
        domain_intel,
        analyze_links,
        detect_hidden_content,
        check_sensitive_request,
        inspect_attachments,
    ):
        result = tool_fn(email)
        for item in result:
            ev.record(
                led,
                claim=item.claim,
                tool=item.tool,
                direction=item.direction,
                weight=item.weight,
                confidence=item.confidence,
                raw=item.raw,
            )
    return led
