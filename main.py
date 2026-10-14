"""FastAPI entry point: startup LLM check, /healthz, SENTINEL API endpoints, and the UI shell.

Boot never fails because of the LLM. If the key is missing, the model string is
wrong, or the network is down, we log the specific cause, keep serving, and show
a banner in the UI.

Endpoints:
  GET  /                     -> UI shell (index.html) with {{BANNER}}
  GET  /healthz              -> LLM reachability & system health
  GET  /api/emails           -> Seed email corpus (A1-A10, B1-B4, N1-N10)
  GET  /api/process          -> SSE stream of pipeline trace events
  POST /api/process          -> Execute pipeline (SSE or JSON)
  POST /api/evidence         -> Inject evidence & trigger reassessment loop
  POST /api/confirm          -> Human operator action confirmation / rejection
  GET  /api/audit            -> Execution audit logs & trace inspection
  GET  /api/capabilities     -> Agent capability matrix & security tiers
"""

from __future__ import annotations

import asyncio
import html
import json
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Union

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field as PField

from agents import ALL_TOOLS, CAPABILITY_MAP, READ_ONLY_TOOLS
from config import Settings, load_settings
import evidence as ev
from orchestrator import Orchestrator, OrchestratorResult
from schemas import Direction, EvidenceItem, TraceEvent
import seed_data as sd

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("app")

STATIC_DIR = Path(__file__).parent / "static"
PROBE_TIMEOUT_S = 10.0

# Global fallback stores (for test suites and lifespan-isolated contexts)
_RUNS: dict[str, OrchestratorResult] = {}
_ORCHESTRATOR = Orchestrator()


@dataclass
class LLMStatus:
    reachable: bool
    problem: str | None = None  # short machine-readable cause, None when reachable
    detail: str | None = None  # human-readable explanation for logs and the banner


def describe_llm_error(exc: Exception, model: str) -> LLMStatus:
    """Map an exception to a named problem (handles Anthropic & OpenAI errors; generic fallback for other providers)."""
    # 1. Anthropic SDK errors
    try:
        import anthropic as _ant
        if isinstance(exc, _ant.AuthenticationError):
            return LLMStatus(False, "bad_key", "API key was rejected (401). Check the key in .env.")
        if isinstance(exc, _ant.PermissionDeniedError):
            return LLMStatus(False, "key_forbidden", f"The API key is not allowed to use model '{model}' (403).")
        if isinstance(exc, _ant.NotFoundError):
            return LLMStatus(False, "bad_model", f"Model '{model}' was not found (404). Check MODEL in .env.")
        if isinstance(exc, _ant.BadRequestError):
            if "model" in str(exc).lower():
                return LLMStatus(False, "bad_model", f"Model '{model}' was rejected (400): {exc.message}")
            return LLMStatus(False, "bad_request", f"Test call was rejected (400): {exc.message}")
        if isinstance(exc, _ant.RateLimitError):
            return LLMStatus(False, "rate_limited", "The API is rate limiting this key (429). Try again shortly.")
        if isinstance(exc, _ant.APIStatusError):
            return LLMStatus(False, "api_error", f"The API returned HTTP {exc.status_code}: {exc.message}")
        if isinstance(exc, _ant.APITimeoutError):
            return LLMStatus(False, "no_network", f"The test call timed out after {PROBE_TIMEOUT_S:.0f}s. Check network access.")
        if isinstance(exc, _ant.APIConnectionError):
            return LLMStatus(False, "no_network", "Could not connect to the API endpoint. Check network access.")
    except ImportError:
        pass

    # 2. OpenAI SDK errors
    try:
        import openai as _oai
        if isinstance(exc, _oai.AuthenticationError):
            return LLMStatus(False, "bad_key", "API key was rejected (401). Check the key in .env.")
        if isinstance(exc, _oai.PermissionDeniedError):
            return LLMStatus(False, "key_forbidden", f"The API key is not allowed to use model '{model}' (403).")
        if isinstance(exc, _oai.NotFoundError):
            return LLMStatus(False, "bad_model", f"Model '{model}' was not found (404). Check MODEL in .env.")
        if isinstance(exc, _oai.BadRequestError):
            if "model" in str(exc).lower():
                return LLMStatus(False, "bad_model", f"Model '{model}' was rejected (400): {exc.message}")
            return LLMStatus(False, "bad_request", f"Test call was rejected (400): {exc.message}")
        if isinstance(exc, _oai.RateLimitError):
            return LLMStatus(False, "rate_limited", "The API is rate limiting this key (429). Try again shortly.")
        if isinstance(exc, _oai.APIStatusError):
            return LLMStatus(False, "api_error", f"The API returned HTTP {exc.status_code}: {exc.message}")
        if isinstance(exc, _oai.APITimeoutError):
            return LLMStatus(False, "no_network", f"The test call timed out after {PROBE_TIMEOUT_S:.0f}s. Check network access.")
        if isinstance(exc, _oai.APIConnectionError):
            return LLMStatus(False, "no_network", "Could not connect to the API endpoint. Check network access.")
    except ImportError:
        pass

    # Generic fallback
    status = getattr(exc, "status_code", None)
    if status == 401:
        return LLMStatus(False, "bad_key", f"API key rejected (401): {exc}")
    if status == 404:
        return LLMStatus(False, "bad_model", f"Model not found (404): {exc}")
    if status == 429:
        return LLMStatus(False, "rate_limited", f"Rate limited (429): {exc}")
    return LLMStatus(False, "unexpected", f"Unexpected error during test call: {type(exc).__name__}: {exc}")


async def probe_llm(settings: Settings) -> LLMStatus:
    """Make one minimal model call. Never raises."""
    if not settings.has_api_key:
        return LLMStatus(False, "missing_key", "LLM_API_KEY / ANTHROPIC_API_KEY not set. Copy .env.example to .env and add your key.")
    os.environ["LLM_API_KEY"] = settings.api_key
    os.environ["OPENAI_API_KEY"] = settings.api_key
    try:
        from llm import complete as llm_complete
        loop = asyncio.get_event_loop()
        await asyncio.wait_for(
            loop.run_in_executor(None, lambda: llm_complete("You are a health check.", "Reply with exactly: OK")),
            timeout=PROBE_TIMEOUT_S,
        )
    except Exception as exc:  # noqa: BLE001 - boot must never crash
        return describe_llm_error(exc, settings.model)
    return LLMStatus(True)



@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.started_at = time.monotonic()
    app.state.settings = load_settings()
    app.state.runs = _RUNS
    app.state.orchestrator = _ORCHESTRATOR
    settings = app.state.settings
    log.info(
        "Starting up: provider=%s model=%s base_url=%s allowed_domains=%s",
        settings.provider, settings.model, settings.base_url,
        ",".join(settings.allowed_domains) or "(none)",
    )

    try:
        status = await probe_llm(settings)
    except Exception as exc:  # noqa: BLE001 - belt and braces; probe_llm should not raise
        status = LLMStatus(False, "unexpected", f"Startup check crashed: {type(exc).__name__}: {exc}")
    app.state.llm = status

    if status.reachable:
        log.info("LLM check passed: provider %s model %s is reachable", settings.provider, settings.model)
    else:
        log.error("LLM check FAILED [%s]: %s Serving the UI in degraded mode.", status.problem, status.detail)
    yield


app = FastAPI(title="SENTINEL", lifespan=lifespan)


# ---------------------------------------------------------------------------
# Error Handlers: Clean JSON errors, never a stack trace
# ---------------------------------------------------------------------------

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": "http_error", "detail": str(exc.detail), "status_code": exc.status_code},
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"error": "validation_error", "detail": str(exc), "status_code": 422},
    )


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    return JSONResponse(
        status_code=400,
        content={"error": "invalid_request", "detail": str(exc), "status_code": 400},
    )


@app.exception_handler(PermissionError)
async def permission_error_handler(request: Request, exc: PermissionError):
    return JSONResponse(
        status_code=403,
        content={"error": "permission_denied", "detail": str(exc), "status_code": 403},
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    log.error("Unhandled server exception: %s", exc, exc_info=False)
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_error",
            "detail": "An internal error occurred. Stack traces are suppressed for security.",
            "status_code": 500,
        },
    )


# ---------------------------------------------------------------------------
# Request / Response Models & Helpers
# ---------------------------------------------------------------------------

class ProcessRequest(BaseModel):
    email_id: Optional[str] = None
    sentinel_enabled: bool = True
    subject: Optional[str] = None
    body: Optional[str] = None
    sender: Optional[str] = None


class EvidenceRequest(BaseModel):
    run_id: str
    claim: str
    tool: str = "analyst"
    direction: Direction = "SUPPORTS_BENIGN"
    weight: float = PField(default=0.9, ge=0.0, le=1.0)
    confidence: float = PField(default=0.95, ge=0.0, le=1.0)
    raw: dict = PField(default_factory=dict)
    trigger: str = "analyst_evidence"


class ConfirmRequest(BaseModel):
    run_id: str
    confirmed: bool
    note: Optional[str] = None


def serialize_result(res: OrchestratorResult) -> dict[str, Any]:
    """Serialize OrchestratorResult to a JSON-compatible dictionary."""
    return {
        "run_id": res.run_id,
        "sentinel_enabled": res.sentinel_enabled,
        "email_id": res.email_id,
        "verdict": res.verdict,
        "rule_id": res.rule_id,
        "parsed": res.parsed.model_dump() if res.parsed else None,
        "ledger": res.ledger.model_dump() if res.ledger else None,
        "risk": res.risk.model_dump() if res.risk else None,
        "injection_findings": [f.model_dump() for f in res.injection_findings],
        "action": res.action.model_dump() if res.action else None,
        "decision": res.decision.model_dump() if res.decision else None,
        "naive_result": res.naive_result,
        "traces": [t.model_dump() for t in res.traces],
        "total_ms": res.total_ms,
    }


def resolve_email(
    email_id: Optional[str] = None,
    subject: Optional[str] = None,
    body: Optional[str] = None,
    sender: Optional[str] = None,
) -> Union[sd.SeedEmail, dict[str, Any]]:
    """Lookup email by ID or construct a custom synthetic email object."""
    if email_id and email_id != "custom":
        found = sd.email_by_id(email_id)
        if found is not None:
            return found
    return {
        "id": email_id or f"custom-{uuid.uuid4().hex[:6]}",
        "sender_address": sender or "attacker@external-untrusted.org",
        "sender_display": sender or "External Contact",
        "subject": subject or "Invoice & Payment Notification",
        "body": body or "Please update payment account to GB29NWBK60161331926819 immediately.",
        "headers": {},
        "attachments": [],
    }


def get_store() -> tuple[dict[str, OrchestratorResult], Orchestrator]:
    """Retrieve the run cache and orchestrator from app.state or fallback."""
    runs = getattr(app.state, "runs", None)
    if runs is None:
        runs = _RUNS
        app.state.runs = runs
    orch = getattr(app.state, "orchestrator", None)
    if orch is None:
        orch = _ORCHESTRATOR
        app.state.orchestrator = orch
    return runs, orch


# ---------------------------------------------------------------------------
# Core Endpoints
# ---------------------------------------------------------------------------

@app.get("/healthz")
async def healthz():
    llm: LLMStatus = getattr(app.state, "llm", LLMStatus(True))
    s: Settings = getattr(app.state, "settings", load_settings())
    started_at = getattr(app.state, "started_at", time.monotonic())
    return {
        "status": "ok" if llm.reachable else "degraded",
        "provider": s.provider,
        "model": s.model,
        "base_url": s.base_url,
        "llm_reachable": llm.reachable,
        "uptime_s": round(time.monotonic() - started_at, 1),
    }


def render_banner(llm: LLMStatus) -> str:
    if llm.reachable:
        return ""
    return (
        '<div class="banner" role="alert">'
        f"<strong>LLM unavailable ({html.escape(llm.problem or 'unknown')}).</strong> "
        f"{html.escape(llm.detail or '')}"
        "</div>"
    )


@app.get("/", response_class=HTMLResponse)
async def index():
    llm = getattr(app.state, "llm", LLMStatus(True))
    page = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    return page.replace("{{BANNER}}", render_banner(llm))


@app.get("/api/emails")
async def get_emails():
    """Return all seed corpus emails grouped into attacks, ambiguous, and benign."""
    emails_out = []
    for e in sd.EMAILS:
        category = "attack" if e.id.startswith("A") else ("ambiguous" if e.id.startswith("B") else "benign")
        emails_out.append({
            "id": e.id,
            "category": category,
            "sender_display": e.sender_display,
            "sender_address": e.sender_address,
            "subject": e.subject,
            "body": e.body,
            "timestamp": e.timestamp,
            "spf": e.spf,
            "dkim": e.dkim,
            "dmarc": e.dmarc,
            "reply_to": e.reply_to,
            "thread_id": e.thread_id,
            "attachments": [{"name": a.name, "content_type": a.content_type, "size_kb": a.size_kb} for a in e.attachments],
            "is_attack": e.is_attack,
            "attack_type": e.attack_type,
            "expected_verdict": e.expected_verdict,
            "expected_risk": e.expected_risk,
            "notes": getattr(e, "notes", ""),
        })
    return emails_out


@app.get("/api/capabilities")
async def get_capabilities():
    """Return the capability map enforced by SENTINEL and security policy tiers."""
    return {
        "capabilities": CAPABILITY_MAP,
        "read_only_tools": READ_ONLY_TOOLS,
        "all_tools": ALL_TOOLS,
        "thesis": (
            "Email content may become DATA, never INSTRUCTIONS. Every argument of every proposed "
            "action carries a provenance tag (USER / TRUSTED_CONTACT / UNTRUSTED_EMAIL). A deterministic "
            "policy engine refuses consequential actions whose arguments came from untrusted content."
        ),
        "tiers": {
            "READ_ONLY": "No side-effects (summarize, check_auth, etc.). Allowed even with untrusted inputs.",
            "REVERSIBLE": "Undoable actions (draft_reply, add_note). Allowed if critical arguments are trusted.",
            "CONSEQUENTIAL": "State-changing or exfiltrating (update_payment_details, forward_external). Refused if arguments derive from untrusted email content.",
        },
    }


# ---------------------------------------------------------------------------
# Pipeline Execution & Server-Sent Events (SSE)
# ---------------------------------------------------------------------------

async def sse_event_stream(
    email_obj: Union[sd.SeedEmail, dict[str, Any]],
    sentinel_enabled: bool,
    runs: dict[str, OrchestratorResult],
    orch: Orchestrator,
):
    """Generator yielding Server-Sent Events line by line with UI-pacing."""
    res = orch.process(email_obj, sentinel_enabled=sentinel_enabled)
    runs[res.run_id] = res

    # Stream each trace event as it happened
    for trace in res.traces:
        data_json = json.dumps(trace.model_dump(), default=str)
        yield f"data: {data_json}\n\n"
        await asyncio.sleep(0.02)  # Micro-pacing for smooth visual UI rendering

    # Emit completion event with full serialized result
    complete_payload = {
        "event": "complete",
        "run_id": res.run_id,
        "result": serialize_result(res),
    }
    yield f"event: complete\ndata: {json.dumps(complete_payload, default=str)}\n\n"


@app.get("/api/process")
async def process_get(
    email_id: Optional[str] = Query(None),
    sentinel_enabled: bool = Query(True),
    subject: Optional[str] = Query(None),
    body: Optional[str] = Query(None),
    sender: Optional[str] = Query(None),
):
    """SSE endpoint for browser EventSource consumption."""
    runs, orch = get_store()
    email_obj = resolve_email(email_id=email_id, subject=subject, body=body, sender=sender)
    return StreamingResponse(
        sse_event_stream(email_obj, sentinel_enabled, runs, orch),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/api/process")
async def process_post(
    request: Request,
    payload: Optional[ProcessRequest] = None,
    stream: bool = Query(False),
):
    """Execute pipeline via POST. Supports both SSE streaming and direct JSON responses."""
    runs, orch = get_store()
    body_payload = payload or ProcessRequest()

    email_obj = resolve_email(
        email_id=body_payload.email_id,
        subject=body_payload.subject,
        body=body_payload.body,
        sender=body_payload.sender,
    )

    accept_header = request.headers.get("accept", "")
    wants_stream = stream or "text/event-stream" in accept_header

    if wants_stream:
        return StreamingResponse(
            sse_event_stream(email_obj, body_payload.sentinel_enabled, runs, orch),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    res = orch.process(email_obj, sentinel_enabled=body_payload.sentinel_enabled)
    runs[res.run_id] = res
    return {"result": serialize_result(res)}


# ---------------------------------------------------------------------------
# Reassessment Loop
# ---------------------------------------------------------------------------

@app.post("/api/evidence")
async def inject_evidence(payload: EvidenceRequest):
    """Inject new evidence into an existing run and re-run risk -> plan -> gate."""
    runs, orch = get_store()
    previous = runs.get(payload.run_id)
    if previous is None:
        raise HTTPException(status_code=404, detail=f"Run '{payload.run_id}' not found")

    new_item = EvidenceItem(
        id=ev._next_id(previous.ledger) if previous.ledger else f"E_{uuid.uuid4().hex[:4]}",
        claim=payload.claim,
        tool=payload.tool,
        direction=payload.direction,
        weight=payload.weight,
        confidence=payload.confidence,
        raw=payload.raw,
    )

    reassessment, revised_res = orch.reassess(
        previous_result=previous,
        new_evidence=new_item,
        trigger=payload.trigger,
    )

    runs[payload.run_id] = revised_res
    return {
        "status": "revised",
        "reassessment": reassessment.model_dump(),
        "result": serialize_result(revised_res),
    }


# ---------------------------------------------------------------------------
# Operator Action Confirmation
# ---------------------------------------------------------------------------

@app.post("/api/confirm")
async def confirm_action(payload: ConfirmRequest):
    """Operator confirmation or refusal for held actions."""
    runs, orch = get_store()
    run = runs.get(payload.run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=f"Run '{payload.run_id}' not found")

    status = "executed" if payload.confirmed else "rejected_by_operator"
    tool_name = run.action.tool if run.action else "action"
    message = (
        f"Operator CONFIRMED and EXECUTED action '{tool_name}'."
        if payload.confirmed
        else f"Operator REJECTED action '{tool_name}'."
    )
    if payload.note:
        message += f" Note: {payload.note}"

    event = TraceEvent(
        seq=len(run.traces) + 1,
        stage="EXECUTE_CONFIRMED",
        agent="operator",
        status="ok" if payload.confirmed else "blocked",
        payload={
            "confirmed": payload.confirmed,
            "status": status,
            "message": message,
            "note": payload.note,
            "action": run.action.model_dump() if run.action else None,
        },
        ms=0,
    )
    run.traces.append(event)

    return {
        "run_id": payload.run_id,
        "confirmed": payload.confirmed,
        "status": status,
        "message": message,
        "result": serialize_result(run),
    }


# ---------------------------------------------------------------------------
# Audit Trail Inspection
# ---------------------------------------------------------------------------

@app.get("/api/audit")
async def get_audit(run_id: Optional[str] = Query(None)):
    """Inspect full trace and evidence ledger for a run, or list recent audit summaries."""
    runs, _ = get_store()
    if run_id:
        run = runs.get(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")
        return serialize_result(run)

    # Return list of recent runs
    summaries = []
    for r in runs.values():
        summaries.append({
            "run_id": r.run_id,
            "email_id": r.email_id,
            "sentinel_enabled": r.sentinel_enabled,
            "verdict": r.verdict,
            "rule_id": r.rule_id,
            "total_ms": r.total_ms,
            "traces_count": len(r.traces),
            "evidence_count": len(r.ledger.items) if r.ledger else 0,
        })
    return summaries
