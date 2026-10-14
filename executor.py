"""Consequential tool implementations with a simulated side effect on ledger.py.

These functions are the tool boundary. Each one records its own execution at the top of
its body, so an "EXECUTED" line and a ledger entry exist only if the tool really ran.
The orchestrator calls execute() only after the policy gate allowed the action (or an
operator approved a CONFIRM); on BLOCK or HOLD the function is never called.
"""

from __future__ import annotations

from typing import Any, Optional

import ledger


def _fmt(args: dict[str, Any]) -> str:
    return ", ".join(f"{k}={v!r}" for k, v in args.items())


def send_reply(run_id: str, args: dict[str, Any]) -> str:
    # Side effect and EXECUTED line come from inside this tool body, not the orchestrator or UI.
    ledger.append(run_id, "send_reply", args, "reply sent (simulated)")
    print(f"EXECUTED  run={run_id}  send_reply({_fmt(args)})", flush=True)
    return "reply sent (simulated)"


def forward_external(run_id: str, args: dict[str, Any]) -> str:
    # Side effect and EXECUTED line come from inside this tool body, not the orchestrator or UI.
    ledger.append(run_id, "forward_external", args, "message forwarded externally (simulated)")
    print(f"EXECUTED  run={run_id}  forward_external({_fmt(args)})", flush=True)
    return "message forwarded externally (simulated)"


def update_payment_details(run_id: str, args: dict[str, Any]) -> str:
    # Side effect and EXECUTED line come from inside this tool body, not the orchestrator or UI.
    ledger.append(run_id, "update_payment_details", args, "vendor payment record updated (simulated)")
    print(f"EXECUTED  run={run_id}  update_payment_details({_fmt(args)})", flush=True)
    return "vendor payment record updated (simulated)"


def share_document(run_id: str, args: dict[str, Any]) -> str:
    # Side effect and EXECUTED line come from inside this tool body, not the orchestrator or UI.
    ledger.append(run_id, "share_document", args, "document shared (simulated)")
    print(f"EXECUTED  run={run_id}  share_document({_fmt(args)})", flush=True)
    return "document shared (simulated)"


def reset_credential(run_id: str, args: dict[str, Any]) -> str:
    # Side effect and EXECUTED line come from inside this tool body, not the orchestrator or UI.
    ledger.append(run_id, "reset_credential", args, "credential reset (simulated)")
    print(f"EXECUTED  run={run_id}  reset_credential({_fmt(args)})", flush=True)
    return "credential reset (simulated)"


TOOLS = {
    "send_reply": send_reply,
    "forward_external": forward_external,
    "update_payment_details": update_payment_details,
    "share_document": share_document,
    "reset_credential": reset_credential,
}


def execute(run_id: str, tool: Optional[str], args: Any) -> Optional[str]:
    """Run a consequential tool. Non-consequential tools have no side effect and return None."""
    fn = TOOLS.get(tool or "")
    if fn is None:
        return None
    return fn(run_id, dict(args) if isinstance(args, dict) else {"raw": args})
