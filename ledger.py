"""Simulated side-effect ledger: the record of every consequential action that actually ran.

Only the tool functions in executor.py write here. If a tool was never called, nothing
is appended, so the ledger is the proof of what executed. In memory; resets on restart.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any

_LOCK = threading.Lock()
_LEDGER: list[dict[str, Any]] = []


def append(run_id: str, tool: str, args: dict[str, Any], result: str) -> dict[str, Any]:
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        "tool": tool,
        "args": dict(args),
        "result": result,
    }
    with _LOCK:
        _LEDGER.append(entry)
    return entry


def entries() -> list[dict[str, Any]]:
    with _LOCK:
        return list(_LEDGER)


def size() -> int:
    with _LOCK:
        return len(_LEDGER)


def has_run(run_id: str) -> bool:
    with _LOCK:
        return any(e["run_id"] == run_id for e in _LEDGER)
