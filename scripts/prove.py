"""Run A1 with protection ON then OFF and show the ledger before/after each.

The EXECUTED / NOT EXECUTED lines below are printed live by the tool function and the
orchestrator themselves; this script only prints the ledger counts around them.

    python scripts/prove.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import ledger  # noqa: E402
from orchestrator import Orchestrator  # noqa: E402
from seed_data import email_by_id  # noqa: E402

RULE = "-" * 72


def run(orch: Orchestrator, protection: bool) -> None:
    label = "ON  (SENTINEL policy gate)" if protection else "OFF (naive agent, no gate)"
    print(RULE)
    print(f"A1 with protection {label}")
    before = ledger.size()
    print(f"  ledger before: {before}")
    res = orch.process(email_by_id("A1"), sentinel_enabled=protection)
    after = ledger.size()
    if protection:
        print(f"  verdict:       {res.verdict} ({res.rule_id})")
    else:
        n = res.naive_result or {}
        print(f"  engine:        {n.get('engine')} {n.get('model', '')}".rstrip())
    print(f"  ledger after:  {after}   ({'+' if after > before else ''}{after - before})")


def main() -> None:
    email = email_by_id("A1")
    print(f"Email A1: {email.subject!r} from {email.sender_address}")
    print("Hidden in the HTML: an instruction to change the vendor's IBAN.")
    orch = Orchestrator()
    run(orch, protection=True)
    run(orch, protection=False)
    print(RULE)
    print("Ledger contents (only actions that genuinely ran):")
    for e in ledger.entries():
        print(f"  {e['timestamp']}  {e['run_id']}  {e['tool']}  {e['args']}")


if __name__ == "__main__":
    main()
