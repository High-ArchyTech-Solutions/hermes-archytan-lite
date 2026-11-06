"""A local list of recent decisions, for `/archytan log`.

This is a convenience copy. The record that counts is the gate's own
hash-chained, signed receipt log, which `hermes archytan verify` checks.
Each line holds what was decided and the trace id that finds its receipt:
tool name, action, resource id (a path, a program name, a host), decision
and reason. Never tool arguments or results. Kept to about 2 MB.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

_MAX_BYTES = 2 * 1024 * 1024
_lock = threading.Lock()


def _file(data_dir: Path) -> Path:
    return data_dir / "decisions.jsonl"


def record(data_dir: Path, tool_name: str, session: str, decisions, ran: bool = True) -> None:
    """``ran`` is whether the tool call went ahead. When it didn't, the
    checks that were allowed are marked unused: their permissions were never
    spent, because another check in the same call was refused."""
    rows = []
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    for d in decisions:
        rows.append(json.dumps({
            "ts": now, "session": session, "tool": tool_name,
            "action": d.check.action, "resource": d.check.resource_id,
            "decision": "ALLOW" if d.allowed else "BLOCK",
            "unused": bool(d.allowed and not ran),
            "reason": d.reason, "trace_id": d.trace_id, "seq": d.seq,
        }, ensure_ascii=False))
    if not rows:
        return
    path = _file(data_dir)
    with _lock:
        try:
            if path.exists() and path.stat().st_size > _MAX_BYTES:
                path.replace(path.with_suffix(".jsonl.1"))
            with path.open("a", encoding="utf-8") as f:
                f.write("\n".join(rows) + "\n")
        except OSError:
            pass  # the journal is a convenience; the gate's log is the record


def tail(data_dir: Path, n: int = 10) -> list[dict]:
    path = _file(data_dir)
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out = []
    for line in lines[-n:]:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out
