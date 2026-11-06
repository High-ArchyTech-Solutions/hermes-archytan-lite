"""Archytan Lite for Hermes: every tool call is decided by a gate the agent
can't reach, and every decision is a signed, hash-chained receipt.

A `pre_tool_call` hook turns each tool call into checks (mapping.py), asks
Archytan Lite about all of them and spends each single-use permission just
before the tool runs (gate.py). A refusal blocks the call with a message the
model can act on. An error anywhere in this plugin blocks the call too:
nothing runs without an ALLOW.
"""

from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path

from . import commands, gate, journal, mapping, paths

logger = logging.getLogger(__name__)

PLUGIN = "archytan-lite"
TOKEN_ENV = "ARCHYTAN_LITE_HERMES_TOKEN"
DEFAULT_URL = "http://127.0.0.1:8431"


def _data_dir() -> Path:
    try:
        from plugins.plugin_storage import plugin_data_dir
        return plugin_data_dir(PLUGIN)
    except Exception:  # an older layout; fall back to the documented location
        home = os.environ.get("HERMES_HOME") or str(Path.home() / ".hermes")
        p = Path(home) / "plugin-data" / PLUGIN
        p.mkdir(parents=True, exist_ok=True)
        return p


def _secret(name: str) -> str:
    try:
        from agent.secret_scope import get_secret
        return get_secret(name) or ""
    except Exception:
        return ""


class Plugin:
    def __init__(self, ctx) -> None:
        self.ctx = ctx

    # settings ---------------------------------------------------------------

    def cfg(self, key: str, default=None):
        try:
            value = self.ctx.get_config(key, default=default)
        except Exception:
            return default
        return default if value is None else value

    def settings(self) -> gate.Settings:
        try:
            timeout = float(self.cfg("timeout_seconds", 2.0))
        except (TypeError, ValueError):
            timeout = 2.0
        return gate.Settings(
            url=str(self.cfg("gate_url", DEFAULT_URL) or "").rstrip("/"),
            token=_secret(TOKEN_ENV),
            public_key_hex=str(self.cfg("gate_public_key_hex", "") or "").strip(),
            timeout=max(0.2, min(timeout, 10.0)),
            expected_policy_sha256=str(self.cfg("expected_policy_sha256", "") or "").strip(),
        )

    def context(self) -> mapping.Context | None:
        workspace = str(self.cfg("workspace", "") or "")
        style = paths.style_of(workspace)
        if style is None:
            return None
        home = str(self.cfg("home", "") or "") or None
        if home is None and style == paths.host_style():
            home = str(Path.home())
        if home is not None and paths.style_of(home) != style:
            home = None
        mode = str(self.cfg("resolve_symlinks", "auto") or "auto")
        return mapping.Context(
            workspace=paths.resolve(workspace, workspace, style) or workspace,
            style=style, home=home, resolve_links=(mode != "off"),
        )

    def ungated(self) -> frozenset[str]:
        value = self.cfg("ungated_tools", None)
        if isinstance(value, list) and all(isinstance(v, str) for v in value):
            return frozenset(value)
        return frozenset(mapping.DEFAULT_UNGATED)

    # the hook ---------------------------------------------------------------

    def pre_tool_call(self, tool_name: str = "", args=None, task_id: str = "", **kwargs):
        try:
            return self._decide(tool_name, args if isinstance(args, dict) else {}, task_id, kwargs)
        except Exception as e:  # fail closed, loudly
            logger.exception("archytan-lite: refusing %s after an internal error", tool_name)
            return {"action": "block", "message": (
                f"Archytan Lite refused this call: the plugin hit an error ({type(e).__name__}) "
                "before the gate could decide, and nothing runs without an ALLOW. Tell the user.")}

    def _decide(self, tool_name: str, args: dict, task_id: str, kw: dict):
        if tool_name in self.ungated():
            return None
        ctx = self.context()
        if ctx is None:
            return {"action": "block", "message": (
                "Archytan Lite refused this call: no workspace is configured, so paths can't be "
                "checked. The user needs to run `hermes archytan setup`.")}
        plan = mapping.plan_for(tool_name, args, ctx)
        session = str(kw.get("session_id") or task_id or "")
        actor = f"hermes:{session or 'no-session'}"
        outcome = gate.decide(plan.checks, actor, self.settings(), _traceparent(session, kw))
        journal.record(_data_dir(), tool_name, session, outcome.decisions)
        if not outcome.allowed:
            return {"action": "block", "message": refusal(tool_name, outcome.refused)}
        if plan.rewrite:
            return {"action": "modify", "args": plan.rewrite}
        return None


def _traceparent(session: str, kw: dict) -> str | None:
    """A W3C traceparent tying the receipt to this Hermes turn: the trace id
    is derived from session and turn, the span id from the tool call."""
    turn = str(kw.get("turn_id") or "")
    call = str(kw.get("tool_call_id") or "")
    if not session and not turn:
        return None
    trace = hashlib.sha256(f"{session}:{turn}".encode()).hexdigest()[:32]
    span = hashlib.sha256(f"{session}:{turn}:{call}".encode()).hexdigest()[:16]
    if set(trace) == {"0"} or set(span) == {"0"}:
        return None
    return f"00-{trace}-{span}-01"


def refusal(tool_name: str, d: gate.Decision | None) -> str:
    if d is None:
        return "Archytan Lite refused this call."
    c = d.check
    why = c.why or _explain(d.reason)
    trace = f" Trace {d.trace_id}." if d.trace_id else ""
    return (
        f"Archytan Lite refused this call: {c.action} on {c.resource_id}"
        f"{' (' + why + ')' if why else ''}. Nothing ran.{trace} "
        "The decision is signed and recorded by a gate outside Hermes. Don't retry it unchanged "
        "and don't try another tool or command to do the same thing. Tell the user what you "
        "were trying to do; they can change the policy if it should be allowed."
    )


def _explain(reason: str) -> str:
    if reason.startswith("gate_unreachable"):
        return "the gate didn't answer, and an unanswered request counts as a refusal"
    if reason.startswith("misconfigured"):
        return reason.split(":", 1)[1].strip()
    if "status 429" in reason:
        return "the gate is getting requests faster than it accepts them; wait a moment before the next call"
    if "status 403" in reason:
        return "the policy doesn't allow it, or this action's limit per minute was reached"
    if reason:
        return reason.replace("gate_denied: ", "")
    return ""


def register(ctx) -> None:
    plugin = Plugin(ctx)
    ctx.register_hook("pre_tool_call", plugin.pre_tool_call)
    commands.register(ctx, plugin, _data_dir)
