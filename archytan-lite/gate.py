"""Asks Archytan Lite about each check, through its official Python client.

Two phases, so a call that's refused on its third check hasn't spent the
first two: every check is authorized first, and only when all of them come
back ALLOW is each single-use capability redeemed, immediately before the
tool runs. The client treats anything other than a verified ALLOW that
matches the request as a denial (a timeout, a refused connection, a bad
signature, a receipt for some other request), and so does this module.

lite_client.py is that client (archytan-lite 2.1.1 on PyPI, MIT, by the
same authors) copied byte for byte, so the plugin installs with nothing to
resolve; tests/test_vendored_client.py holds it to the published file. It
needs only httpx and cryptography, which Hermes already ships.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from .lite_client import authorize, redeem_capability
from .mapping import Check


@dataclass(frozen=True)
class Settings:
    url: str
    token: str
    public_key_hex: str
    timeout: float = 2.0
    expected_policy_sha256: str = ""


@dataclass(frozen=True)
class Decision:
    check: Check
    allowed: bool
    reason: str = ""
    trace_id: str = ""
    receipt_id: str = ""
    seq: int | None = None
    policy_sha256: str = ""


@dataclass(frozen=True)
class Outcome:
    allowed: bool
    decisions: tuple[Decision, ...]

    @property
    def refused(self) -> Decision | None:
        return next((d for d in self.decisions if not d.allowed), None)


def _misconfigured(s: Settings) -> str:
    if not s.url:
        return "no gate URL is set (run `hermes archytan setup`)"
    if not s.token:
        return "no caller token is set (run `hermes archytan setup`)"
    if not s.public_key_hex:
        return "the gate's public key isn't set, so no receipt could be verified"
    return ""


def decide(checks: list[Check], actor_uid: str, s: Settings, traceparent: str | None = None) -> Outcome:
    if not checks:
        # A tool call that maps to nothing is a bug in the mapping, and a
        # bug must not open the gate.
        return Outcome(False, (Decision(Check("tool.call", "tool", "unmapped"), False, "nothing to check"),))
    problem = _misconfigured(s)
    if problem:
        return Outcome(False, (Decision(checks[0], False, f"misconfigured: {problem}"),))

    actor = {"uid": actor_uid}
    granted = []
    decisions: list[Decision] = []
    for c in checks:
        resource = {"type": c.resource_type, "id": c.resource_id}
        res = authorize(
            url=s.url, token=s.token, gate_public_key_hex=s.public_key_hex,
            action=c.action, actor=actor, resource=resource,
            idempotency_key=f"hermes-{uuid.uuid4().hex}", timeout=s.timeout,
            traceparent=traceparent, expected_policy_sha256=s.expected_policy_sha256 or None,
        )
        receipt = res.receipt or {}
        d = Decision(
            c, res.allowed, res.reason, res.trace_id or "",
            str(receipt.get("receipt_id", "")), receipt.get("seq"),
            str(receipt.get("policy_sha256", "")),
        )
        if res.allowed and res.capability is None:
            # Without a capability the gate's ALLOW is an opinion nothing
            # spends, and the one-call-one-permission guarantee isn't in
            # force. Refuse rather than run on a weaker promise.
            d = Decision(c, False, "the gate issued no capability (start it with ARCHYTAN_LITE_CAPABILITIES=on)",
                         d.trace_id, d.receipt_id, d.seq, d.policy_sha256)
        decisions.append(d)
        if not d.allowed:
            return Outcome(False, tuple(decisions))
        granted.append((c, resource, res.capability))

    for i, (c, resource, cap) in enumerate(granted):
        spent = redeem_capability(
            url=s.url, token=s.token, capability_token=cap.token,
            action=c.action, resource=resource, timeout=s.timeout, traceparent=traceparent,
        )
        if not spent.redeemed:
            d = decisions[i]
            decisions[i] = Decision(c, False, spent.reason, d.trace_id, d.receipt_id, d.seq, d.policy_sha256)
            return Outcome(False, tuple(decisions))
    return Outcome(True, tuple(decisions))
