"""Against a real Archytan Lite gate from the pinned image. Every way an
ALLOW could be faked or stretched must come back refused."""

import copy
import sqlite3
import tempfile
from pathlib import Path

import pytest

from conftest import WORKSPACE, LiveGate, plugin_pkg

gate = plugin_pkg.gate
Check = plugin_pkg.mapping.Check
policy = plugin_pkg.policy

INSIDE = Check("file.read", "file", WORKSPACE + "/README.md")
OUTSIDE = Check("file.read", "file", "/etc/shadow")


def test_allow_inside_the_workspace(live_gate):
    out = gate.decide([INSIDE], "hermes:test", live_gate.settings())
    assert out.allowed
    d = out.decisions[0]
    assert d.receipt_id and d.seq is not None and len(d.policy_sha256) == 64


def test_block_outside_the_workspace(live_gate):
    out = gate.decide([OUTSIDE], "hermes:test", live_gate.settings())
    assert not out.allowed
    assert out.refused.check == OUTSIDE and out.refused.trace_id


def test_one_refusal_refuses_the_whole_call(live_gate):
    out = gate.decide([INSIDE, OUTSIDE], "hermes:test", live_gate.settings())
    assert not out.allowed and out.refused.check == OUTSIDE


def test_programs_and_subcommands(live_gate):
    s = live_gate.settings()
    assert gate.decide([Check("shell.run", "program", "git/status")], "hermes:test", s).allowed
    for pid in ("git/push", "rm", "python", "unreadable-command", "unresolved", "curl", "sudo"):
        assert not gate.decide([Check("shell.run", "program", pid)], "hermes:test", s).allowed, pid


@pytest.mark.parametrize("check", [
    Check("code.run", "runtime", "python"),
    Check("browser.use", "tool", "browser_exec"),
    Check("mcp.call", "tool", "linkedin_create_post"),
    Check("tool.call", "tool", "anything"),
    Check("hermes.admin", "tool", "manage_catalog"),
    Check("repo.internal", "file", WORKSPACE + "/.git/hooks/pre-commit"),
    Check("shell.env", "variable", "LD_PRELOAD"),
    Check("cron.manage", "job", "create"),
    Check("file.read", "file", WORKSPACE + "/../etc/passwd"),   # not canonical
    Check("file.read", "file", WORKSPACE + "x/secret"),         # a sibling with the same prefix
    Check("web.fetch", "url", "http/example.com"),
])
def test_starter_policy_refuses(live_gate, check):
    assert not gate.decide([check], "hermes:test", live_gate.settings()).allowed


def test_a_capability_spent_elsewhere_first_is_refused(live_gate, monkeypatch):
    # Someone else spends the capability between the ALLOW and the plugin's
    # own redeem: the gate refuses the second spend, so the call must not run.
    real = gate.redeem_capability

    def spend_first(**kw):
        assert real(**kw).redeemed
        return real(**kw)

    monkeypatch.setattr(gate, "redeem_capability", spend_first)
    out = gate.decide([INSIDE], "hermes:test", live_gate.settings())
    assert not out.allowed and "redemption refused" in out.refused.reason


def test_kanban_is_not_in_the_starter_policy(live_gate):
    assert not gate.decide([Check("kanban.write", "tool", "kanban_create")], "hermes:test", live_gate.settings()).allowed


def test_wrong_public_key_is_refused(live_gate):
    out = gate.decide([INSIDE], "hermes:test", live_gate.settings(public_key_hex="00" * 32))
    assert not out.allowed and "signature" in out.refused.reason


def test_wrong_token_is_refused(live_gate):
    assert not gate.decide([INSIDE], "hermes:test", live_gate.settings(token="nope")).allowed


def test_unreachable_gate_is_refused(live_gate):
    out = gate.decide([INSIDE], "hermes:test", live_gate.settings(url="http://127.0.0.1:9", timeout=0.5))
    assert not out.allowed and out.refused.reason.startswith("gate_unreachable")


def test_missing_settings_are_refused(live_gate):
    for over in ({"token": ""}, {"public_key_hex": ""}, {"url": ""}):
        out = gate.decide([INSIDE], "hermes:test", live_gate.settings(**over))
        assert not out.allowed and out.refused.reason.startswith("misconfigured")


def test_no_checks_is_refused(live_gate):
    assert not gate.decide([], "hermes:test", live_gate.settings()).allowed


def test_unexpected_policy_is_refused(live_gate):
    out = gate.decide([INSIDE], "hermes:test", live_gate.settings(expected_policy_sha256="ab" * 32))
    assert not out.allowed


def test_rate_limit(live_gate):
    s = live_gate.settings()
    c = Check("cron.manage", "job", "list")  # granted, and no other test uses it
    pol = copy.deepcopy(live_gate.policy)
    for rule in pol["actions"]:
        if rule["action"] == "cron.manage":
            rule["assertions"] = {"max_per_window": 3, "window_seconds": 60}
    live_gate.write_policy(pol)
    live_gate.reload()
    try:
        results = [gate.decide([c], "hermes:test", s).allowed for _ in range(5)]
        assert results == [True, True, True, False, False]
    finally:
        live_gate.write_policy(live_gate.policy)
        live_gate.reload()


def test_policy_reload_changes_the_decision_and_the_signed_policy_hash(live_gate):
    s = live_gate.settings()
    push = Check("shell.run", "program", "git/push")
    before = gate.decide([INSIDE], "hermes:test", s).decisions[0].policy_sha256
    assert not gate.decide([push], "hermes:test", s).allowed
    pol = copy.deepcopy(live_gate.policy)
    for rule in pol["actions"]:
        if rule["action"] == "shell.run":
            rule["grants"][0]["resource_ids"].append("git/push")
    live_gate.write_policy(pol)
    live_gate.reload()
    try:
        out = gate.decide([push], "hermes:test", s)
        assert out.allowed
        assert out.decisions[0].policy_sha256 != before
    finally:
        live_gate.write_policy(live_gate.policy)
        live_gate.reload()
    assert not gate.decide([push], "hermes:test", s).allowed


def test_chain_verifies_after_everything_above(live_gate):
    code, out = live_gate.verify()
    assert code == 0, out


def test_gate_without_capabilities_is_refused():
    g = LiveGate(WORKSPACE, "posix", capabilities=False).start()
    try:
        out = gate.decide([INSIDE], "hermes:test", g.settings())
        assert not out.allowed and "capability" in out.refused.reason
    finally:
        g.stop()


def test_an_edited_receipt_is_caught_by_verify():
    g = LiveGate(WORKSPACE, "posix").start()
    try:
        s = g.settings()
        gate.decide([OUTSIDE], "hermes:test", s)
        gate.decide([INSIDE], "hermes:test", s)
        assert g.verify()[0] == 0
        # Turn the BLOCK into an ALLOW in the database, the way someone with
        # disk access would try to rewrite history.
        g.docker("stop", g.name)
        tmp = Path(tempfile.mkdtemp()).resolve()
        g.docker("cp", f"{g.name}:/data/archytan.db", str(tmp / "archytan.db"))
        for side in ("-wal", "-shm"):
            g.docker("cp", f"{g.name}:/data/archytan.db{side}", str(tmp / f"archytan.db{side}"), check=False)
        con = sqlite3.connect(tmp / "archytan.db")
        n = con.execute("UPDATE receipts SET decision='ALLOW' WHERE decision='BLOCK'").rowcount
        con.commit()
        con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        con.close()
        assert n >= 1
        # Put back the edited file and an empty write-ahead log, so the
        # gate can't replay the original rows over the edit.
        (tmp / "archytan.db-wal").write_bytes(b"")
        for name in ("archytan.db", "archytan.db-wal"):
            g.docker("cp", str(tmp / name), f"{g.name}:/data/{name}")
        g.docker("start", g.name)
        import time
        time.sleep(2)
        code, out = g.verify()
        assert code != 0, out
    finally:
        g.stop()
