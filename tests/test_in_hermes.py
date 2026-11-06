"""Inside real Hermes: the plugin installed in a throwaway HERMES_HOME,
loaded by Hermes's own plugin manager, and tool calls sent through Hermes's
own dispatcher (model_tools.handle_function_call) with --yolo on and
approvals off. A refused call must not run; an allowed one must run on the
path that was checked.

Runs only when HERMES_SRC points at a hermes-agent checkout and the test is
started with that checkout's Python (see scripts/test-in-hermes.sh).
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

from conftest import PLUGIN_DIR, LiveGate, _docker_ok, plugin_pkg

HERMES_SRC = os.environ.get("HERMES_SRC")
pytestmark = pytest.mark.skipif(not HERMES_SRC, reason="HERMES_SRC isn't set")

STYLE = plugin_pkg.paths.host_style()


@pytest.fixture(scope="module")
def hermes():
    if not _docker_ok():
        pytest.skip("Docker or the pinned Archytan Lite image isn't available")
    home = Path(tempfile.mkdtemp(prefix="ahl-home-")).resolve()
    ws = Path(tempfile.mkdtemp(prefix="ahl-ws-")).resolve()
    outside = Path(tempfile.mkdtemp(prefix="ahl-outside-")).resolve()
    g = LiveGate(str(ws), STYLE).start()

    shutil.copytree(PLUGIN_DIR, home / "plugins" / "archytan-lite",
                    ignore=shutil.ignore_patterns("__pycache__"))
    (home / "config.yaml").write_text(json.dumps({
        "approvals": {"mode": "off"},
        "terminal": {"backend": "local", "cwd": str(ws)},
        "plugins": {
            "enabled": ["archytan-lite"],
            "entries": {"archytan-lite": {"settings": {
                "workspace": str(ws), "gate_url": g.url, "gate_public_key_hex": g.public_key,
            }}},
        },
    }), encoding="utf-8")
    os.environ["HERMES_HOME"] = str(home)
    os.environ["HERMES_YOLO_MODE"] = "1"
    os.environ["ARCHYTAN_LITE_HERMES_TOKEN"] = g.token
    sys.path.insert(0, HERMES_SRC)

    from hermes_cli.plugins import discover_plugins, get_plugin_manager
    discover_plugins(force=True)
    mgr = get_plugin_manager()
    import model_tools
    from tools.approval import _yolo_active

    yield {"call": model_tools.handle_function_call, "ws": ws, "outside": outside,
           "gate": g, "yolo": _yolo_active, "mgr": mgr, "home": home}
    g.stop()
    for p in (home, ws, outside):
        shutil.rmtree(p, ignore_errors=True)


def run(h, tool, args, n=[0]):
    n[0] += 1
    out = h["call"](tool, args, task_id="t-hermes", session_id="s-hermes", tool_call_id=f"c{n[0]}", turn_id="u1")
    return out


def test_plugin_loaded_and_yolo_on(hermes):
    assert hermes["yolo"]()
    hooks = hermes["mgr"]._hooks.get("pre_tool_call", [])
    owners = [getattr(getattr(cb, "__self__", None), "__module__", "") or getattr(cb, "__module__", "") for cb in hooks]
    assert any("archytan_lite" in o for o in owners), owners


def test_refused_command_does_not_run(hermes):
    marker = hermes["outside"] / "ran.txt"
    out = run(hermes, "terminal", {"command": f"touch '{marker}'"})
    assert "Archytan Lite refused" in out, out
    assert not marker.exists()


def test_push_refused_under_yolo(hermes):
    out = run(hermes, "terminal", {"command": "git push origin main"})
    assert "Archytan Lite refused" in out and "git/push" in out, out


def test_allowed_command_runs_in_the_workspace(hermes):
    out = run(hermes, "terminal", {"command": "echo archytan-hermes-ok && pwd"})
    assert "archytan-hermes-ok" in out, out
    assert "Archytan Lite refused" not in out
    # pwd prints the workspace (Git Bash writes C:\x as /c/x on Windows).
    leaf = hermes["ws"].name
    assert leaf in out, out


def test_decisions_were_journaled_in_hermes_home(hermes):
    rows = (hermes["home"] / "plugin-data" / "archytan-lite" / "decisions.jsonl").read_text().splitlines()
    assert any('"BLOCK"' in r and "git/push" in r for r in rows)


def test_write_outside_is_refused_and_nothing_is_written(hermes):
    target = hermes["outside"] / "x.txt"
    out = run(hermes, "write_file", {"path": str(target), "content": "pwned"})
    assert "Archytan Lite refused" in out, out
    assert not target.exists()


def test_relative_write_lands_in_the_workspace(hermes):
    out = run(hermes, "write_file", {"path": "notes/hello.txt", "content": "hi"})
    assert "Archytan Lite refused" not in out, out
    assert (hermes["ws"] / "notes" / "hello.txt").read_text() == "hi"


def test_execute_code_refused(hermes):
    out = run(hermes, "execute_code", {"code": "print(1)"})
    assert "Archytan Lite refused" in out, out


def test_receipts_verify(hermes):
    code, out = hermes["gate"].verify()
    assert code == 0, out


def test_slash_command_reports_status_and_log(hermes):
    from hermes_cli.plugins import get_plugin_command_handler
    handler = get_plugin_command_handler("archytan")
    assert handler is not None
    status = handler("", session_id="s-hermes", platform="cli")
    assert "Gate at" in status and "ok" in status and "refused" in status, status
    log = handler("log 50", session_id="s-hermes", platform="cli")
    assert "BLOCK" in log and "git/push" in log, log
