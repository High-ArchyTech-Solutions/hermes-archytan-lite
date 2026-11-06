"""The starter policy `hermes archytan setup` writes.

Deliberately tight. Hermes can read and write inside one workspace, run a
short list of programs that don't execute other code, search the web,
fetch https pages, keep memory and delegate to subagents (which run in the
same process, behind the same gate). Everything else is refused until you
add it: running code (python, node, execute_code), deleting files,
pushing, the browser, MCP servers, other plugins' tools, new cron jobs,
editing skills, and kanban tasks (another profile's worker picks those
up, and that profile may not have this plugin). Every action absent from
the file is refused for every role; there is no catch-all.
"""

from __future__ import annotations

import json

ROLE = "hermes_agent"
SCHEMA = "https://high-archy.tech/schemas/policy.v1.json"

# None of these runs a program or script it's handed. Interpreters, `find`
# (-exec), `xargs`, `sed` and `awk` are left out because each can.
STARTER_PROGRAMS = (
    "ls", "pwd", "cat", "head", "tail", "wc", "grep", "rg", "sort", "uniq",
    "diff", "echo", "printf", "date", "true", "false", "which", "file",
    "stat", "du", "tree", "mkdir", "touch", "cp", "mv",
    "git/status", "git/diff", "git/log", "git/show", "git/branch",
    "git/add", "git/commit", "git/switch", "git/fetch", "git/rev-parse",
)


def _rule(action: str, *, roles=None, ids=None, per_minute: int | None = None) -> dict:
    rule: dict = {"action": action}
    if ids is None:
        rule["allowed_roles"] = list(roles or [ROLE])
    else:
        rule["grants"] = [{"roles": list(roles or [ROLE]), "resource_ids": list(ids)}]
    if per_minute:
        rule["assertions"] = {"max_per_window": per_minute, "window_seconds": 60}
    return rule


def workspace_pattern(workspace: str, style: str) -> str:
    sep = "\\" if style == "windows" else "/"
    return workspace.rstrip("\\/") + sep + "**" if workspace.rstrip("\\/") else sep + "**"


def starter(workspace: str, style: str) -> dict:
    ws = workspace_pattern(workspace, style)
    return {
        "$schema": SCHEMA,
        "version": 1,
        "actions": [
            _rule("file.read", ids=[ws]),
            _rule("file.write", ids=[ws], per_minute=120),
            _rule("shell.run", ids=STARTER_PROGRAMS, per_minute=60),
            _rule("shell.process"),
            _rule("web.search", per_minute=30),
            _rule("web.fetch", ids=["https/*"], per_minute=60),
            _rule("memory.write", per_minute=30),
            _rule("agent.delegate", per_minute=10),
            _rule("media.generate", per_minute=10),
            _rule("cron.manage", ids=["list"]),
        ],
    }


def dumps(policy: dict) -> str:
    return json.dumps(policy, indent=2) + "\n"


def grants_pattern(path, pattern: str) -> bool:
    """True when the policy file at ``path`` names ``pattern`` in any grant."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        return any(pattern in g.get("resource_ids", [])
                   for rule in doc.get("actions", []) for g in rule.get("grants", []))
    except (OSError, ValueError, AttributeError, TypeError):
        return False
