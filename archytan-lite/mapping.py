"""Turns a Hermes tool call into the requests Archytan Lite decides.

A tool call becomes one or more checks, each an action and a resource, and
every check has to come back ALLOW before the tool runs. A call this module
can't describe precisely becomes a check on a resource the starter policy
never grants ("unresolved", "unreadable-command"), so the gate refuses it
and the refusal is signed like any other decision.

Tools nobody mapped here are checked as ``tool.call`` on the tool's own
name, which the starter policy doesn't grant either: a new tool is refused
until someone decides it should run.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from . import paths, shell

UNRESOLVED = "unresolved"

# Tools that only read Hermes's own state or talk to the user. They run
# without asking the gate and leave no receipt; everything else is checked.
DEFAULT_UNGATED = (
    "clarify", "todo_list", "skills_list", "skill_view", "session_search",
    "kanban_show", "kanban_list", "kanban_attachments", "read_terminal",
    "read_window_below", "set_theme", "show_tip", "gui_tour", "focus_pane",
    "react_to_message", "setup_beat",
)

_UNSAFE = re.compile(r"[^A-Za-z0-9 _.~+=,@:#()/-]")


@dataclass(frozen=True)
class Check:
    action: str
    resource_type: str
    resource_id: str
    why: str = ""  # shown to the model when this check is refused


@dataclass
class Plan:
    checks: list[Check] = field(default_factory=list)
    # Arguments handed back to the tool, so it acts on exactly what was
    # checked (an absolute path, the directory a command was checked in).
    rewrite: dict = field(default_factory=dict)

    def add(self, check: Check) -> None:
        if all((c.action, c.resource_type, c.resource_id) !=
               (check.action, check.resource_type, check.resource_id) for c in self.checks):
            self.checks.append(check)


@dataclass(frozen=True)
class Context:
    workspace: str      # absolute; relative paths resolve against it
    style: str          # "posix" or "windows", the workspace's path style
    home: str | None    # what ~ means, or None when it can't be known
    resolve_links: bool = True


def _safe_id(text: str) -> str:
    """``text`` as a resource id, or "unresolved" when it has a character the
    gate doesn't accept in a name. Never rewritten into something close:
    `ls.` and `ls` are different programs to the shell, so they must not
    become the same request to the gate."""
    if not text or _UNSAFE.search(text):
        return UNRESOLVED
    return text


def _in_git_dir(path: str, style: str) -> bool:
    for part in re.split(r"[\\/]", path):
        if (part.lower() if style == "windows" else part) == ".git":
            return True
    return False


def _add_file(plan: Plan, ctx: Context, action: str, path: str, from_shell: bool = False) -> None:
    plan.add(Check(action, "file", path))
    if (action == "file.write" or from_shell) and _in_git_dir(path, ctx.style):
        # A hook or a config line under .git is a command git runs later
        # (core.fsmonitor on `git status`, hooks on `git commit`), so
        # writing there is a separate grant from writing the workspace.
        plan.add(Check("repo.internal", "file", path, "files inside .git can make git run commands"))


def _file(plan: Plan, ctx: Context, action: str, raw: object, arg: str | None) -> None:
    p = paths.resolve(raw, ctx.workspace, ctx.style, ctx.home)
    if p is None:
        plan.add(Check(action, "file", UNRESOLVED, f"couldn't tell which file {raw!r} means"))
        return
    if ctx.resolve_links:
        p = paths.real(p, ctx.style)
    _add_file(plan, ctx, action, p)
    if arg and p != raw:
        plan.rewrite[arg] = p


# The same markers Hermes's own V4A parser (tools/patch_parser.py) acts on:
# at column 0, with any spacing. A line starting with *** that isn't one of
# them makes the patch unresolved rather than skipped.
_V4A_OPS = (
    re.compile(r"\*\*\*\s*Update\s+File:\s*(.+)"),
    re.compile(r"\*\*\*\s*Add\s+File:\s*(.+)"),
    re.compile(r"\*\*\*\s*Delete\s+File:\s*(.+)"),
)
_V4A_MOVE = re.compile(r"\*\*\*\s*Move\s+File:\s*(.+?)\s*->\s*(.+)")
_V4A_FRAME = re.compile(r"\*\*\*\s*(Begin\s+Patch|End\s+Patch|End\s+of\s+File)\s*$")


def _v4a(plan: Plan, ctx: Context, patch: object) -> None:
    """Every file a V4A patch adds, updates, deletes or moves, both ends of a
    move included."""
    if not isinstance(patch, str):
        plan.add(Check("file.write", "file", UNRESOLVED, "the patch isn't text"))
        return
    found = False
    for line in patch.split("\n"):
        line = line.removesuffix("\r")
        if not line.startswith("***") or _V4A_FRAME.match(line):
            continue
        m = _V4A_MOVE.match(line)
        targets = [m.group(1), m.group(2)] if m else []
        if not m:
            m = next((hit for rx in _V4A_OPS if (hit := rx.match(line))), None)
            targets = [m.group(1)] if m else []
        if not targets:
            plan.add(Check("file.write", "file", UNRESOLVED, f"the patch has a line this plugin doesn't read ({line[:60]!r})"))
            return
        for t in targets:
            _file(plan, ctx, "file.write", t.strip(), None)
        found = True
    if not found:
        plan.add(Check("file.write", "file", UNRESOLVED, "the patch names no file"))


def _url_id(url: object) -> str | None:
    """scheme/host[:port] for an http(s) URL, else None."""
    if not isinstance(url, str):
        return None
    try:
        parts = urlsplit(url.strip())
        host = parts.hostname
        port = parts.port
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not host:
        return None
    if parts.username is not None or parts.password is not None:
        return None  # user:pass@host hides which host is meant from a quick read
    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    if _UNSAFE.search(host) or ":" in host or "/" in host:
        return None  # IPv6 literals and anything odder
    rid = f"{parts.scheme.lower()}/{host}"
    return f"{rid}:{port}" if port else rid


def _fetch(plan: Plan, url: object) -> None:
    rid = _url_id(url)
    if rid is None:
        plan.add(Check("web.fetch", "url", UNRESOLVED, f"couldn't read {url!r} as an http(s) URL"))
    else:
        plan.add(Check("web.fetch", "url", rid))


def _media(plan: Plan, ctx: Context, ref: object) -> None:
    """An image or video the tool will open: a URL is a fetch, a path a read."""
    if isinstance(ref, str) and re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", ref):
        _fetch(plan, ref)
    elif isinstance(ref, str) and ref.startswith("data:"):
        return  # inline data names nothing outside the call
    else:
        _file(plan, ctx, "file.read", ref, None)


def _terminal(plan: Plan, ctx: Context, args: dict) -> None:
    workdir = args.get("workdir")
    if workdir in (None, ""):
        cwd = ctx.workspace
    else:
        cwd = paths.resolve(workdir, ctx.workspace, ctx.style, ctx.home)
        if cwd is None:
            plan.add(Check("file.read", "file", UNRESOLVED, f"couldn't tell which directory {workdir!r} means"))
            return
        if ctx.resolve_links:
            cwd = paths.real(cwd, ctx.style)
        _add_file(plan, ctx, "file.read", cwd, from_shell=True)
    # Every command starts where it was checked, never wherever an earlier
    # command left the shell.
    plan.rewrite["workdir"] = cwd

    try:
        reading = shell.read_command(args.get("command"), cwd, ctx.style, ctx.home)
    except shell.Unreadable as e:
        plan.add(Check("shell.run", "program", "unreadable-command",
                       f"the command {e.why}, so what it would touch can't be checked"))
        return

    for t in reading.touches:
        if t.kind == "program":
            pid = _safe_id(t.value)
            plan.add(Check("shell.run", "program", pid,
                           "" if pid != UNRESOLVED else f"the program name {t.value!r} has characters the gate doesn't accept"))
        elif t.kind in ("read", "write"):
            p = paths.real(t.value, ctx.style) if ctx.resolve_links else t.value
            _add_file(plan, ctx, f"file.{t.kind}", p, from_shell=True)
        elif t.kind == "fetch":
            _fetch(plan, t.value)
        elif t.kind == "env":
            plan.add(Check("shell.env", "variable", _safe_id(t.value),
                           "setting an environment variable for a command can change what the program does"))


def _per_action(plan: Plan, action: str, rtype: str, value: object) -> None:
    rid = _safe_id(value) if isinstance(value, str) and value else UNRESOLVED
    plan.add(Check(action, rtype, rid))


def plan_for(tool_name: str, args: dict, ctx: Context) -> Plan:
    plan = Plan()
    a = args if isinstance(args, dict) else {}

    if tool_name in ("read_file",):
        _file(plan, ctx, "file.read", a.get("path"), "path")
    elif tool_name == "search_files":
        _file(plan, ctx, "file.read", a.get("path") or ".", "path")
    elif tool_name == "write_file":
        _file(plan, ctx, "file.write", a.get("path"), "path")
    elif tool_name == "patch":
        if a.get("mode") == "patch" or "patch" in a:
            _v4a(plan, ctx, a.get("patch"))
            if a.get("path"):
                _file(plan, ctx, "file.write", a.get("path"), "path")
        else:
            _file(plan, ctx, "file.write", a.get("path"), "path")
    elif tool_name == "terminal":
        _terminal(plan, ctx, a)
    elif tool_name in ("process_manage", "close_terminal"):
        _per_action(plan, "shell.process", "process", a.get("action") or "close")
    elif tool_name == "execute_code":
        plan.add(Check("code.run", "runtime", "python",
                       "running code can do anything the account can"))
    elif tool_name == "web_search":
        plan.add(Check("web.search", "query", "web"))
    elif tool_name == "web_extract":
        urls = a.get("urls")
        if isinstance(urls, str):
            urls = [urls]
        if not isinstance(urls, list) or not urls:
            plan.add(Check("web.fetch", "url", UNRESOLVED, "no URL was given"))
        else:
            for u in urls:
                _fetch(plan, u)
    elif tool_name in ("vision_analyze",):
        _media(plan, ctx, a.get("image_url"))
    elif tool_name in ("video_analyze",):
        _media(plan, ctx, a.get("video_url"))
    elif tool_name.startswith("browser_") or tool_name in ("drive_preview", "desktop_preview", "annotate_preview"):
        _per_action(plan, "browser.use", "tool", tool_name)
    elif tool_name == "computer_use":
        _per_action(plan, "computer.use", "action", a.get("action"))
    elif tool_name == "memory":
        _per_action(plan, "memory.write", "store", a.get("target"))
    elif tool_name == "skill_manage":
        plan.add(Check("skill.write", "store", "skills",
                       "a skill changes the instructions future sessions follow"))
    elif tool_name == "cronjob_manage":
        _per_action(plan, "cron.manage", "job", a.get("action"))
    elif tool_name == "delegate_task":
        plan.add(Check("agent.delegate", "agent", "subagent"))
    elif tool_name in ("image_generate", "video_generate", "text_to_speech", "xai_video_edit", "xai_video_extend"):
        _per_action(plan, "media.generate", "tool", tool_name)
        if a.get("output_path"):
            _file(plan, ctx, "file.write", a.get("output_path"), "output_path")
        for key in ("video_url", "image_url"):
            if a.get(key):
                _media(plan, ctx, a.get(key))
    elif tool_name.startswith("kanban_"):
        _per_action(plan, "kanban.write", "tool", tool_name)
    elif tool_name in ("manage_connections", "manage_catalog", "desktop_project"):
        _per_action(plan, "hermes.admin", "tool", tool_name)
    elif tool_name.startswith("mcp_"):
        _per_action(plan, "mcp.call", "tool", tool_name[4:])
    else:
        _per_action(plan, "tool.call", "tool", tool_name)
    return plan
