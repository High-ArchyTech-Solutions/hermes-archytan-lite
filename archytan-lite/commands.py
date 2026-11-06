"""`hermes archytan ...` in a terminal and `/archytan ...` in a chat.

Only a person runs these. None of them is a tool, so the agent can't call
one, and the policy file they point at lives outside any workspace the
agent can write.
"""

from __future__ import annotations

import os
from collections import Counter
from pathlib import Path

from . import journal, paths, policy, provision

USAGE = (
    "/archytan            gate status and today's decisions\n"
    "/archytan log [n]    the last n decisions (default 10)\n"
    "/archytan verify     check every receipt's signature and the hash chain\n"
)


def _fmt_rows(rows: list[dict]) -> str:
    if not rows:
        return "No decisions recorded yet."
    out = []
    for r in rows:
        ts = str(r.get("ts", ""))[11:19]
        seq = f" #{r['seq']}" if r.get("seq") is not None else ""
        trace = f" {r['trace_id']}" if r.get("trace_id") else ""
        out.append(f"{ts} {r.get('decision', '?'):5} {r.get('action', '')} {r.get('resource', '')}"
                   f" [{r.get('tool', '')}]{seq}{trace}")
    return "\n".join(out)


def _health(plugin) -> str:
    import httpx

    url = plugin.settings().url
    try:
        resp = httpx.get(f"{url}/v1/healthz", timeout=2)
        body = resp.json()
    except Exception as e:  # any failure is reported, not raised
        return f"Gate at {url}: not answering ({type(e).__name__}). Every gated tool call is being refused."
    return (f"Gate at {url}: {body.get('status', '?')}, capabilities {body.get('capabilities', '?')}, "
            f"auth {body.get('auth_mode', '?')}, mode {body.get('mode', '?')}")


def status_text(plugin, data_dir: Path) -> str:
    rows = journal.tail(data_dir, 500)
    today = rows[-1]["ts"][:10] if rows else ""
    counts = Counter(r.get("decision") for r in rows if str(r.get("ts", "")).startswith(today))
    workspace = plugin.cfg("workspace", "") or "(not set: run `hermes archytan setup`)"
    return "\n".join([
        _health(plugin),
        f"Workspace: {workspace}",
        f"Today: {counts.get('ALLOW', 0)} allowed, {counts.get('BLOCK', 0)} refused",
        "",
        "Latest:",
        _fmt_rows(rows[-5:]),
    ])


def verify_text(plugin) -> str:
    pub = plugin.settings().public_key_hex
    if not pub:
        return "No gate public key is configured; run `hermes archytan setup`."
    try:
        ok, out = provision.verify_chain(pub)
    except provision.SetupError as e:
        return f"Couldn't run the check: {e}"
    head = "Receipt log verified." if ok else "THE RECEIPT LOG DID NOT VERIFY."
    return f"{head}\n{out[-1500:]}"


def slash(plugin, data_dir_fn, raw_args: str = "", **_):
    parts = (raw_args or "").split()
    sub = parts[0] if parts else "status"
    if sub in ("status", ""):
        return status_text(plugin, data_dir_fn())
    if sub == "log":
        try:
            n = max(1, min(int(parts[1]), 100)) if len(parts) > 1 else 10
        except ValueError:
            n = 10
        return _fmt_rows(journal.tail(data_dir_fn(), n))
    if sub == "verify":
        return verify_text(plugin)
    return USAGE


# --- CLI ---------------------------------------------------------------------


def _setup_argparse(parser) -> None:
    subs = parser.add_subparsers(dest="archytan_command")
    s = subs.add_parser("setup", help="Start the gate in Docker, issue Hermes its credential, write a starter policy")
    s.add_argument("--workspace", help="The folder Hermes may read and write (absolute path)")
    s.add_argument("--in-container", action="store_true",
                   help="The workspace is a path inside Hermes's terminal container, not on this machine")
    s.add_argument("--home", help="What ~ means in the agent's paths (for a workspace inside a container)")
    s.add_argument("--port", type=int, default=provision.DEFAULT_PORT, help="Local port for the gate")
    s.add_argument("--pull", action="store_true", help=f"Pull {provision.IMAGE} if it isn't present")
    s.add_argument("--new-policy", action="store_true", help="Replace an existing policy.json with the starter policy")
    subs.add_parser("status", help="Gate status and today's decisions")
    lg = subs.add_parser("log", help="Recent decisions")
    lg.add_argument("n", nargs="?", type=int, default=20)
    subs.add_parser("verify", help="Check every receipt's signature and the hash chain")
    subs.add_parser("reload", help="Apply an edited policy.json without restarting the gate")
    subs.add_parser("policy", help="Show where policy.json is")


def _check_workspace(raw: str, style: str, in_container: bool = False) -> str:
    ws = paths.resolve(raw, raw, style) if style else None
    if not ws:
        raise provision.SetupError(f"--workspace must be an absolute path, got {raw!r}")
    if ws in ("/",) or (style == "windows" and len(ws) <= 3):
        raise provision.SetupError("pick a project folder, not a drive root")
    if style == paths.host_style() and not in_container:
        if not os.path.isdir(ws):
            raise provision.SetupError(f"{ws} isn't a directory")
        ws = paths.real(ws, style)
        home = paths.real(str(Path.home()), style)
        hermes_home = paths.real(os.environ.get("HERMES_HOME") or str(Path.home() / ".hermes"), style)
        is_root = ws == "/" if style == "posix" else len(ws) <= 3
        if is_root or ws == home:
            raise provision.SetupError("pick a project folder, not a drive root or your whole home directory")
        if paths.is_inside(hermes_home, ws, style):
            raise provision.SetupError(
                f"{ws} contains Hermes's own home ({hermes_home}); the agent could edit its config there")
    return ws


def run_setup(plugin, data_dir: Path, args) -> int:
    layout = provision.Layout(data_dir)
    raw = args.workspace or plugin.cfg("workspace", "")
    if not raw:
        print("Pass --workspace: the folder Hermes may read and write.")
        return 2
    ws = _check_workspace(raw, paths.style_of(raw) or "", args.in_container)
    style = paths.style_of(ws)
    if args.home and paths.style_of(args.home) != style:
        raise provision.SetupError(f"--home must be an absolute path in the workspace's style, got {args.home!r}")

    provision.require_docker()
    if not provision.image_present():
        if not args.pull:
            print(f"The gate image isn't on this machine. Pull it yourself (Archytan Lite {provision.IMAGE_VERSION}, "
                  f"free under the Community license):\n\n  docker pull {provision.IMAGE}\n\n"
                  "or run setup again with --pull.")
            return 2
        print(f"Pulling {provision.IMAGE} ...")
        provision.pull()

    pub = provision.ensure_key(layout)
    print(f"Gate public key: {pub}")
    token = provision.new_caller(layout, policy.ROLE)
    if args.new_policy or not layout.policy.exists():
        layout.policy.write_text(policy.dumps(policy.starter(ws, style)), encoding="utf-8")
        print(f"Wrote the starter policy to {layout.policy}")
    else:
        print(f"Kept your policy at {layout.policy}")
        if not policy.grants_pattern(layout.policy, policy.workspace_pattern(ws, style)):
            print(f"  Note: it doesn't grant {policy.workspace_pattern(ws, style)}. Edit it, or run setup "
                  "again with --new-policy to start from the starter policy for this workspace.")
    provision.lint(layout)
    provision.start(layout, args.port)
    url = f"http://127.0.0.1:{args.port}"
    health = provision.wait_healthy(url)
    print(f"Gate is up at {url} (capabilities {health.get('capabilities')}, auth {health.get('auth_mode')})")

    plugin.ctx.set_config("gate_url", url)
    plugin.ctx.set_config("gate_public_key_hex", pub)
    plugin.ctx.set_config("workspace", ws)
    plugin.ctx.set_config("resolve_symlinks", "off" if args.in_container else "auto")
    if args.home:
        plugin.ctx.set_config("home", args.home)
    if not _store_token(token):
        print("\nCouldn't store the caller token through Hermes. Set it as ARCHYTAN_LITE_HERMES_TOKEN "
              f"(Desktop: Settings > Plugins > Archytan Lite). It is shown once:\n\n  {token}\n")
    else:
        print("Stored Hermes's caller token through Hermes's credential store.")

    _smoke(plugin, ws, style)
    print("\nRestart the gateway (or start a new session) so running sessions pick up the settings.")
    return 0


def _store_token(token: str) -> bool:
    try:
        from hermes_cli.config import save_env_value_secure
        save_env_value_secure("ARCHYTAN_LITE_HERMES_TOKEN", token)
        os.environ["ARCHYTAN_LITE_HERMES_TOKEN"] = token  # for the check below, this process only
        return True
    except Exception:
        return False


def _smoke(plugin, ws: str, style: str) -> None:
    from . import gate
    from .mapping import Check

    sep = "\\" if style == "windows" else "/"
    inside = ws.rstrip("\\/") + sep + "README.md"
    # A sibling of the workspace: outside it, and harmless to name.
    outside = ws.rstrip("\\/") + "-setup-check" + sep + "README.md"
    s = plugin.settings()
    for c, want in ((Check("file.read", "file", inside), True), (Check("file.read", "file", outside), False)):
        got = gate.decide([c], "hermes:setup-check", s).allowed
        mark = "ok" if got == want else "UNEXPECTED"
        print(f"  {mark}: file.read {c.resource_id} -> {'ALLOW' if got else 'BLOCK'}")


def cli(plugin, data_dir_fn, args) -> int:
    sub = getattr(args, "archytan_command", None)
    try:
        if sub == "setup":
            return run_setup(plugin, data_dir_fn(), args)
        if sub in (None, "status"):
            print(status_text(plugin, data_dir_fn()))
            return 0
        if sub == "log":
            print(_fmt_rows(journal.tail(data_dir_fn(), max(1, min(args.n, 500)))))
            return 0
        if sub == "verify":
            text = verify_text(plugin)
            print(text)
            return 0 if text.startswith("Receipt log verified") else 1
        if sub == "reload":
            layout = provision.Layout(data_dir_fn())
            provision.lint(layout)
            provision.reload()
            print("Sent the gate SIGHUP. It validates the file first and keeps the old policy if the new one is invalid; "
                  "check `hermes archytan status` and the gate's log.")
            return 0
        if sub == "policy":
            layout = provision.Layout(data_dir_fn())
            print(f"{layout.policy}\nEdit it, then run `hermes archytan reload`.")
            return 0
    except provision.SetupError as e:
        print(f"archytan: {e}")
        return 1
    return 2


def register(ctx, plugin, data_dir_fn) -> None:
    ctx.register_command(
        "archytan",
        handler=lambda raw_args="", **kw: slash(plugin, data_dir_fn, raw_args, **kw),
        description="Archytan Lite: gate status, recent decisions, verify the receipt log",
    )
    ctx.register_cli_command(
        name="archytan",
        help="Archytan Lite gate for Hermes tool calls",
        setup_fn=_setup_argparse,
        handler_fn=lambda args: cli(plugin, data_dir_fn, args),
    )
