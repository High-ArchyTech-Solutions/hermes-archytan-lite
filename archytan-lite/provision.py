"""Starts and manages the Archytan Lite gate this plugin talks to, in Docker.

Everything here runs only when you type a `hermes archytan` command; the
agent never reaches it. The image is pinned by digest and never pulled
unless you pass --pull. Docker runs with a minimal environment.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

IMAGE_VERSION = "2.7.1"
IMAGE = ("ghcr.io/high-archytech-solutions/archytan-lite@sha256:"
         "205703a7fc67a9e96aa0930fd9dda83fe2b9694b724b13dea8c1854948e82071")
CONTAINER = "archytan-hermes"
VOLUME = "archytan-hermes-data"
DEFAULT_PORT = 8431
CALLER_ID = "hermes"
INSTANCE_URN = "urn:archytan-lite:instance:hermes"

_ENV_KEYS = (
    "PATH", "HOME", "USERPROFILE", "SystemRoot", "SYSTEMROOT", "TEMP", "TMP",
    "APPDATA", "LOCALAPPDATA", "ProgramData", "ProgramFiles", "ProgramW6432",
    "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY",
    "XDG_RUNTIME_DIR",
)


class SetupError(Exception):
    pass


def docker(*args: str, timeout: float = 120) -> subprocess.CompletedProcess:
    env = {k: os.environ[k] for k in _ENV_KEYS if k in os.environ}
    try:
        return subprocess.run(["docker", *args], capture_output=True, text=True,
                              timeout=timeout, env=env, check=False)
    except FileNotFoundError as e:
        raise SetupError("Docker isn't installed or isn't on PATH") from e
    except subprocess.TimeoutExpired as e:
        raise SetupError(f"docker {args[0]} took longer than {timeout:.0f}s") from e


@dataclass
class Layout:
    data_dir: Path

    @property
    def gate_dir(self) -> Path:
        return self.data_dir / "gate"

    @property
    def config_dir(self) -> Path:
        return self.gate_dir / "config"

    @property
    def policy(self) -> Path:
        return self.config_dir / "policy.json"

    @property
    def callers(self) -> Path:
        return self.config_dir / "callers.json"

    @property
    def public_key(self) -> Path:
        return self.gate_dir / "public_key.hex"


def require_docker() -> None:
    r = docker("version", "--format", "{{.Server.Version}}", timeout=30)
    if r.returncode != 0:
        raise SetupError("Docker is installed but its engine isn't answering; start Docker and try again")


def image_present() -> bool:
    return docker("image", "inspect", IMAGE, timeout=30).returncode == 0


def pull() -> None:
    r = docker("pull", IMAGE, timeout=600)
    if r.returncode != 0:
        raise SetupError(f"docker pull failed: {r.stderr.strip()[-400:]}")


def container_state() -> str:
    """"running", "exited", ... or "" when there's no such container."""
    r = docker("inspect", "-f", "{{.State.Status}}", CONTAINER, timeout=30)
    return r.stdout.strip() if r.returncode == 0 else ""


def ensure_key(layout: Layout) -> str:
    """The gate's public key, generating the signing key on first setup."""
    if layout.public_key.exists():
        return layout.public_key.read_text(encoding="ascii").strip()
    docker("volume", "create", VOLUME, timeout=30)
    r = docker("run", "--rm", "-v", f"{VOLUME}:/data", "--entrypoint", "keygen", IMAGE,
               "-out", "/data/signing_key.pem")
    if r.returncode != 0:
        if "refusing to overwrite" in r.stderr:
            raise SetupError(
                f"the volume {VOLUME} already holds a signing key, but its public key isn't recorded "
                f"in {layout.public_key}. Write the public key there, or remove the volume yourself "
                f"(docker volume rm {VOLUME}, which deletes its receipts) and run setup again")
        raise SetupError(f"keygen failed: {r.stderr.strip()[-400:]}")
    pub = ""
    for line in r.stdout.splitlines():
        if line.startswith("public key"):
            pub = line.rsplit(":", 1)[1].strip()
    if len(pub) != 64:
        raise SetupError("keygen didn't print a public key")
    layout.gate_dir.mkdir(parents=True, exist_ok=True)
    layout.public_key.write_text(pub + "\n", encoding="ascii")
    return pub


def new_caller(layout: Layout, role: str) -> str:
    """Issue the agent's credential and write callers.json. Returns the token."""
    r = docker("run", "--rm", "--entrypoint", "callergen", IMAGE,
               "-json", "-caller-id", CALLER_ID, "-role", role, timeout=60)
    if r.returncode != 0:
        raise SetupError(f"callergen failed: {r.stderr.strip()[-400:]}")
    out = json.loads(r.stdout)
    layout.config_dir.mkdir(parents=True, exist_ok=True)
    layout.callers.write_text(json.dumps({
        "$schema": "https://high-archy.tech/schemas/callers.v1.json",
        "version": 1,
        "callers": [out["record"]],
    }, indent=2) + "\n", encoding="utf-8")
    return out["token"]


def lint(layout: Layout) -> None:
    r = docker("run", "--rm", "--mount", _config_mount(layout), "--entrypoint", "policylint", IMAGE,
               "-policy", "/etc/archytan-lite/policy.json", "-callers", "/etc/archytan-lite/callers.json",
               timeout=60)
    if r.returncode != 0:
        raise SetupError(f"policylint found a problem:\n{(r.stdout + r.stderr).strip()[-1500:]}")


def _config_mount(layout: Layout) -> str:
    return f"type=bind,source={layout.config_dir},target=/etc/archytan-lite,readonly"


def start(layout: Layout, port: int) -> None:
    if container_state():
        docker("rm", "-f", CONTAINER, timeout=60)
    r = docker(
        "run", "-d", "--name", CONTAINER, "--restart", "unless-stopped",
        "-p", f"127.0.0.1:{port}:8421",
        "-v", f"{VOLUME}:/data", "--mount", _config_mount(layout),
        "-e", "ARCHYTAN_LITE_DB_PATH=/data/archytan.db",
        "-e", "ARCHYTAN_LITE_SIGNING_KEY_PATH=/data/signing_key.pem",
        "-e", "ARCHYTAN_LITE_POLICY_PATH=/etc/archytan-lite/policy.json",
        "-e", "ARCHYTAN_LITE_CALLERS_PATH=/etc/archytan-lite/callers.json",
        "-e", f"ARCHYTAN_LITE_INSTANCE_URN={INSTANCE_URN}",
        "-e", "ARCHYTAN_LITE_CAPABILITIES=on",
        # One local caller making two requests per check: room for a burst
        # of parallel tool calls. The policy's per-minute limits are the ones
        # that mean something.
        "-e", "ARCHYTAN_LITE_RATE_LIMIT_RPS=100",
        "-e", "ARCHYTAN_LITE_RATE_LIMIT_BURST=200",
        IMAGE, timeout=120,
    )
    if r.returncode != 0:
        raise SetupError(f"couldn't start the gate: {r.stderr.strip()[-400:]}")


def wait_healthy(url: str, seconds: float = 20) -> dict:
    import httpx

    deadline = time.monotonic() + seconds
    last = ""
    while time.monotonic() < deadline:
        try:
            resp = httpx.get(f"{url}/v1/healthz", timeout=2)
            if resp.status_code == 200:
                return resp.json()
            last = f"status {resp.status_code}"
        except httpx.HTTPError as e:
            last = str(e)
        time.sleep(0.5)
    logs = docker("logs", "--tail", "20", CONTAINER, timeout=30)
    raise SetupError(f"the gate didn't come up ({last}). Its last log lines:\n{(logs.stdout + logs.stderr).strip()}")


def reload() -> None:
    r = docker("kill", "-s", "HUP", CONTAINER, timeout=30)
    if r.returncode != 0:
        raise SetupError(f"couldn't signal the gate: {r.stderr.strip()[-300:] or 'is it running?'}")


def verify_chain(public_key_hex: str) -> tuple[bool, str]:
    r = docker("exec", "-e", f"ARCHYTAN_LITE_TRUSTED_PUBLIC_KEYS_HEX={public_key_hex}",
               CONTAINER, "archytan-lite", "--verify-chain", timeout=300)
    return r.returncode == 0, (r.stdout + r.stderr).strip()


def log_lines(n: int = 30) -> str:
    r = docker("logs", "--tail", str(n), CONTAINER, timeout=30)
    return (r.stdout + r.stderr).strip()
