"""Loads the plugin package (its directory name has a hyphen, as Hermes
plugins do) and, when Docker is available, starts a real Archytan Lite gate
from the same pinned image the plugin's setup uses."""

from __future__ import annotations

import importlib.util
import json
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PLUGIN_DIR = ROOT / "archytan-lite"


def _load_plugin():
    name = "archytan_lite_plugin"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(
        name, PLUGIN_DIR / "__init__.py", submodule_search_locations=[str(PLUGIN_DIR)])
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


plugin_pkg = _load_plugin()


@pytest.fixture(scope="session")
def pkg():
    return plugin_pkg


def _docker_ok() -> bool:
    if not shutil.which("docker"):
        return False
    r = subprocess.run(["docker", "image", "inspect", plugin_pkg.provision.IMAGE], capture_output=True)
    return r.returncode == 0


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class LiveGate:
    """A throwaway gate: its own volume, policy and caller credential."""

    def __init__(self, workspace: str, style: str, policy: dict | None = None, capabilities: bool = True):
        self.name = f"archytan-hermes-test-{uuid.uuid4().hex[:8]}"
        self.volume = self.name
        self.port = _free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self.tmp = Path(tempfile.mkdtemp(prefix="ahl-")).resolve()
        self.config = self.tmp / "config"
        self.config.mkdir()
        self.workspace, self.style = workspace, style
        self.policy = policy or plugin_pkg.policy.starter(workspace, style)
        self.capabilities = capabilities

    def docker(self, *args, check=True):
        r = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=120)
        if check and r.returncode != 0:
            raise RuntimeError(f"docker {' '.join(args[:3])}: {r.stderr}")
        return r

    def start(self):
        img = plugin_pkg.provision.IMAGE
        self.docker("volume", "create", self.volume)
        out = self.docker("run", "--rm", "-v", f"{self.volume}:/data", "--entrypoint", "keygen", img,
                          "-out", "/data/signing_key.pem").stdout
        self.public_key = [l for l in out.splitlines() if l.startswith("public key")][0].rsplit(":", 1)[1].strip()
        cg = json.loads(self.docker("run", "--rm", "--entrypoint", "callergen", img, "-json",
                                    "-caller-id", "hermes", "-role", plugin_pkg.policy.ROLE).stdout)
        self.token = cg["token"]
        (self.config / "callers.json").write_text(json.dumps({"version": 1, "callers": [cg["record"]]}))
        self.write_policy(self.policy)
        self.docker(
            "run", "-d", "--name", self.name, "-p", f"127.0.0.1:{self.port}:8421",
            "-v", f"{self.volume}:/data",
            "--mount", f"type=bind,source={self.config},target=/etc/archytan-lite,readonly",
            "-e", "ARCHYTAN_LITE_DB_PATH=/data/archytan.db",
            "-e", "ARCHYTAN_LITE_SIGNING_KEY_PATH=/data/signing_key.pem",
            "-e", "ARCHYTAN_LITE_POLICY_PATH=/etc/archytan-lite/policy.json",
            "-e", "ARCHYTAN_LITE_CALLERS_PATH=/etc/archytan-lite/callers.json",
            "-e", "ARCHYTAN_LITE_INSTANCE_URN=urn:archytan-lite:instance:hermes-test",
            "-e", f"ARCHYTAN_LITE_CAPABILITIES={'on' if self.capabilities else 'off'}",
            "-e", "ARCHYTAN_LITE_RATE_LIMIT_RPS=100", "-e", "ARCHYTAN_LITE_RATE_LIMIT_BURST=200",
            img,
        )
        import httpx
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                if httpx.get(f"{self.url}/v1/healthz", timeout=1).status_code == 200:
                    return self
            except httpx.HTTPError:
                pass
            time.sleep(0.3)
        raise RuntimeError("gate didn't start: " + self.docker("logs", self.name, check=False).stderr)

    def write_policy(self, policy: dict):
        (self.config / "policy.json").write_text(json.dumps(policy, indent=2))

    def reload(self):
        self.docker("kill", "-s", "HUP", self.name)
        time.sleep(0.8)

    def verify(self):
        r = self.docker("exec", "-e", f"ARCHYTAN_LITE_TRUSTED_PUBLIC_KEYS_HEX={self.public_key}",
                        self.name, "archytan-lite", "--verify-chain", check=False)
        return r.returncode, r.stdout + r.stderr

    def settings(self, **over):
        s = dict(url=self.url, token=self.token, public_key_hex=self.public_key, timeout=3.0)
        s.update(over)
        return plugin_pkg.gate.Settings(**s)

    def stop(self):
        self.docker("rm", "-f", self.name, check=False)
        self.docker("volume", "rm", self.volume, check=False)
        shutil.rmtree(self.tmp, ignore_errors=True)


WORKSPACE = "/home/hermes/project"


@pytest.fixture(scope="session")
def live_gate():
    if not _docker_ok():
        pytest.skip("Docker or the pinned Archytan Lite image isn't available")
    g = LiveGate(WORKSPACE, "posix").start()
    yield g
    g.stop()
