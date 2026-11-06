"""archytan-lite/lite_client.py must be the published client, byte for byte."""

import hashlib
from pathlib import Path

import pytest

from conftest import PLUGIN_DIR

# archytan_lite/client.py in archytan-lite 2.1.1 on PyPI.
PUBLISHED_SHA256 = "e18ba9ec861baa53d8dab49714b96601d3e0f401d19a1f0b9573fa2e344d1310"


def test_vendored_client_is_the_published_2_1_1_file():
    data = (PLUGIN_DIR / "lite_client.py").read_bytes()
    assert hashlib.sha256(data).hexdigest() == PUBLISHED_SHA256


def test_matches_the_installed_package_when_present():
    archytan_lite = pytest.importorskip("archytan_lite")
    installed = Path(archytan_lite.__file__).parent / "client.py"
    assert installed.read_bytes() == (PLUGIN_DIR / "lite_client.py").read_bytes()
