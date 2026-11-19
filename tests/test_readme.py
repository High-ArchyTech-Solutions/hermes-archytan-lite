"""The plugin folder carries its own README, because the Hermes catalog shows
the README from the entry's subdir. It must say exactly what the repo README
says; only the banner link differs, since a relative path there would point
inside the plugin folder."""

import subprocess

import pytest

from conftest import PLUGIN_DIR, ROOT

BANNER = ("https://raw.githubusercontent.com/High-ArchyTech-Solutions/hermes-archytan-lite/"
          "1fc0adde723841c5b83055d8a74a6d1f116f8fab/docs/banner.png")


def test_plugin_readme_is_the_repo_readme():
    repo = (ROOT / "README.md").read_text(encoding="utf-8")
    plugin = (PLUGIN_DIR / "README.md").read_text(encoding="utf-8")
    assert "](docs/banner.png)" in repo
    assert plugin == repo.replace("](docs/banner.png)", f"]({BANNER})", 1)


def test_banner_at_the_pinned_commit_is_the_repo_banner():
    sha = BANNER.split("/")[-3]
    shown = subprocess.run(["git", "-C", str(ROOT), "show", f"{sha}:docs/banner.png"], capture_output=True)
    if shown.returncode != 0:
        pytest.skip("needs the repo's git history")
    assert shown.stdout == (ROOT / "docs" / "banner.png").read_bytes()
