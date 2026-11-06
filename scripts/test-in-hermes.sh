#!/usr/bin/env bash
# Runs tests/test_in_hermes.py with a hermes-agent checkout's own Python, so
# the plugin is loaded by Hermes's real plugin manager and dispatcher.
#
#   scripts/test-in-hermes.sh /path/to/hermes-agent [/path/to/hermes/python]
#
# The second argument defaults to the checkout's .venv. pytest and the
# archytan-lite client come from this repo's .venv.
set -euo pipefail
src="$(cd "$1" && pwd)"
py="${2:-$src/.venv/bin/python}"
here="$(cd "$(dirname "$0")/.." && pwd)"
site="$("$here/.venv/bin/python" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"
cd "$here"
HERMES_SRC="$src" PYTHONPATH="$site" "$py" -m pytest -q tests/test_in_hermes.py "${@:3}"
