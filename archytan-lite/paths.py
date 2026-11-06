"""Path handling: turn what the model wrote into the one absolute path the
gate decides on and the tool then uses.

Relative paths resolve against the workspace (or the directory a command is
running in), never against wherever the Hermes process happens to be, and
the hook hands the resolved path back to the tool, so the path that was
checked is the path that is used. A path that can't be pinned down, such
as ``~otheruser``, a drive-relative Windows path or a UNC share, resolves to
nothing, and the caller refuses the call.
"""

from __future__ import annotations

import ntpath
import os
import posixpath
import re

_DRIVE_ABS = re.compile(r"^[A-Za-z]:[\\/]")
_DRIVE_ANY = re.compile(r"^[A-Za-z]:")
_MSYS_DRIVE = re.compile(r"^/([A-Za-z])(?=/|$)")


def style_of(path: str) -> str | None:
    """"posix" for /a/b, "windows" for C:\\a\\b, None for anything else."""
    if not isinstance(path, str):
        return None
    if path.startswith("/"):
        return "posix"
    if _DRIVE_ABS.match(path):
        return "windows"
    return None


def host_style() -> str:
    return "windows" if os.name == "nt" else "posix"


def resolve(raw: object, base: str, style: str, home: str | None = None) -> str | None:
    """The absolute, lexically normalized form of ``raw``, or None.

    ``base`` must already be absolute in ``style``. ``home`` is what a
    leading ``~`` means; without one, ``~`` can't be resolved.
    """
    if not isinstance(raw, str) or raw == "" or "\x00" in raw:
        return None
    p = raw
    if p == "~" or p.startswith("~/") or (style == "windows" and p.startswith("~\\")):
        if not home:
            return None
        p = home + p[1:]
    elif p.startswith("~"):
        # ~otheruser: another account's home, which this plugin won't guess.
        return None

    if style == "windows":
        if p.startswith(("\\\\", "//")):
            return None  # UNC share or device namespace
        msys = _MSYS_DRIVE.match(p)
        if msys:
            # Git Bash, which Hermes runs commands in on Windows, writes
            # C:\x as /c/x.
            p = msys.group(1).upper() + ":\\" + p[3:]
        if not _DRIVE_ABS.match(p):
            if _DRIVE_ANY.match(p) or p.startswith(("\\", "/")):
                # C:foo is relative to C:'s own current directory, and \foo
                # is rooted on whichever drive is current: neither is ours.
                return None
            p = ntpath.join(base, p)
        p = ntpath.normpath(p)
        return p[0].upper() + p[1:]

    if not p.startswith("/"):
        p = posixpath.join(base, p)
    p = posixpath.normpath(p)
    if p.startswith("//"):
        p = "/" + p.lstrip("/")
    return p


def real(path: str, style: str) -> str:
    """Follow symlinks when the path lives on this machine.

    A workspace inside a container (paths the host doesn't have) is left as
    written: the host can't see the container's links, so the check is
    lexical there, as the README says.
    """
    if style != host_style():
        return path
    try:
        resolved = os.path.realpath(path)
    except (OSError, ValueError):
        return path
    if style == "windows":
        if resolved.startswith("\\\\"):
            return path
        return resolved[0].upper() + resolved[1:]
    return resolved


def is_inside(path: str, root: str, style: str) -> bool:
    """True when ``path`` is ``root`` or below it (both already resolved)."""
    sep = ntpath.sep if style == "windows" else posixpath.sep
    if style == "windows":
        path, root = path.lower(), root.lower()
    prefix = root if root.endswith(sep) else root + sep
    return path == root or path.startswith(prefix)
