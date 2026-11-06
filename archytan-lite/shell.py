"""Reads a terminal command the way a POSIX shell will, well enough to say
what it touches, and gives up rather than guess.

It finds the programs a command runs, the files it redirects into or out
of, the paths and URLs it names, and the directories it changes into.
Anything whose meaning is only settled when the shell runs it ($VAR, $(...),
backticks, here-documents, process substitution, brace expansion, loops)
makes the command unreadable, and the caller checks an unreadable command
as a single request that the starter policy never grants.

What this can't see: what a program does once it's running. A granted
interpreter (python, node, bash) can do anything the account can, which is
why the starter policy grants none.
"""

from __future__ import annotations

import ntpath
import posixpath
import re
from dataclasses import dataclass

from . import paths

# Programs whose first argument picks what they do: `git push` and
# `git status` are different requests, so the gate sees "git/push".
SUBCOMMAND_PROGRAMS = frozenset({
    "apt", "apt-get", "aws", "az", "brew", "cargo", "conda", "docker", "dotnet",
    "gcloud", "gh", "git", "go", "helm", "hermes", "kubectl", "npm", "pip",
    "pip3", "pnpm", "poetry", "systemctl", "terraform", "uv", "yarn",
})

# Programs that write to the paths they're given: their path arguments are
# checked as writes, not reads.
WRITING_PROGRAMS = frozenset({
    "chmod", "chown", "cp", "dd", "install", "ln", "mkdir", "mv", "rm", "rmdir",
    "rsync", "tee", "touch", "truncate", "unlink",
})

# Words that start or continue a compound command rather than name a
# program; the command that follows them is what runs.
_LEADING_KEYWORDS = frozenset({"if", "then", "else", "elif", "do", "while", "until", "time", "!"})
_CLOSING_KEYWORDS = frozenset({"fi", "done", "esac"})
# Constructs that bind a variable or loop over words: the command inside
# them can't be read without running the shell.
_UNREADABLE_KEYWORDS = frozenset({"for", "case", "select", "function", "coproc"})

_SEPARATORS = frozenset({";", "&&", "||", "|", "|&", "&", "(", ")", "\n", "{", "}"})
_REDIRECTS = frozenset({">", ">>", ">|", "&>", "&>>", "<", ">&", "<&"})
_OPERATORS = (  # longest first
    "&>>", "<<<", "<<-", ";;&", "&&", "||", "|&", ";;", ";&", ">>", ">|", "&>",
    "<<", "<(", ">(", ">&", "<&", "<>", ";", "&", "|", "(", ")", "<", ">",
)
_UNREADABLE_OPERATORS = {
    "<<": "uses a here-document", "<<-": "uses a here-document", "<<<": "uses a here-string",
    "<(": "uses process substitution", ">(": "uses process substitution",
    "<>": "opens a file for reading and writing", ";;": "uses a case statement",
    ";&": "uses a case statement", ";;&": "uses a case statement",
}
_HARMLESS_TARGETS = frozenset({"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty"})
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_URL = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_DRIVE = re.compile(r"^[A-Za-z]:")

MAX_TOUCHES = 40


class Unreadable(Exception):
    """The command can't be read without running it."""

    def __init__(self, why: str) -> None:
        super().__init__(why)
        self.why = why


@dataclass(frozen=True)
class Word:
    text: str
    glob: bool = False   # an unquoted * ? or [
    tilde: bool = False  # an unquoted leading ~


@dataclass(frozen=True)
class Op:
    text: str


@dataclass(frozen=True)
class Touch:
    """One thing a command touches.

    kind is "program", "read", "write", "fetch" or "env"; value is the
    program id, the resolved path, the URL or the variable name.
    """

    kind: str
    value: str


@dataclass(frozen=True)
class Reading:
    touches: tuple[Touch, ...]
    cwd: str  # the directory the command starts in after its leading cd's


def tokenize(cmd: str) -> list[Word | Op]:
    tokens: list[Word | Op] = []
    buf: list[str] = []
    state = {"in_word": False, "glob": False, "tilde": False, "quoted": False}

    def flush() -> None:
        if state["in_word"]:
            text = "".join(buf)
            if text in ("{", "}") and not state["quoted"]:
                tokens.append(Op(text))
            else:
                tokens.append(Word(text, glob=state["glob"], tilde=state["tilde"]))
        buf.clear()
        state.update(in_word=False, glob=False, tilde=False, quoted=False)

    i, n = 0, len(cmd)
    while i < n:
        c = cmd[i]
        if c in " \t":
            flush()
            i += 1
        elif c in "\r\n":
            flush()
            tokens.append(Op("\n"))
            i += 1
        elif c == "#" and not state["in_word"]:
            end = cmd.find("\n", i)
            i = n if end < 0 else end
        elif c == "\\":
            if i + 1 >= n:
                raise Unreadable("ends with a backslash")
            if cmd[i + 1] == "\n":
                i += 2
                continue
            buf.append(cmd[i + 1])
            state.update(in_word=True, quoted=True)
            i += 2
        elif c == "'":
            end = cmd.find("'", i + 1)
            if end < 0:
                raise Unreadable("has an unclosed quote")
            buf.append(cmd[i + 1:end])
            state.update(in_word=True, quoted=True)
            i = end + 1
        elif c == '"':
            j, part = i + 1, []
            while True:
                if j >= n:
                    raise Unreadable("has an unclosed quote")
                d = cmd[j]
                if d == '"':
                    break
                if d in "$`":
                    raise Unreadable("expands a variable or runs a command substitution")
                if d == "\\" and j + 1 < n and cmd[j + 1] in '"\\$`\n':
                    if cmd[j + 1] != "\n":
                        part.append(cmd[j + 1])
                    j += 2
                    continue
                part.append(d)
                j += 1
            buf.append("".join(part))
            state.update(in_word=True, quoted=True)
            i = j + 1
        elif c in "$`":
            raise Unreadable("expands a variable or runs a command substitution")
        elif c in ";&|()<>":
            word = "".join(buf)
            if c in "<>" and state["in_word"] and not state["quoted"] and word.isdigit():
                # "2>" names a file descriptor, not a word.
                buf.clear()
                state.update(in_word=False, glob=False, tilde=False, quoted=False)
            else:
                flush()
            op = next(o for o in _OPERATORS if cmd.startswith(o, i))
            if op in _UNREADABLE_OPERATORS:
                raise Unreadable(_UNREADABLE_OPERATORS[op])
            tokens.append(Op(op))
            i += len(op)
        else:
            if c in "{}" and not state["quoted"] and (
                state["in_word"] or (i + 1 < n and cmd[i + 1] not in " \t\r\n;&|")
            ):
                raise Unreadable("uses brace expansion")
            if c in "*?[":
                state["glob"] = True
            if c == "~" and not state["in_word"]:
                state["tilde"] = True
            buf.append(c)
            state["in_word"] = True
            i += 1
    flush()
    return tokens


def _split(tokens: list[Word | Op]) -> list[tuple[list[Word | Op], str]]:
    """Simple commands, each with the separator that follows it."""
    out: list[tuple[list[Word | Op], str]] = []
    cur: list[Word | Op] = []
    for t in tokens:
        if isinstance(t, Op) and t.text in _SEPARATORS:
            out.append((cur, t.text))
            cur = []
        else:
            cur.append(t)
    out.append((cur, ""))
    return [(c, sep) for c, sep in out if c]


def _program_id(word: str, style: str) -> str:
    base = ntpath.basename(word) if style == "windows" else posixpath.basename(word)
    if style == "windows":
        base = base.lower()
        if base.endswith(".exe"):
            base = base[:-4]
    return base


def _path_like(text: str, style: str) -> bool:
    if text.startswith((".", "~")) or "/" in text:
        return True
    return style == "windows" and ("\\" in text or bool(_DRIVE.match(text)))


class _Reader:
    def __init__(self, cwd: str, style: str, home: str | None) -> None:
        self.cwd = cwd
        self.style = style
        self.home = home
        self.touches: list[Touch] = []

    def add(self, kind: str, value: str) -> None:
        t = Touch(kind, value)
        if t not in self.touches:
            self.touches.append(t)
        if len(self.touches) > MAX_TOUCHES:
            raise Unreadable("names more things than this plugin checks in one command")

    def resolve(self, word: Word) -> str:
        if word.glob:
            raise Unreadable("uses a wildcard where a single path is needed")
        p = paths.resolve(word.text, self.cwd, self.style, self.home)
        if p is None:
            raise Unreadable(f"names a path this plugin can't pin down ({word.text!r})")
        return p

    def path_arg(self, word: Word, kind: str = "read") -> None:
        text = word.text
        if word.glob:
            # Check the directory the wildcard expands in. A wildcard with no
            # directory part expands in the working directory, which is
            # already checked.
            first = min(text.find(ch) for ch in "*?[" if ch in text)
            head = text[:first]
            cut = max(head.rfind("/"), head.rfind("\\") if self.style == "windows" else -1)
            if cut < 0:
                if head.startswith("~"):
                    raise Unreadable(f"names a path this plugin can't pin down ({text!r})")
                if kind == "write":
                    self.add(kind, self.cwd)
                return
            text = head[:cut] or ("/" if head.startswith("/") else ".")
            word = Word(text, tilde=word.tilde)
        self.add(kind, self.resolve(word))


def read_command(cmd: str, cwd: str, style: str, home: str | None = None) -> Reading:
    """What ``cmd`` touches when it starts in ``cwd``. Raises Unreadable."""
    if not isinstance(cmd, str) or not cmd.strip():
        raise Unreadable("is empty")
    r = _Reader(cwd, style, home)
    commands = _split(tokenize(cmd))
    if not commands:
        raise Unreadable("is empty")

    leading = True  # still inside the run of `cd x &&` at the start
    for items, sep in commands:
        words: list[Word] = []
        it = iter(items)
        for t in it:
            if isinstance(t, Op):  # a redirect
                target = next(it, None)
                if not isinstance(target, Word):
                    raise Unreadable("redirects without naming a file")
                if t.text in (">&", "<&") and (target.text.isdigit() or target.text == "-"):
                    continue  # 2>&1 and friends copy a descriptor
                if target.text in _HARMLESS_TARGETS:
                    continue
                r.add("read" if t.text in ("<", "<&") else "write", r.resolve(target))
            else:
                words.append(t)

        while words and words[0].text in _LEADING_KEYWORDS:
            words.pop(0)
        if words and words[0].text in _UNREADABLE_KEYWORDS:
            raise Unreadable(f"uses a {words[0].text} construct")
        if len(words) == 1 and words[0].text in _CLOSING_KEYWORDS:
            words = []
        while words and _ASSIGNMENT.match(words[0].text) and not words[0].tilde:
            r.add("env", words.pop(0).text.split("=", 1)[0])
        if not words:
            leading = leading and sep == "&&"
            continue

        program = words[0]
        if program.glob:
            raise Unreadable("runs a program named by a wildcard")
        args = words[1:]

        if program.text == "cd":
            rest = [a for a in args if a.text not in ("-L", "-P", "--")]
            if not leading or sep not in ("&&", ""):
                raise Unreadable("changes directory part-way through; start it with `cd dir &&` or use workdir")
            if rest and rest[0].text == "-":
                raise Unreadable("changes to the previous directory, which this plugin doesn't track")
            target = rest[0] if rest else Word("~", tilde=True)
            new_cwd = r.resolve(target)
            r.add("read", new_cwd)
            r.cwd = new_cwd
            continue
        leading = False

        if _path_like(program.text, style) or program.tilde:
            r.add("read", r.resolve(program))
        pid = _program_id(program.text, style)
        if pid in SUBCOMMAND_PROGRAMS:
            if pid == "git":
                while len(args) >= 2 and args[0].text == "-C":
                    r.add("read", r.resolve(args[1]))
                    args = args[2:]
            if args:
                sub = args[0].text
                if args[0].glob or not sub:
                    raise Unreadable("runs a subcommand named by a wildcard")
                pid = f"{pid}/{sub}"
                args = args[1:]
        r.add("program", pid)
        kind = "write" if pid in WRITING_PROGRAMS else "read"

        for a in args:
            text = a.text
            if _URL.match(text):
                r.add("fetch", text)
                continue
            if text.startswith("-"):
                if "=" not in text:
                    continue
                value = text.split("=", 1)[1]
                if _URL.match(value):
                    r.add("fetch", value)
                    continue
                if value and _path_like(value, style):
                    r.path_arg(Word(value, glob=a.glob), kind)
                continue
            if _path_like(text, style) or a.tilde:
                r.path_arg(a, kind)
            elif kind == "write":
                # A bare name is a file in the working directory; a writing
                # program's targets are checked even then.
                r.path_arg(a, kind)

    return Reading(tuple(r.touches), r.cwd)
