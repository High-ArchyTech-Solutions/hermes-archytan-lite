"""Tool calls to checks, without a gate."""

import pytest

from conftest import plugin_pkg

mapping = plugin_pkg.mapping
paths = plugin_pkg.paths

WS = "/home/hermes/project"
CTX = mapping.Context(workspace=WS, style="posix", home="/home/hermes", resolve_links=False)


def checks(tool, args, ctx=CTX):
    return [(c.action, c.resource_type, c.resource_id) for c in mapping.plan_for(tool, args, ctx).checks]


def test_relative_file_paths_resolve_in_the_workspace_and_are_handed_back():
    plan = mapping.plan_for("read_file", {"path": "src/a.py"}, CTX)
    assert [(c.action, c.resource_id) for c in plan.checks] == [("file.read", WS + "/src/a.py")]
    assert plan.rewrite == {"path": WS + "/src/a.py"}


def test_write_tools():
    assert checks("write_file", {"path": "/etc/hosts", "content": "x"}) == [("file.write", "file", "/etc/hosts")]
    assert checks("patch", {"path": "a.py", "old_string": "a", "new_string": "b"}) == [("file.write", "file", WS + "/a.py")]


def test_writes_into_dot_git_need_their_own_grant():
    got = checks("write_file", {"path": ".git/hooks/pre-commit", "content": "x"})
    assert ("repo.internal", "file", WS + "/.git/hooks/pre-commit") in got
    got = checks("terminal", {"command": "cp x .git/config"})
    assert ("repo.internal", "file", WS + "/.git/config") in got


def test_dot_git_case_folds_on_windows():
    ctx = mapping.Context(workspace="C:\\ws", style="windows", home=None, resolve_links=False)
    got = checks("write_file", {"path": ".GIT\\hooks\\post-checkout", "content": "x"}, ctx)
    assert ("repo.internal", "file", "C:\\ws\\.GIT\\hooks\\post-checkout") in got


def test_missing_or_unpinnable_paths_are_unresolved():
    assert checks("read_file", {}) == [("file.read", "file", "unresolved")]
    assert checks("read_file", {"path": "~root/.ssh/id"}) == [("file.read", "file", "unresolved")]
    assert checks("read_file", {"path": "a\x00b"}) == [("file.read", "file", "unresolved")]


def test_search_defaults_to_the_workspace():
    assert checks("search_files", {"pattern": "x"}) == [("file.read", "file", WS)]


def test_terminal_pins_the_working_directory():
    plan = mapping.plan_for("terminal", {"command": "ls"}, CTX)
    assert plan.rewrite == {"workdir": WS}
    plan = mapping.plan_for("terminal", {"command": "ls", "workdir": "/etc"}, CTX)
    assert ("file.read", "/etc") in [(c.action, c.resource_id) for c in plan.checks]
    assert plan.rewrite == {"workdir": "/etc"}


def test_terminal_unreadable_command():
    got = checks("terminal", {"command": "cat $(echo /etc/passwd)"})
    assert got == [("shell.run", "program", "unreadable-command")]


def test_terminal_program_names_are_never_rewritten_into_others():
    assert ("shell.run", "program", "unresolved") in checks("terminal", {"command": "'ls!' x"})


def test_execute_code_and_browser_and_unknown_tools():
    assert checks("execute_code", {"code": "print(1)"}) == [("code.run", "runtime", "python")]
    assert checks("browser_exec", {"code": "x"}) == [("browser.use", "tool", "browser_exec")]
    assert checks("some_new_tool", {}) == [("tool.call", "tool", "some_new_tool")]
    assert checks("mcp_linkedin_create_post", {}) == [("mcp.call", "tool", "linkedin_create_post")]


@pytest.mark.parametrize("url,rid", [
    ("https://Example.COM/a?b=c", "https/example.com"),
    ("http://example.com:8080/", "http/example.com:8080"),
    ("https://bücher.example/", "https/xn--bcher-kva.example"),
])
def test_urls(url, rid):
    assert checks("web_extract", {"urls": [url]}) == [("web.fetch", "url", rid)]


@pytest.mark.parametrize("url", [
    "file:///etc/passwd", "https://user:pw@example.com/", "https://[::1]/", "javascript:alert(1)", "", 5,
])
def test_urls_that_cant_be_read_plainly_are_unresolved(url):
    assert checks("web_extract", {"urls": [url]}) == [("web.fetch", "url", "unresolved")]


def test_every_url_is_checked():
    got = checks("web_extract", {"urls": ["https://a.example", "https://b.example"]})
    assert got == [("web.fetch", "url", "https/a.example"), ("web.fetch", "url", "https/b.example")]


def test_vision_reads_local_files_through_the_file_check():
    assert checks("vision_analyze", {"image_url": "/etc/x.png", "question": "?"}) == [("file.read", "file", "/etc/x.png")]
    assert checks("vision_analyze", {"image_url": "https://x.example/i.png", "question": "?"}) == [("web.fetch", "url", "https/x.example")]


def test_cron_and_memory_and_admin():
    assert checks("cronjob_manage", {"action": "create"}) == [("cron.manage", "job", "create")]
    assert checks("memory", {"target": "user", "operations": []}) == [("memory.write", "store", "user")]
    assert checks("manage_catalog", {"action": "install"}) == [("hermes.admin", "tool", "manage_catalog")]


def test_args_that_are_not_a_dict_still_map_to_a_refusable_check():
    assert checks("read_file", None) == [("file.read", "file", "unresolved")]


V4A = """*** Begin Patch
*** Update File: src/app.py
@@ def main():
-    pass
+    run()
*** Add File: /etc/cron.d/x
+* * * * * root sh -c evil
*** Delete File: old.py
*** End Patch
"""


def test_v4a_patches_check_every_file_they_touch():
    got = checks("patch", {"mode": "patch", "patch": V4A})
    assert ("file.write", "file", WS + "/src/app.py") in got
    assert ("file.write", "file", "/etc/cron.d/x") in got
    assert ("file.write", "file", WS + "/old.py") in got


def test_v4a_move_checks_both_ends():
    got = checks("patch", {"mode": "patch", "patch": "*** Begin Patch\n*** Move File: a.py -> /tmp/a.py\n*** End Patch\n"})
    assert ("file.write", "file", WS + "/a.py") in got
    assert ("file.write", "file", "/tmp/a.py") in got


def test_v4a_markers_are_read_with_hermess_own_spacing_rules():
    # Hermes's parser accepts "***Add File:/x" and runs of spaces; so must this.
    got = checks("patch", {"mode": "patch", "patch": "***Add  File:/etc/x\n+y\n***Delete File:   /etc/y\n"})
    assert ("file.write", "file", "/etc/x") in got and ("file.write", "file", "/etc/y") in got


def test_v4a_without_files_or_with_unknown_headers_is_unresolved():
    assert checks("patch", {"mode": "patch", "patch": "*** Begin Patch\n*** End Patch\n"}) == [("file.write", "file", "unresolved")]
    assert ("file.write", "file", "unresolved") in checks("patch", {"mode": "patch", "patch": "*** Begin Patch\n*** Copy File: a\n"})
    assert ("file.write", "file", "unresolved") in checks("patch", {"mode": "patch", "patch": "*** Update File: a.py\n*** Move to: /tmp/a.py\n"})
    assert checks("patch", {"mode": "patch"}) == [("file.write", "file", "unresolved")]


def test_v4a_agrees_with_hermess_parser_when_available():
    import os
    import sys
    src = os.environ.get("HERMES_SRC")
    if not src:
        pytest.skip("HERMES_SRC isn't set")
    sys.path.insert(0, src)
    from tools.patch_parser import parse_v4a_patch
    for text in (V4A, "***Add  File:/etc/x\n+y\n", "*** Begin Patch\n*** Move File: a.py -> /tmp/a.py\n*** End Patch\n"):
        ops, err = parse_v4a_patch(text)
        theirs = set()
        for op in ops:
            theirs.add(op.file_path)
            if op.new_path:
                theirs.add(op.new_path)
        ours = {c.resource_id for c in mapping.plan_for("patch", {"mode": "patch", "patch": text}, CTX).checks}
        for p in theirs:
            assert paths.resolve(p, WS, "posix") in ours, (text, p, ours)


def test_v4a_crlf_patch_is_read():
    got = checks("patch", {"mode": "patch", "patch": "*** Begin Patch\r\n*** Add File: /etc/x\r\n+y\r\n*** End Patch\r\n"})
    assert ("file.write", "file", "/etc/x") in got


def test_v4a_patch_key_without_mode_is_still_parsed():
    got = checks("patch", {"patch": "*** Begin Patch\n*** Add File: /etc/x\n+y\n*** End Patch"})
    assert ("file.write", "file", "/etc/x") in got


def test_text_to_speech_output_path_is_a_write():
    got = checks("text_to_speech", {"text": "hi", "output_path": "/etc/profile.d/x.sh"})
    assert ("file.write", "file", "/etc/profile.d/x.sh") in got


def test_kanban_writes_are_checked():
    assert checks("kanban_create", {"title": "x"}) == [("kanban.write", "tool", "kanban_create")]
