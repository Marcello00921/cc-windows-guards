# -*- coding: utf-8 -*-
"""Tests for blast_radius, kill_by_name and guard. Run: python -m unittest

Every check runs against a fake home / project / temp tree, never the real ones.
"""
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import blast_radius as br  # noqa: E402
import kill_by_name as kbn  # noqa: E402

WIN = os.name == "nt"


def n(p):
    return str(p).replace("\\", "/")


class Sandbox:
    def __init__(self):
        self.base = pathlib.Path(tempfile.mkdtemp(prefix="cc_guards_"))
        self.home = self.base / "home"
        self.proj = self.home / "proj"
        self.other = self.home / "other"
        self.tmp = self.base / "tmp"
        for d in (self.home / "Desktop", self.proj / ".git", self.proj / "src", self.proj / "keep",
                  self.proj / ".claude" / "worktrees" / "x", self.other / "sub", self.tmp / "big", self.tmp / "small"):
            d.mkdir(parents=True, exist_ok=True)
        (self.proj / ".claude" / "worktrees" / "x" / ".git").write_text("gitdir: elsewhere")
        for k in range(250):
            (self.tmp / "big" / ("f%03d.tmp" % k)).touch()
        for k in range(5):
            (self.tmp / "small" / ("f%d.tmp" % k)).touch()
        self.env = {"USERPROFILE": n(self.home), "HOME": n(self.home), "TEMP": n(self.tmp), "TMP": n(self.tmp),
                    "CLAUDE_PROJECT_DIR": n(self.proj)}

    def close(self):
        shutil.rmtree(self.base, ignore_errors=True)


class BlastRadiusTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sb = Sandbox()

    @classmethod
    def tearDownClass(cls):
        cls.sb.close()

    def ev(self, cmd, tool="Bash", cwd=None, **extra_env):
        env = dict(self.sb.env, **extra_env)
        return br.evaluate(cmd, tool, n(cwd or self.sb.proj), env)

    def assertDenied(self, kind, cmd, tool="Bash", cwd=None, **extra_env):
        r = self.ev(cmd, tool, cwd, **extra_env)
        self.assertTrue(r and r["deny"], "should deny: %s -> %r" % (cmd, r))
        self.assertEqual(r["kind"], kind, "%s -> %s" % (cmd, r["text"][:200]))

    def assertAllowed(self, cmd, tool="Bash", cwd=None, **extra_env):
        r = self.ev(cmd, tool, cwd, **extra_env)
        self.assertTrue(r is None or not r["deny"], "should allow: %s -> %s" % (cmd, r and r["text"][:300]))
        return r

    # ── the #97660 shape: empty or undefined variable ──
    def test_empty_variable_is_denied(self):
        sb = self.sb
        self.assertDenied("empty", 'rm -rf "$EMPTY_X/"')
        self.assertDenied("empty", 'rm -rf "${EMPTY_X}x"', cwd=sb.tmp)          # would land in an allowed zone
        self.assertDenied("empty", 'Remove-Item -Recurse -Force "$env:EMPTY_X\\"', "PowerShell")
        self.assertDenied("empty", 'bash -c \'rm -rf "$EMPTY_X/"\'', "PowerShell")
        self.assertDenied("empty", 'rm -f "$EMPTY_X"/*')                          # not recursive: still denied
        self.assertDenied("empty", "python -c \"import shutil,sys; shutil.rmtree(sys.argv[1])\" \"$EMPTY_X\"")

    # ── forbidden zones ──
    def test_roots_home_desktop_project_git(self):
        sb = self.sb
        for cmd in ("rm -rf \\", "rm -rf /", "rm -rf ~", "rm -rf " + n(sb.home), "rm -rf " + n(sb.base),
                    "rm -rf ~/Desktop", "rm -rf ~/Desktop/anything", "rm -rf " + n(sb.proj), "rm -rf .",
                    "rm -rf " + n(sb.other), "rm -rf .git", "rm -rf src/../.git", "rm -rf *",
                    "cd ~ && rm -rf Desktop", "rm -f ~/*", "rm -f ~/Desktop/*.txt", "rm -f .git/*.lock",
                    "git clean -fdx", "find ~ -name '*.pyc' -delete", "find ~ -mtime +14 -delete",
                    "rm -rf .claude/worktrees/x", "rm -rf " + n(sb.tmp),
                    "python -c \"import shutil; shutil.rmtree('%s')\"" % n(sb.home),
                    "python -c \"import shutil,sys; shutil.rmtree(sys.argv[1])\" " + n(sb.other)):
            self.assertDenied("zone", cmd)
        self.assertDenied("zone", "git -C %s clean -fd" % n(sb.proj), cwd=sb.tmp)
        self.assertDenied("zone", "Remove-Item -Recurse -Force \\", "PowerShell")
        self.assertDenied("zone", "Get-ChildItem %s -Recurse | Remove-Item -Force" % n(sb.home), "PowerShell")

    @unittest.skipUnless(WIN, "Windows paths")
    def test_windows_spellings(self):
        sb = self.sb
        hw, pw = str(sb.home), str(sb.proj)
        self.assertDenied("zone", "rm -rf /c/")
        self.assertDenied("zone", "rm -rf 'C:\\'")
        self.assertDenied("zone", "Remove-Item C:\\ -Recurse -Force", "PowerShell")
        self.assertDenied("zone", 'cmd //c "rd /s /q %s"' % hw)
        self.assertDenied("zone", "cmd /c rd /s /q %s" % pw, "PowerShell")
        self.assertDenied("zone", "cmd /c del /s /q %s\\*.tmp" % hw, "PowerShell")
        self.assertDenied("zone", "for w in a b; do cmd //c \"rmdir /s /q %s\\\\$w\"; done" % hw.replace("\\", "\\\\"))

    @unittest.skipUnless(WIN, "8.3 short names exist only on Windows")
    def test_short_8dot3_name_hits_the_same_rule(self):
        import ctypes
        long_dir = self.sb.base / "a folder with a long name"
        long_dir.mkdir(exist_ok=True)
        buf = ctypes.create_unicode_buffer(1024)
        ctypes.windll.kernel32.GetShortPathNameW(str(long_dir), buf, 1024)
        short = buf.value
        if not short or "~" not in short:
            self.skipTest("8.3 name generation is off on this volume")
        env = dict(self.sb.env, USERPROFILE=n(long_dir), HOME=n(long_dir))
        r = br.evaluate("rm -rf " + n(short), "Bash", n(self.sb.proj), env)
        self.assertTrue(r and r["deny"] and "HOME" in r["text"], r)

    def test_unresolvable_target(self):
        self.assertDenied("unresolved", "S=$(ls -td x* | head -1); rm -rf $S/sub")
        self.assertDenied("unresolved", "ls | xargs rm -rf")
        self.assertDenied("unresolved", "rm -rf $(cat list.txt)")

    def test_size_cap(self):
        t = n(self.sb.tmp)
        self.assertDenied("size", "rm -rf %s/big" % t)
        self.assertDenied("size", "rm -rf %s/big/*" % t)
        self.assertDenied("size", "find %s -name '*.tmp' -delete" % t)
        self.assertDenied("size", "find %s -maxdepth 1 -name big -exec rm -rf {} +" % t)
        self.assertAllowed("BLAST_OK=1 rm -rf %s/big" % t)
        self.assertAllowed("rm -rf %s/big" % t, BLAST_RADIUS_MAX_FILES="1000")

    # ── allowed ──
    def test_allowed_zone(self):
        sb, t = self.sb, n(self.sb.tmp)
        for cmd in ("rm -rf missing_build_dir", 'D=src; rm -rf "$D"', 'rm -rf "${EMPTY_X:-src}"',
                    "rm -rf /tmp/missing_x", "rm -rf .claude/worktrees/x/node_modules",
                    "find %s -name '*.tmp' -path '*small*' -delete" % t,
                    "python -c \"import shutil; shutil.rmtree('src', ignore_errors=True)\"",
                    'D=src && rm -f "$D"/~\\$*.doc', "for d in /tmp/missing_*; do rm -rf \"$d\"; done",
                    "T=$(mktemp -d); rm -rf $T/sub", "python - <<'PY'\nimport shutil\nshutil.rmtree(base)\nPY",
                    "rm -f src/*.pyc", "rm -rf src/__pycache__"):
            self.assertAllowed(cmd)
        self.assertAllowed('for d in a b; do rm -rf "$d"; done', cwd=sb.tmp)
        self.assertAllowed("Remove-Item -Recurse -Force $env:TEMP\\missing_x", "PowerShell")
        r = self.assertAllowed("rm -rf %s/small" % t)
        self.assertEqual(r["n"], 5)

    def test_settings_only_allow_protect(self):
        sb = self.sb
        self.assertDenied("zone", "rm -rf src", BLAST_RADIUS_ONLY="out")
        self.assertDenied("zone", "rm -rf out", BLAST_RADIUS_ONLY="out")
        self.assertAllowed("rm -rf out/x", BLAST_RADIUS_ONLY="out")
        self.assertDenied("zone", "rm -rf keep", BLAST_RADIUS_PROTECT=n(sb.proj / "keep"))
        self.assertAllowed("rm -rf %s/sub" % n(sb.other), BLAST_RADIUS_ALLOW=n(sb.other))

    def test_everyday_commands_stay_silent(self):
        common = ["git status --short | head", "git rm -r -q --cached build/", 'grep -rn "rm -rf" . | head',
                  'echo "never rm -rf /"', "rm -f data/x.json", "rm a.txt b.txt", 'rmdir "$B/empty"',
                  "find . -name '*.py' | head", "git clean -n -d", "git clean -nfdx", "del file.txt",
                  "ls -t notes/*.md | head -1", "git log --oneline -5", "git diff --stat | tail -3",
                  "git add a.py && git commit -m x -- a.py", "python -c \"print('rmtree')\"",
                  "find src -type f -mtime +7 | wc -l", "git worktree list", "rm -f /tmp/x.log",
                  "echo rd /s /q C:\\", "git branch --show-current", "npm run build", "gh pr list",
                  "git show HEAD --stat | head", "python -m unittest -v", "make clean"]
        ps = ["Remove-Item src\\x.txt", "Remove-Item -Recurse -WhatIf C:\\", "Get-ChildItem src -Recurse | Measure-Object",
              "Remove-Item $env:TEMP\\x.txt -Force", "Write-Output 'Remove-Item -Recurse'", "Test-Path src\\x"]
        for c in common:
            self.assertIsNone(self.ev(c), c)
        for c in ps:
            self.assertIsNone(self.ev(c, "PowerShell"), c)

    # ── negative controls: break the guard, the suite must notice ──
    def test_negative_control_empty_variable_check(self):
        with mock.patch.object(br, "_empty_var", lambda name: [""]):
            r = self.ev('rm -rf "${EMPTY_X}x"', cwd=self.sb.tmp)
        self.assertFalse(r and r["deny"] and r["kind"] == "empty",
                         "with the empty-variable check removed the case must stop being denied as 'empty'")

    def test_negative_control_zone_check(self):
        with mock.patch.object(br, "_zone", lambda a, ctx: (True, "mutant")):
            r = self.ev("rm -rf " + n(self.sb.other))
        self.assertFalse(r and r["deny"], "with the zone check removed the case must pass")


class KillByNameTest(unittest.TestCase):
    def ev(self, cmd):
        return {"tool_name": "Bash", "tool_input": {"command": cmd}}

    def test_denied(self):
        for c in ['cd "C:/x"; taskkill //F //IM python.exe >/dev/null 2>&1; cat a.txt', "taskkill /f /im node.exe",
                  "taskkill.exe -IM python.exe -F", "Stop-Process -Name python -Force",
                  "Get-Process python | Stop-Process", "pkill -f server.py", "sleep 1; killall python3",
                  "kill -9 $(pgrep -f server)", "wmic process where name='python.exe' delete"]:
            self.assertTrue(kbn.match(self.ev(c)), c)
            self.assertEqual(kbn.decide(self.ev(c))["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_allowed(self):
        for c in ["taskkill //PID 4312 //T //F", "kill 4312", "kill -9 4312", "Stop-Process -Id 4312 -Force",
                  "Get-Process -Id 4312 | Stop-Process", "python -c \"import os; os.kill(4312, 9)\""]:
            self.assertFalse(kbn.match(self.ev(c)), c)
            self.assertIsNone(kbn.decide(self.ev(c)))


class RealHookTest(unittest.TestCase):
    """The real path: JSON on stdin, JSON on stdout, rc 0."""

    def run_hook(self, script, stdin, env=None):
        return subprocess.run([sys.executable, str(ROOT / script)], input=stdin, capture_output=True, text=True,
                              encoding="utf-8", timeout=60, env=env)

    def test_guard_denies_empty_variable(self):
        sb = Sandbox()
        try:
            env = dict(os.environ)
            env.pop("EMPTY_X", None)
            env.update(sb.env)
            e = {"tool_name": "Bash", "tool_input": {"command": 'rm -rf "$EMPTY_X/"'}, "cwd": n(sb.proj)}
            r = self.run_hook("guard.py", json.dumps(e), env)
            out = json.loads(r.stdout)["hookSpecificOutput"]
            self.assertEqual(r.returncode, 0)
            self.assertEqual(out["permissionDecision"], "deny")
            self.assertIn("97660", out["permissionDecisionReason"])
        finally:
            sb.close()

    def test_guard_denies_kill_by_name(self):
        e = {"tool_name": "PowerShell", "tool_input": {"command": "Stop-Process -Name node -Force"}}
        r = self.run_hook("guard.py", json.dumps(e))
        self.assertEqual(r.returncode, 0)
        self.assertEqual(json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_guard_silent_on_harmless_and_on_bad_input(self):
        r = self.run_hook("guard.py", json.dumps({"tool_name": "Bash", "tool_input": {"command": "git status"}}))
        self.assertEqual((r.returncode, r.stdout.strip()), (0, ""))
        for script in ("guard.py", "blast_radius.py", "kill_by_name.py"):
            r = self.run_hook(script, "not json")
            self.assertEqual((r.returncode, r.stdout.strip()), (0, ""), script)


if __name__ == "__main__":
    unittest.main()
