# -*- coding: utf-8 -*-
"""kill_by_name: deny killing processes by NAME. Kill only the PID of what you started.

Why: `taskkill /F /IM python.exe` run by one agent to clean up its own test processes kills EVERY
python on the machine: other agents' long runs, MCP servers, dev servers, background jobs of other
sessions. A sandbox that isolates files does not isolate processes, and "work only inside this folder"
does not reach a command that kills by image name.

Denies: `taskkill` with `/IM`; `Stop-Process -Name`; `Get-Process <name> | Stop-Process`; `pkill`;
`killall`; `kill $(pgrep|pidof ...)`; `wmic process where name=... delete|call terminate`.
Allows: `taskkill /PID <n> /T /F`, `kill <pid>`, `Stop-Process -Id <n>`.
Any internal error lets the command through (a guard that breaks work by its own bug is worse than none).

    python kill_by_name.py < event.json        (PreToolUse hook, JSON on stdin)
"""
import json
import re
import sys

for _f in (sys.stdout, sys.stderr):
    try:
        _f.reconfigure(encoding="utf-8")
    except Exception:
        pass

PATTERNS = (
    ("taskkill /IM", re.compile(r"\btaskkill(?:\.exe)?\b[^\n;&|]*?\s[/-]{1,2}im\b", re.I)),
    ("Stop-Process -Name", re.compile(r"\b(?:Stop-Process|spps)\b[^\n;|]*\s-(?:Process)?Name\b", re.I)),
    ("Get-Process <name> | Stop-Process", re.compile(
        r"\b(?:Get-Process|gps|ps)\s+(?!-Id\b)(?!-)[^\n|;]*\|\s*(?:Stop-Process|spps|kill)\b", re.I)),
    ("pkill", re.compile(r"(?:^|[\s;&|(])pkill\b", re.I)),
    ("killall", re.compile(r"(?:^|[\s;&|(])killall\b", re.I)),
    ("kill $(pgrep)", re.compile(r"\bkill\b[^\n;]*\$\(\s*(?:pgrep|pidof)\b", re.I)),
    ("wmic by name", re.compile(r"\bwmic\b[^\n]*\bprocess\b[^\n]*\bname\b[^\n]*\b(?:delete|terminate)\b", re.I)),
)


def match(event: dict) -> str:
    """Name of the kill-by-name pattern found in the command, or ''."""
    cmd = str(((event or {}).get("tool_input") or {}).get("command") or "")
    for name, rx in PATTERNS:
        if rx.search(cmd):
            return name
    return ""


def decide(event: dict):
    """PreToolUse response for one hook event, or None."""
    which = match(event)
    if not which:
        return None
    text = ("Killing a process by NAME (%s) takes down every matching process on the machine, not only yours: "
            "other sessions, background jobs, MCP and dev servers. Kill the PID of what YOU started: "
            "`taskkill /PID <pid> /T /F`, `kill <pid>`, `Stop-Process -Id <pid>`." % which)
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                   "permissionDecisionReason": text}}


def main() -> int:
    try:
        event = json.loads(sys.stdin.read() or "{}")
    except Exception:
        return 0
    r = decide(event)
    if r:
        print(json.dumps(r, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        sys.exit(0)
