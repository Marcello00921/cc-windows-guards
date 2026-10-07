# -*- coding: utf-8 -*-
"""kill_by_name: deny killing processes by NAME. Kill only the PID of what you started.

Why: `taskkill /F /IM python.exe` run by one agent to clean up its own test processes kills EVERY
python on the machine: other agents' long runs, MCP servers, dev servers, background jobs of other
sessions. A sandbox that isolates files does not isolate processes, and "work only inside this folder"
does not reach a command that kills by image name.

Denies: `taskkill` with `/IM`; `Stop-Process -Name` (any prefix: `-n`, `-ProcessName`, alias `spps`);
`Get-Process` without `-Id` piped into `Stop-Process` or `.Kill()` (also through `Where-Object` filters);
`pkill`; `killall` (also inside quotes: `bash -lc "pkill -f x"`); `kill $(pgrep|pidof ...)`;
`wmic process where name=... delete|call terminate`; `Win32_Process` filtered by name and terminated (CIM/WMI);
`kill -Name x` (the PowerShell alias). From the PowerShell tool only, `kill -n x` too: in bash `-n` is a signal.
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

# PowerShell accepts any unambiguous prefix of a parameter: `-n`, `-na`, `-Name`, `-ProcessName`, `-pr`
_PS_NAME = r"-(?:n(?:a(?:me?)?)?|pr(?:o(?:c(?:e(?:s(?:s(?:n(?:a(?:me?)?)?)?)?)?)?)?)?)(?=[\s:]|$)"
# a command start: line start, separator, or a quote (`bash -lc "pkill ..."` from the PowerShell tool)
_START = r"(?:^|[\s;&|(\"'])"

PATTERNS = (
    ("taskkill /IM", re.compile(r"\btaskkill(?:\.exe)?\b[^\n;&|]*?\s[/-]{1,2}im\b", re.I)),
    ("Stop-Process -Name", re.compile(r"\b(?:Stop-Process|spps)\b[^\n;|]*\s" + _PS_NAME, re.I)),
    ("Get-Process <name> | Stop-Process", re.compile(
        r"\b(?:Get-Process|gps|ps)\s+(?!-Id\b)(?!-)[^\n|;]*\|\s*(?:Stop-Process|spps|kill)\b", re.I)),
    ("pkill", re.compile(_START + r"pkill\b", re.I)),
    ("killall", re.compile(_START + r"killall\b", re.I)),
    ("kill $(pgrep)", re.compile(r"\bkill\b[^\n;]*\$\(\s*(?:pgrep|pidof)\b", re.I)),
    ("wmic by name", re.compile(r"\bwmic\b[^\n]*\bprocess\b[^\n]*\bname\b[^\n]*\b(?:delete|terminate)\b", re.I)),
    ("Win32_Process by name | Terminate", re.compile(
        r"\bWin32_Process\b[^\n;]*\bname\b[^\n;]*\bTerminate\b", re.I)),
    # `kill -Name x` is Stop-Process in PowerShell; bash `kill` has no `-Name` / `-ProcessName`
    ("kill -Name (PowerShell alias)", re.compile(_START + r"kill\s[^\n;|]*?-(?:Process)?Name\b", re.I)),
)
# only from the PowerShell tool: there `kill` is Stop-Process and `-n` is -Name (in bash, `kill -n 9` is a signal)
PS_ONLY = (
    ("kill -n (PowerShell alias)", re.compile(_START + r"kill\s[^\n;|]*?" + _PS_NAME, re.I)),
)
# Get-Process without -Id whose objects reach Stop-Process or .Kill(), in the same statement:
# `Get-Process -Name node | Stop-Process`, `Get-Process | ? Name -eq x | Stop-Process`, `(Get-Process x).Kill()`
_GPS = re.compile(r"\b(?:Get-Process|gps)\b", re.I)
_GPS_KILL = re.compile(r"\|\s*(?:Stop-Process|spps|kill)\b|\.Kill\s*\(", re.I)
_BY_ID = re.compile(r"(?:^|\s)-Id\b|\.Id\s*-(?:eq|in)\b|\bId\s+-(?:eq|in)\b", re.I)


def match(event: dict) -> str:
    """Name of the kill-by-name pattern found in the command, or ''."""
    cmd = str(((event or {}).get("tool_input") or {}).get("command") or "")
    ps = str((event or {}).get("tool_name") or "").lower().startswith("power")
    for name, rx in PATTERNS + (PS_ONLY if ps else ()):
        if rx.search(cmd):
            return name
    for stmt in re.split(r"[;\n]", cmd):
        if _GPS.search(stmt) and _GPS_KILL.search(stmt) and not _BY_ID.search(stmt):
            return "Get-Process ... | Stop-Process / .Kill()"
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
