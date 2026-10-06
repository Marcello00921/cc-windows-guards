# -*- coding: utf-8 -*-
"""guard: one PreToolUse hook (Bash|PowerShell) that runs both guards.

A cold Python start costs seconds on Windows, so both checks share one process: kill_by_name always
(regexes only), blast_radius only when the command passes its cheap prefilter (rm, Remove-Item, rd,
del, find -delete, git clean, rmtree...).

    python guard.py < event.json
Any internal error exits 0 without output: the hook never blocks by its own bug.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import kill_by_name  # noqa: E402


def decide(event):
    r = kill_by_name.decide(event)
    if r:
        return r
    cmd = str(((event or {}).get("tool_input") or {}).get("command") or "")
    import blast_radius
    if not blast_radius.PREFILTER.search(cmd):
        return None
    return blast_radius.decide(event)


def main() -> int:
    try:
        event = json.loads(sys.stdin.read() or "{}")
        r = decide(event)
    except Exception:
        return 0
    if r:
        print(json.dumps(r, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        sys.exit(0)
