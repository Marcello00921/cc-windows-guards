# cc-windows-guards

Two Claude Code `PreToolUse` guards for Bash and PowerShell, built for Windows first:

- **blast radius**: resolves the real target of `rm -rf`, `Remove-Item -Recurse`, `rd /s`, `del /s`,
  `find -delete`, `git clean -f` and `shutil.rmtree` *before* the command runs, and denies it when
  the target is empty, unresolvable, outside the working tree, or too big;
- **kill by name**: denies `taskkill /IM`, `Stop-Process -Name`, `pkill`, `killall` and friends.
  Kill the PID of what you started, not every process with the same name.

## Commands from the PowerShell tool

Agents on Windows often reach bash, WSL or .NET from the PowerShell tool. The guards follow them:

| command (PowerShell tool) | result |
|---|---|
| `bash -lc "rm -rf /c/other"`, `& "C:\Program Files\Git\bin\bash.exe" -lc '...'`, `sh -ec`, `bash --login -c` | judged as the inner bash command |
| `wsl rm -rf /mnt/c/...`, `wsl -d Ubuntu -- rm -rf ...` | judged as bash; `/mnt/c/` is read as `C:/` |
| `Remove-Item -Recurse` / `ri -r` / `gci ... \| ri -Recurse` outside the project tree | deny |
| `[System.IO.Directory]::Delete("C:\other", $true)` | judged like `Remove-Item -Recurse`; a computed path is denied |
| `Stop-Process -Name x`, `spps -n x`, `-ProcessName`, `kill -Name x`, `kill -n x` | deny |
| `Get-Process -Name x \| Stop-Process`, `Get-Process \| ? Name -eq x \| Stop-Process`, `(Get-Process x).Kill()` | deny |
| `Get-CimInstance Win32_Process -Filter "Name='x'" \| Invoke-CimMethod -MethodName Terminate` | deny |
| `Stop-Process -Id 1234`, `Get-Process -Id 1234 \| Stop-Process`, `Get-Process x \| Select Id` | allow |

`kill -n` is read as `-Name` only from the PowerShell tool: in bash, `kill -n 9 <pid>` sends a signal.

## Why

Related issue: [anthropics/claude-code#97660](https://github.com/anthropics/claude-code/issues/97660).
On Windows, an agent moved from PowerShell to bash with an empty variable. `rm -rf "$VAR/"`
became `rm -rf /` and wiped the drive. Every Bash/PowerShell tool call is a **new shell**, so a
variable set in one call does not exist in the next one.

Claude Code 2.1.292 fixed `rm -rf` on the 8.3 short name of the user folder
(`C:\Users\JOHNSM~1`). This hook still covers the general case: empty variables, `$(...)`,
`xargs`, nested `bash -c` / `cmd /c` / `powershell -EncodedCommand`, MSYS paths (`/c/...`) and
paths outside the project. It also resolves 8.3 short names to long names before it compares paths.

The kill-by-name guard comes from a real incident. `taskkill /F /IM python.exe`, run to clean up
one agent's test processes, also killed every other Python process on the machine: other
sessions' long jobs, MCP servers and dev servers.

## What the blast radius guard decides

| situation | result |
|---|---|
| variable empty or undefined in the target (`rm -rf "$X/"`, `$env:X`, `%X%`) | deny |
| target from `$(...)`, backticks, `xargs`, `$1`, a loop fed by a command | deny (cannot be measured) |
| drive root, home, Desktop, project root, any repo root, whole worktree, `.git`, a folder containing any of them | deny |
| recursive delete outside the project tree, the temp folder, `.claude/worktrees/<x>/…` and `BLAST_RADIUS_ALLOW` | deny |
| `rm -rf *` over a forbidden folder | deny |
| allowed zone, more than 200 files or 500 MB | deny with the first 10 files; `BLAST_OK=1` on the command allows it |
| allowed zone, under the cap | allow (adds the file count as context) |
| `rm -f` / `Remove-Item` of loose files, even with a glob | allow, unless the variable is empty or the folder is root/home/Desktop/`.git` |
| `__pycache__`, `node_modules`, `.pytest_cache`, `dist/`, `build/` next to a manifest, inside any repo | allowed zone |

If the guard hits an internal error before it recognizes a destructive command, it lets the
command through. If the error comes after that, it denies.

## Install

Python 3.8+ and the standard library only. Copy `guard.py`, `blast_radius.py` and
`kill_by_name.py` to, for example, `.claude/hooks/`, and register **one** hook (one Python start
for both guards):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell",
        "hooks": [
          {
            "type": "command",
            "command": "python \"$CLAUDE_PROJECT_DIR/.claude/hooks/guard.py\"",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

Each module also works alone as a hook (`python blast_radius.py`, `python kill_by_name.py`).

## Settings (environment)

| variable | default | meaning |
|---|---|---|
| `BLAST_RADIUS_MAX_FILES` | `200` | file cap for one delete |
| `BLAST_RADIUS_MAX_MB` | `500` | size cap for one delete |
| `BLAST_RADIUS_ONLY` | empty | comma list of project subfolders where recursive delete is allowed (e.g. `build,out`); empty = the whole project tree |
| `BLAST_RADIUS_ALLOW` | empty | extra folders where recursive delete is allowed (`os.pathsep` separated) |
| `BLAST_RADIUS_PROTECT` | empty | extra folders that are never deleted |

The project is `CLAUDE_PROJECT_DIR`, or the git root of the hook's `cwd` if that variable is not set.

## Check it against your own history

```sh
python blast_radius.py --scan-transcripts --days=7
```

This replays every unique Bash/PowerShell command in your local Claude Code transcripts and lists
what would be denied. Use it to find false positives before you turn the hook on.

## Tests

```sh
python -m unittest -v
```

The tests use a fake home, project and temp tree, so nothing real is touched. They cover the
deny and allow tables, the settings, about 30 everyday commands that must stay silent, the real
hook path (JSON on stdin, rc 0), and two negative controls that remove the empty-variable check
and the zone check and confirm the cases flip. Tested on Windows 11 with Python 3.13. POSIX paths
are handled but have had less testing. The 8.3 test is skipped on volumes where short-name
generation is off.

## License

MIT, see [LICENSE](LICENSE).
