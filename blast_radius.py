# -*- coding: utf-8 -*-
"""blast_radius: resolve the TARGET of a mass-delete command BEFORE it runs, and deny what must not go.

Why: anthropics/claude-code#97660. On Windows an agent went from PowerShell to bash with an empty
variable; `rm -rf "$VAR/"` became `rm -rf /` and wiped the drive. Every Bash/PowerShell call is a NEW
shell, so a variable set in a previous call does not exist in the next one.

What it detects (Bash and PowerShell, also inside `bash -c`, `cmd /c`, `powershell -Command`/`-EncodedCommand`):
  rm -r/-rf/-fr or rm with a glob · Remove-Item (and the PowerShell aliases rm/del/rd/ri/rmdir) with
  -Recurse or a glob · `gci -Recurse | Remove-Item` · rd/rmdir /s and del /s (cmd) · find -delete and
  find -exec rm · git clean -f · shutil.rmtree in `python -c`.

How it decides:
  1. expands variables with the hook's environment plus the assignments on the same command line
     (X=..., for x in ..., $x = ...). An EMPTY or UNDEFINED variable is denied at once (the #97660 cause).
     $(...), xargs, $1 are denied too: the target cannot be resolved before the command runs.
  2. normalizes the path (/c/.. -> C:/.., ~, /tmp, \\\\?\\, .., 8.3 short names) and ALWAYS denies: a drive
     root, the home folder, the Desktop, the project root, any repository root or whole worktree, `.git`.
     Recursive deletion is allowed only inside: the project tree (CLAUDE_PROJECT_DIR), the temp folder,
     `.claude/worktrees/<x>/` (inside, not the worktree itself) and BLAST_RADIUS_ALLOW. Inside any
     repository, `__pycache__`, `node_modules`, `.pytest_cache`, `dist/` and `build/` (next to a
     package.json/pyproject.toml/setup.py) are disposable.
  3. inside the allowed zone it counts files and bytes; above the cap (200 files or 500 MB by default)
     it denies, shows the first 10 files and asks for `BLAST_OK=1` on the command. BLAST_OK never
     unlocks a forbidden zone.
  Zone and cap apply only to RECURSIVE deletion. `rm`/`rm -f`/`Remove-Item` of loose files, even with a
  glob, pass unless a variable is empty or the folder is a drive root, home, Desktop or `.git`
  (`rm -f $EMPTY/*`, `rm -f ~/*`).
An internal error BEFORE a destructive command is recognized lets the command through (a guard that
breaks work by its own bug is worse than none); an error AFTER that denies (here the cheap mistake is
to deny).

Settings (environment of the hook process):
  BLAST_RADIUS_MAX_FILES   cap on files deleted at once (default 200)
  BLAST_RADIUS_MAX_MB      cap on megabytes deleted at once (default 500)
  BLAST_RADIUS_ONLY        comma list of project subfolders where recursive deletion is allowed
                           (e.g. "build,out,tmp"); empty = the whole project tree
  BLAST_RADIUS_ALLOW       extra folders where recursive deletion is allowed (os.pathsep separated)
  BLAST_RADIUS_PROTECT     extra folders that are never deleted, nor any folder that contains them

    python blast_radius.py < event.json                 (PreToolUse hook, JSON on stdin)
    python blast_radius.py --scan <cmds.json>           ([{tool, command, cwd}] -> what would be denied)
    python blast_radius.py --scan-transcripts [--days=7]  (same, straight from ~/.claude/projects/*.jsonl)
"""
import base64
import fnmatch
import glob
import json
import os
import re
import shlex
import sys
import time

for _f in (sys.stdout, sys.stderr):
    try:
        _f.reconfigure(encoding="utf-8")
    except Exception:
        pass

WINDOWS = os.name == "nt"
TIME_BUDGET_S = 2.5          # the hook timeout is 10 s and a cold Python start can take ~3 s on Windows
COUNT_CEILING = 20000
CONFIRM = re.compile(r"\bBLAST_OK=1\b")
PREFILTER = re.compile(r"\brm\b|remove-item|\bri\b|\brd\b|\brmdir\b|\bdel\b|\berase\b|-delete\b|-exec(?:dir)?\b"
                       r"|\bclean\b|rmtree|-encodedcommand\b|\s-enc?\s", re.I)
PUNCT = ";&|()\n"
KEYWORDS = {"{", "}", "!", "then", "do", "else", "elif", "if", "while", "until", "done", "fi", "time", "[[", "]]"}
RX_REDIR = re.compile(r"^(?:\d+|&|\*)?(?:>>?|<<?<?|>\|)(.*)$")
RX_HEREDOC = re.compile(r"(?<!<)<<(?!<)-?\s*(['\"]?)([A-Za-z_]\w*)\1")
RX_ASSIGN = re.compile(r"^([A-Za-z_]\w*)=(.*)$", re.S)
RX_PS_ASSIGN = re.compile(r"^\$([A-Za-z_]\w*)=(.*)$", re.S)
# the whole argument must be the literal: `rmtree(r'\\?\' + sys.argv[1])` is NOT a literal
RX_RMTREE = re.compile(r"rmtree\(\s*(?:(?:pathlib\.)?Path\(\s*)?(r?)(['\"])((?:(?!\2).)*)\2\s*(?:\)\s*)?(?=[,)]|$)")
PH = "__BLAST_DOLLAR__"      # `\$` and `'$x'` in bash (and `` `$ `` / '$x' in PS) are a LITERAL dollar sign
UNRESOLVED = object()
DISPOSABLE = ("__pycache__", "node_modules", ".pytest_cache", "dist")
APP_MANIFESTS = ("package.json", "pyproject.toml", "setup.py")


class Deny(Exception):
    def __init__(self, kind, text):
        super().__init__(text)
        self.kind, self.text = kind, text


class Ctx:
    def __init__(self, cwd, env, dialect):
        self.cwd = _norm(cwd) if cwd else None
        self.env = env
        self.dialect = dialect
        self.project = _project(env, self.cwd)
        self.vars = {}
        self.targets = []         # (absolute_path, filter|None, excerpt)
        self.destructive = False
        self.recursive = False
        self.notes = []


def _limit(env, name, default):
    try:
        return float(_env(name, env) or default)
    except ValueError:
        return float(default)


# ───────────────────────────── paths ─────────────────────────────
def _norm(p: str) -> str:
    s = os.path.normpath(p).replace("\\", "/")
    return s if s in ("/",) or re.fullmatch(r"[A-Za-z]:/", s) else s.rstrip("/")


def _long(a: str) -> str:
    """Windows 8.3 short names (C:/Users/JOHNSM~1) -> the long name, so they hit the same rules."""
    if not WINDOWS or "~" not in a:
        return a
    try:
        r = _norm(os.path.realpath(a))
        return r if r.lower() != a.lower() else a
    except (OSError, ValueError):
        return a


def _env(name, env):
    v = env.get(name)
    if v is None:
        up = name.upper()
        for k, x in env.items():
            if k.upper() == up:
                v = x
                break
    if v is None and name.upper() == "HOME" and WINDOWS:
        v = env.get("USERPROFILE")
    if v is None and name.upper() == "TMPDIR":      # Git Bash sets TMPDIR=/tmp; the hook process does not
        v = env.get("TEMP") or env.get("TMP")
    return v


def _home(env):
    first = ("USERPROFILE", "HOME") if WINDOWS else ("HOME", "USERPROFILE")
    return _long(_norm(_env(first[0], env) or _env(first[1], env) or os.path.expanduser("~")))


def _temps(env):
    out = []
    for k in ("TEMP", "TMP", "TMPDIR"):
        v = _env(k, env)
        if v and not (WINDOWS and v.startswith("/")):
            out.append(_long(_norm(v)).lower())
    la = _env("LOCALAPPDATA", env)
    if la:
        out.append(_long(_norm(la + "/Temp")).lower())
    if not WINDOWS and not out:
        out.append("/tmp")
    return sorted(set(out))


def _paths(env, name):
    return [_long(_norm(x)) for x in (_env(name, env) or "").split(os.pathsep) if x.strip()]


def _project(env, cwd):
    p = _env("CLAUDE_PROJECT_DIR", env)
    if p:
        return _long(_norm(p))
    return _repo_root(cwd) if cwd else None


def _protected_roots(ctx):
    rs = ([ctx.project] if ctx.project else []) + _paths(ctx.env, "BLAST_RADIUS_PROTECT")
    return sorted({_long(r).lower() for r in rs if r})


def _abs(p: str, ctx: Ctx) -> str:
    s = p.replace(PH, "$").strip()
    if s == "":
        raise Deny("empty", "empty target (empty variable or empty quotes)")
    s = s.replace("\\", "/")
    if s.startswith("//?/"):
        s = s[4:]
    if s == "~" or s.startswith("~/"):
        s = _home(ctx.env) + s[1:]
    if ctx.dialect == "bash" and WINDOWS:
        m = re.match(r"^/([A-Za-z])(/.*)?$", s)
        if m:
            s = m.group(1).upper() + ":" + (m.group(2) or "/")
        elif s == "/tmp" or s.startswith("/tmp/"):
            t = _temps(ctx.env)
            s = ((_env("TEMP", ctx.env) or (t[0] if t else "/tmp")) + s[4:]).replace("\\", "/")
    if re.fullmatch(r"[A-Za-z]:", s):
        s += "/"
    if s.startswith("/") and not s.startswith("//"):
        if ctx.dialect != "bash" and WINDOWS:     # PS/cmd: "\x" is the root of the current drive
            drv = (ctx.cwd or "C:")[:2] if (ctx.cwd or "C:")[1:2] == ":" else "C:"
            s = drv + s
    elif not re.match(r"^[A-Za-z]:/", s) and not s.startswith("//"):
        if not ctx.cwd:
            raise Deny("unresolved", "relative path after a `cd` that could not be resolved")
        s = ctx.cwd + "/" + s
    return _long(_norm(s))


def _repo_root(a: str):
    p = a
    while p:
        if os.path.exists(p + "/.git"):
            return p
        parent = _norm(os.path.dirname(p))
        if parent == p or not parent:
            return None
        p = parent
    return None


def _inside(al, folders):
    return any(al.startswith(f.rstrip("/") + "/") for f in folders)


def _zone(a: str, ctx: Ctx):
    """(ok, reason) for a RECURSIVE delete. Order: always forbidden > allowed zones > everything else forbidden."""
    al = a.lower()
    if al == "/" or re.fullmatch(r"[a-z]:/?", al):
        return False, "DRIVE ROOT"
    if WINDOWS and al.startswith("/") and not al.startswith("//"):
        return False, "Git Bash POSIX path (outside the allowed zones)"
    if ".git" in al.split("/"):
        return False, ".git"
    r0 = _repo_root(a)
    if r0 and al != r0.lower():
        parts = a[len(r0):].strip("/").split("/")
        for k, part in enumerate(parts):
            parent = r0 + "/" + "/".join(parts[:k])
            if part in DISPOSABLE or (part == "build" and any(
                    os.path.exists(parent.rstrip("/") + "/" + m) for m in APP_MANIFESTS)):
                return True, "disposable folder in a repository (%s)" % part
    home = _home(ctx.env).lower()
    prot = [(home, "HOME"), (home + "/desktop", "DESKTOP"), (home + "/onedrive/desktop", "DESKTOP")]
    prot += [(r, "PROJECT ROOT / PROTECTED FOLDER") for r in _protected_roots(ctx)]
    for target, name in prot:
        if al == target:
            return False, name
        if target.startswith(al.rstrip("/") + "/"):
            return False, "folder that contains %s (%s)" % (name, target)
    if os.path.exists(a + "/.git"):
        wt = "/.claude/worktrees/" in al
        return False, "WHOLE WORKTREE (use `git worktree remove`)" if wt else "REPOSITORY ROOT"
    for t in _temps(ctx.env):
        if al.startswith(t + "/"):
            return True, "temp folder"
        if al == t:
            return False, "the temp folder itself"
    if re.search(r"/\.claude/worktrees/[^/]+/.+", al):
        return True, "inside a worktree"
    proj = (ctx.project or "").lower()
    if proj and al.startswith(proj + "/"):
        only = [x.strip().strip("/").lower() for x in (_env("BLAST_RADIUS_ONLY", ctx.env) or "").split(",")
                if x.strip()]
        if not only:
            return True, "inside the project"
        rel = al[len(proj):].strip("/").split("/")
        if rel[0] in only and len(rel) >= 2:
            return True, rel[0] + "/"
        if rel[0] in only:
            return False, "the whole %s/ folder" % rel[0]
        return False, "project folder outside BLAST_RADIUS_ONLY (%s)" % ", ".join(only)
    if _inside(al, [x.lower() for x in _paths(ctx.env, "BLAST_RADIUS_ALLOW")]):
        return True, "BLAST_RADIUS_ALLOW"
    return False, "outside the working tree"


def _hard_zone(a, ctx):
    """NON-recursive delete: only what is never bulk-deleted (drive root, home, Desktop, .git)."""
    al = a.lower().rstrip("/") or "/"
    if al == "/" or re.fullmatch(r"[a-z]:", al):
        return False, "DRIVE ROOT"
    if ".git" in al.split("/"):
        return False, ".git"
    home = _home(ctx.env).lower()
    for target, name in ((home, "HOME"), (home + "/desktop", "DESKTOP"), (home + "/onedrive/desktop", "DESKTOP")):
        if al == target or target.startswith(al + "/"):
            return False, name
    return True, ""


# ───────────────────────────── text -> segments ─────────────────────────────
def _strip_heredoc(text):
    lines, out, i = text.split("\n"), [], 0
    while i < len(lines):
        ln = lines[i]
        out.append(ln)
        i += 1
        for m in RX_HEREDOC.finditer(ln):
            while i < len(lines) and lines[i].strip() != m.group(2):
                i += 1
            i += 1
    return "\n".join(out)


RX_SUBST = re.compile(r"\$\(\s*pwd\s*\)|\$\((?:[^()]|\([^()]*\))*\)|`[^`]*`")


def _protect_dollar(text, dialect):
    """A dollar sign the shell does NOT expand becomes PH: inside single quotes, and escaped (\\$ in bash,
    `$ in PS). Otherwise `rm -f "$D"/~\\$*.doc` reads `$*` as a parameter and is denied for nothing."""
    if dialect == "cmd":
        return text
    esc = "\\" if dialect == "bash" else "`"
    out, single, double, i = [], False, False, 0
    while i < len(text):
        c = text[i]
        if c == esc and not single and i + 1 < len(text):
            if text[i + 1] == "$":
                out.append(PH)
                i += 2
                continue
            out.append(c + text[i + 1])
            i += 2
            continue
        if c == "'" and not double:
            single = not single
        elif c == '"' and not single:
            double = not double
        elif c == "$" and single:
            c = PH
        out.append(c)
        i += 1
    return "".join(out)


def _tokens(text, dialect):
    text = _protect_dollar(text, dialect)
    # $(...) and `...` become markers BEFORE splitting: "(" is a separator and `rm -rf $(cat x)` would
    # otherwise yield the target "$"
    text = RX_SUBST.sub(lambda m: "__BLAST_PWD__" if re.fullmatch(r"\$\(\s*pwd\s*\)", m.group(0))
                        else "__BLAST_MKTEMP__" if re.fullmatch(r"\$\(\s*mktemp(?:\s+-d)?\s*\)", m.group(0))
                        else "__BLAST_SUBST__", text)
    lex = shlex.shlex(text, posix=True, punctuation_chars=PUNCT)
    lex.whitespace = " \t\r"
    lex.whitespace_split = True
    lex.commenters = ""
    if dialect != "bash":
        lex.escape = ""
    try:
        toks = list(lex)
    except ValueError:                       # open quotes, `\` at the end (the `rm -rf \` of #97660)
        toks = []
        for t in re.findall(r'"[^"]*"?|\'[^\']*\'?|[;&|()\n]+|[^\s;&|()]+', text):
            if len(t) >= 2 and t[0] == t[-1] and t[0] in "\"'":
                t = t[1:-1]
            elif t[:1] in "\"'":
                t = t[1:]
            toks.append(t)
    out, i = [], 0
    while i < len(toks):                     # drop redirections: 2>&1, >/dev/null, > file, <<EOF
        t = toks[i]
        m = RX_REDIR.match(t) if t not in ("&&", "||") and not all(c in PUNCT for c in t) else None
        if m:
            i += 1
            if m.group(1) == "":
                if i < len(toks) and toks[i] == "&":
                    i += 1
                i += 1
            continue
        out.append(t)
        i += 1
    return out


def _segments(toks):
    segs, seg = [], []
    for t in toks:
        if t and all(c in PUNCT for c in t):
            segs.append((seg, t))
            seg = []
        else:
            seg.append(t)
    segs.append((seg, ""))
    return segs


# ───────────────────────────── expansion ─────────────────────────────
RX_V_BASH = re.compile(r"\$\{([A-Za-z_]\w*)(?:(:?[-=?+])([^}]*))?\}|\$([A-Za-z_]\w*|[@*#?$!0-9])|\$\(\s*pwd\s*\)|\$\(|`")
RX_V_PS = re.compile(r"\$\{env:(\w+)\}|\$env:(\w+)|\$\{(\w+)\}|\$(\w+)|\$\(", re.I)
RX_V_CMD = re.compile(r"%([^%\s]+)%")


def _value(name, ctx, ps=False):
    key = name.lower() if ps else name
    if key in ctx.vars:
        return ctx.vars[key]
    return _env(name, ctx.env)


def _empty_var(name):
    raise Deny("empty", "variable %s is EMPTY or UNDEFINED in this shell" % name)


def _expand(w: str, ctx: Ctx):
    """List of possible values of the word (a `for` loop gives several)."""
    if "__BLAST_SUBST__" in w:
        raise Deny("unresolved", "command substitution $(...) or `...` in the target")
    if "__BLAST_MKTEMP__" in w:
        w = w.replace("__BLAST_MKTEMP__", _norm((_env("TEMP", ctx.env) or "/tmp") + "/tmp.blast_mktemp"))
    if "__BLAST_PWD__" in w:
        if not ctx.cwd:
            raise Deny("unresolved", "$(pwd) after a cd that could not be resolved")
        w = w.replace("__BLAST_PWD__", ctx.cwd)
    if ctx.dialect == "cmd":
        rx = RX_V_CMD
    elif ctx.dialect == "ps":
        rx = RX_V_PS
    else:
        rx = RX_V_BASH
    m = rx.search(w)
    if not m:
        return [w]
    pre, rest = w[:m.start()], w[m.end():]
    g = m.group(0)
    if ctx.dialect == "cmd":
        name = m.group(1)
        if name.startswith("~"):
            raise Deny("unresolved", "batch variable %s" % g)
        v = _env(name, ctx.env)
        vals = [v] if v else _empty_var(g)
    elif ctx.dialect == "ps":
        if g == "$(":
            raise Deny("unresolved", "PowerShell subexpression $(...)")
        if m.group(1) or m.group(2):
            name = m.group(1) or m.group(2)
            v = _env(name, ctx.env)
            vals = [v] if v else _empty_var("$env:" + name)
        else:
            name = (m.group(3) or m.group(4)).lower()
            if name == "home":
                vals = [_home(ctx.env)]
            elif name == "pwd":
                if not ctx.cwd:
                    raise Deny("unresolved", "$PWD after a cd that could not be resolved")
                vals = [ctx.cwd]
            elif name == "null":
                vals = _empty_var("$null")
            elif name in ctx.vars:
                v = ctx.vars[name]
                if v is UNRESOLVED:
                    raise Deny("unresolved", "variable $%s has no known value" % name)
                vals = v if isinstance(v, list) else [v]
                if not any(vals):
                    vals = _empty_var("$" + name)
            else:
                raise Deny("unresolved", "PowerShell variable $%s has no value on this line" % name)
    else:
        if g.startswith("$(") and "pwd" in g:
            if not ctx.cwd:
                raise Deny("unresolved", "$(pwd) after a cd that could not be resolved")
            vals = [ctx.cwd]
        elif g in ("$(", "`"):
            raise Deny("unresolved", "command substitution %s...)" % g)
        else:
            name = m.group(1) or m.group(4)
            op, default = m.group(2), m.group(3)
            if not re.match(r"[A-Za-z_]", name):
                raise Deny("unresolved", "positional/special parameter $%s" % name)
            v = _value(name, ctx)
            if v is UNRESOLVED:
                raise Deny("unresolved", "variable $%s comes from a command or loop that cannot be resolved" % name)
            vals = v if isinstance(v, list) else ([v] if v is not None else [])
            empty = not vals or not any(vals)
            if op in (":-", "-", ":=", "=") and (empty if op.startswith(":") else v is None):
                vals = _expand(default or "", ctx)
            elif empty:
                vals = _empty_var("$" + name)
    out = []
    for v in vals:
        for r in _expand(rest, ctx):
            out.append(pre + (v or "") + r)
    return out


def _expand_all(ws, ctx):
    out = []
    for w in ws:
        out.extend(_expand(w, ctx))
    return out


# ───────────────────────────── commands ─────────────────────────────
def _assign(name, value, ctx, ps=False):
    try:
        vals = _expand(value, ctx)
        ctx.vars[name.lower() if ps else name] = vals[0] if len(vals) == 1 else vals
    except Deny:
        ctx.vars[name.lower() if ps else name] = UNRESOLVED


def _target(path, ctx, excerpt, filt=None, recursive=True):
    a = _abs(path, ctx)
    if not recursive:
        has_glob = any(c in a for c in "*?[")
        folder = _norm(re.split(r"[*?\[]", a, maxsplit=1)[0]) if has_glob else a
        if has_glob and not a[len(folder):].startswith("/") and not folder.endswith("/"):
            folder = _norm(os.path.dirname(folder))
        # a protected folder only denies a glob that starts with the wildcard (`~/*`, `~/Desktop/*.txt`);
        # `~/build*.log` is a file pattern
        broad = has_glob and os.path.basename(a)[:1] in "*?["
        for x in ([folder] if broad else []) + [a]:
            ok, why = _hard_zone(x, ctx)
            if not ok:
                raise Deny("zone", "%s -> %s" % (x, why))
        return
    ctx.recursive = True
    if any(c in a for c in "*?[") and filt is None:
        base = re.split(r"[*?\[]", a, maxsplit=1)[0]
        base = _norm(base if base.endswith("/") else os.path.dirname(base))
        if os.path.basename(a)[:1] in "*?[":       # `rm -rf *` empties the folder: judge the folder itself
            ok, why = _zone(base, ctx)
            if not ok:
                raise Deny("zone", "%s -> wildcard over %s" % (a, why))
        found = [_norm(x) for x in glob.glob(a, recursive=True)]
        for x in found:
            ok, why = _zone(x, ctx)
            if not ok:
                raise Deny("zone", "%s -> %s" % (x, why))
        if not found:
            ok, why = _zone(base + "/x", ctx)
            if not ok:
                raise Deny("zone", "%s -> %s" % (a, why))
        ctx.targets.extend((x, None, excerpt) for x in found)
        return
    container = filt is not None and (filt.get("preds") or filt.get("conservative") or filt.get("mindepth"))
    ok, why = _zone(a + "/x" if container else a, ctx)
    if not ok:
        raise Deny("zone", "%s -> %s" % (a, why))
    ctx.targets.append((a, filt, excerpt))


def _cmd_rm_gnu(args, ctx, excerpt, xargs):
    rec, targets, end = False, [], False
    for a in args:
        if not end and a == "--":
            end = True
        elif not end and a.startswith("--"):
            rec = rec or a == "--recursive"
        elif not end and a.startswith("-") and len(a) > 1:
            rec = rec or "r" in a.lower()
        else:
            targets.append(a)
    has_glob = any(any(c in x for c in "*?[") for x in targets)
    if not (rec or has_glob):
        return
    ctx.destructive = True
    ctx.recursive = ctx.recursive or rec
    if xargs and rec:
        raise Deny("unresolved", "`xargs rm -r`: the target comes from standard input")
    if xargs:
        return
    for x in _expand_all(targets, ctx):
        _target(x, ctx, excerpt, recursive=rec)


PS_VALUE = {"-path", "-literalpath", "-lp", "-pspath", "-include", "-exclude", "-filter", "-credential", "-stream",
            "-erroraction", "-ea", "-errorvariable", "-ev", "-warningaction", "-wa", "-outvariable", "-ov"}


def _ps_params(args):
    rec, whatif, targets, i = False, False, [], 0
    while i < len(args):
        a = args[i]
        al = a.lower().split(":")[0]
        if a.startswith("-") and len(a) > 1:
            if "-recurse".startswith(al) and len(al) >= 2:
                rec = not a.lower().endswith(":$false")
            elif al == "-whatif":
                whatif = True
            elif al in ("-path", "-literalpath", "-lp", "-pspath") and i + 1 < len(args):
                targets.extend(x for x in args[i + 1].split(",") if x)
                i += 1
            elif al in PS_VALUE:
                i += 1
            elif re.fullmatch(r"-[a-z]*r[a-z]*f?|-fr", al) and al not in ("-force",):   # `rm -rf` typed in PS
                rec = True
        else:
            targets.extend(x for x in a.split(",") if x)
        i += 1
    return rec, whatif, targets


def _cmd_remove_item(args, ctx, excerpt, previous):
    rec, whatif, targets = _ps_params(args)
    if whatif:
        return
    if not targets and previous:
        cw = (previous[0] or "").lower()
        if cw in ("get-childitem", "gci", "ls", "dir"):
            rec2, _, targets2 = _ps_params(previous[1:])
            if rec2 or rec:
                ctx.destructive = True
                for x in _expand_all(targets2 or ["."], ctx):
                    _target(x, ctx, excerpt)
            return
        if rec:
            ctx.destructive = True
            raise Deny("unresolved", "Remove-Item -Recurse receiving its target from the pipeline")
        return
    has_glob = any(any(c in x for c in "*?[") for x in targets)
    if not (rec or has_glob):
        return
    ctx.destructive = True
    ctx.recursive = ctx.recursive or rec
    for x in _expand_all(targets, ctx):
        _target(x, ctx, excerpt, recursive=rec)


def _cmd_cmd_rd_del(cw, args, ctx, excerpt):
    flags = [a.lower().lstrip("/") for a in args if a.startswith("/")]
    targets = [a for a in args if not a.startswith("/")]
    if "s" not in flags:
        return
    ctx.destructive = True
    ctx.recursive = True
    for x in _expand_all(targets, ctx):
        if cw in ("del", "erase"):
            a = _abs(x, ctx)
            d, pat = (os.path.dirname(a), os.path.basename(a)) if any(c in a for c in "*?") or os.path.isfile(a) \
                else (a, "*")
            _target(d, ctx, excerpt, filt={"preds": [(False, "iname", pat), (False, "type", "f")]})
        else:
            _target(x, ctx, excerpt)


def _cmd_find(args, ctx, excerpt):
    if "-delete" not in args:
        j = [i for i, a in enumerate(args) if a in ("-exec", "-execdir", "-ok")]
        if not any(i + 1 < len(args) and os.path.basename(args[i + 1]).lower() in ("rm", "rmdir", "shred")
                   for i in j):
            return
    ctx.destructive = True
    ctx.recursive = True
    start, i = [], 0
    while i < len(args) and not args[i].startswith("-") and args[i] not in ("(", "!", "\\("):
        start.append(args[i])
        i += 1
    # filter: AND-ed predicates (with ! / -not); -o and parentheses = conservative (everything matches)
    f = {"preds": [], "maxdepth": None, "mindepth": 0, "rf": False, "conservative": False}
    expr, k, neg = args[i:], 0, False
    while k < len(expr):
        e = expr[k]
        nxt = expr[k + 1] if k + 1 < len(expr) else ""
        if e in ("!", "-not"):
            neg = True
            k += 1
            continue
        if e in ("-name", "-iname", "-path", "-ipath", "-wholename", "-type", "-mtime", "-mmin"):
            f["preds"].append((neg, e.lstrip("-").replace("wholename", "path"), nxt))
            k += 2
        elif e in ("-maxdepth", "-mindepth"):
            try:
                f[e[1:]] = int(nxt)
            except ValueError:
                f["conservative"] = True
            k += 2
        elif e in ("-delete", "-print", "-print0", "-depth", "-xdev", "-mount"):
            k += 1
        elif e in ("-exec", "-execdir", "-ok"):
            cmd = expr[k + 1:k + 4]
            if cmd and os.path.basename(cmd[0]).lower() == "rm" and any(
                    c.startswith("-") and "r" in c.lower() for c in cmd[1:]):
                f["rf"] = True
            while k < len(expr) and expr[k] not in (";", "\\;", "+"):
                k += 1
            k += 1
        else:
            f["conservative"] = True
            k += 1
        neg = False
    for x in _expand_all(start or ["."], ctx):
        _target(x, ctx, excerpt, filt=f)


def _cmd_git(args, ctx, excerpt):
    dirs, i = [], 0
    while i < len(args):
        a = args[i]
        if a == "-C" and i + 1 < len(args):
            dirs.append(args[i + 1])
            i += 2
        elif a == "-c" and i + 1 < len(args):
            i += 2
        elif a.startswith("-"):
            i += 1
        else:
            break
    if i >= len(args) or args[i] != "clean":
        return
    rest = args[i + 1:]
    short = "".join(a[1:] for a in rest if a.startswith("-") and not a.startswith("--"))
    force = "f" in short or "--force" in rest
    dry = "n" in short or "--dry-run" in rest
    if not force or dry:
        return
    ctx.destructive = True
    ctx.recursive = True
    base = ctx.cwd
    for d in dirs:
        base = _abs(_expand(d, ctx)[0], Ctx(base, ctx.env, ctx.dialect))
    sub = Ctx(base, ctx.env, ctx.dialect)
    sub.vars = ctx.vars
    sub.project = ctx.project
    paths = [a for a in rest if not a.startswith("-")]
    for x in _expand_all(paths, sub) or [base]:
        _target(x, sub, excerpt)
    ctx.targets.extend(sub.targets)


def _cmd_python(seg, ctx, excerpt, raw_text):
    args = seg[1:]
    if "-c" in args:
        k = args.index("-c")
        code, argv = (args[k + 1] if k + 1 < len(args) else "").replace(PH, "$"), args[k + 2:]
    else:
        code, argv = raw_text, []
    calls = len(re.findall(r"rmtree\s*\(", code))
    if not calls:
        return
    ctx.destructive = True
    ctx.recursive = True
    found = list(RX_RMTREE.finditer(code))
    if len(found) < calls:
        # `shutil.rmtree(var)` inside a heredoc is code, not shell expansion. A target that comes from the
        # shell (sys.argv) is resolved like rm; anything else only gets a note (blast radius not measured).
        if "sys.argv" in code and argv:
            for x in _expand_all(argv, ctx):
                _target(x, ctx, excerpt)
        else:
            ctx.notes.append("shutil.rmtree with a target computed in code: the blast radius was NOT measured")
    for m in found:
        p = m.group(3)
        if not m.group(1):
            p = p.replace("\\\\", "\\")
        if re.search(r"[{}]", p) or "%" in p:
            raise Deny("unresolved", "shutil.rmtree with a formatted path")
        _target(p, ctx, excerpt)


def _analyze_text(text, ctx: Ctx, depth=0):
    if depth > 4:
        raise Deny("unresolved", "too many nested shells")
    toks = _tokens(_strip_heredoc(text) if ctx.dialect == "bash" else text, ctx.dialect)
    previous, prev_sep = None, ""
    for seg, sep in _segments(toks):
        _segment(seg, ctx, text, previous if prev_sep == "|" else None, depth)
        previous, prev_sep = seg, sep


def _segment(seg, ctx, raw_text, previous, depth):
    i, xargs = 0, False
    while i < len(seg):
        t, tl = seg[i], seg[i].lower()
        if tl in KEYWORDS:
            i += 1
        elif ctx.dialect == "bash" and RX_ASSIGN.match(t):
            m = RX_ASSIGN.match(t)
            _assign(m.group(1), m.group(2), ctx)
            i += 1
        elif tl in ("sudo", "command", "builtin", "exec", "nohup", "nice", "stdbuf"):
            i += 1
            while i < len(seg) and seg[i].startswith("-"):
                i += 1
        elif tl == "env":
            i += 1
            while i < len(seg) and (seg[i].startswith("-") or RX_ASSIGN.match(seg[i])):
                m = RX_ASSIGN.match(seg[i])
                if m:
                    _assign(m.group(1), m.group(2), ctx)
                i += 1
        elif tl == "timeout":
            i += 1
            while i < len(seg) and seg[i].startswith("-"):
                i += 1
            i += 1
        elif tl == "xargs":
            xargs = True
            i += 1
            while i < len(seg) and seg[i].startswith("-"):
                i += 2 if seg[i] in ("-I", "-n", "-P", "-L", "-d", "-E", "-s", "-a") else 1
        else:
            break
    seg = seg[i:]
    if not seg:
        return
    cw = os.path.basename(seg[0].replace("\\", "/")).lower()
    if cw.endswith(".exe"):
        cw = cw[:-4]
    args = seg[1:]
    excerpt = " ".join(seg)[:120]
    d = ctx.dialect
    if d == "bash" and cw == "for" and len(seg) >= 3 and seg[2] == "in":
        ctx.vars[seg[1]] = UNRESOLVED
        try:
            vals = []
            for w in seg[3:]:
                for v in _expand(w, ctx):
                    if any(c in v for c in "*?["):
                        vals.extend([_norm(x) for x in glob.glob(_abs(v, ctx))] or [v])
                    else:
                        vals.append(v)
            ctx.vars[seg[1]] = vals or UNRESOLVED
        except Deny:
            pass
        return
    if d == "bash" and cw in ("export", "local", "declare", "typeset", "readonly"):
        for a in args:
            m = RX_ASSIGN.match(a)
            if m:
                _assign(m.group(1), m.group(2), ctx)
        return
    if d == "bash" and cw == "read":
        for a in args:
            if not a.startswith("-"):
                ctx.vars[a] = UNRESOLVED
        return
    if d == "ps":
        m = RX_PS_ASSIGN.match(seg[0]) if len(seg) == 1 else None
        if m:
            _assign(m.group(1), m.group(2), ctx, ps=True)
            return
        if seg[0].startswith("$") and len(seg) >= 3 and seg[1] == "=":
            name = seg[0][1:]
            if name.lower().startswith("env:"):
                ctx.env = dict(ctx.env)
                try:
                    ctx.env[name[4:]] = _expand(seg[2], ctx)[0]
                except Deny:
                    ctx.env[name[4:]] = ""
            else:
                _assign(name, seg[2], ctx, ps=True)
            return
        if seg[0].lower().startswith("$env:") and "=" in seg[0]:
            k, v = seg[0][5:].split("=", 1)
            ctx.env = dict(ctx.env)
            ctx.env[k] = v
            return
    if cw in ("cd", "pushd", "chdir", "set-location", "sl"):
        dest = [a for a in args if not a.startswith("-") or a == "-"]
        try:
            if not dest:
                ctx.cwd = _home(ctx.env)
            elif dest[0] == "-":
                ctx.cwd = None
            else:
                ctx.cwd = _abs(_expand(dest[0], ctx)[0], ctx)
        except Deny:
            ctx.cwd = None
        return
    # nested shells
    if cw in ("bash", "sh", "zsh") and "-c" in args:
        k = args.index("-c")
        if k + 1 < len(args):
            _sub(args[k + 1], "bash", ctx, depth)
        return
    if cw in ("powershell", "pwsh"):
        al = [a.lower() for a in args]
        for k, a in enumerate(al):
            if a in ("-encodedcommand", "-enc", "-e", "-ec") and k + 1 < len(args):
                try:
                    body = base64.b64decode(args[k + 1]).decode("utf-16-le")
                except Exception:
                    ctx.destructive = PREFILTER.search(args[k + 1] or "") is not None
                    return
                return _sub(body, "ps", ctx, depth)
            if a in ("-command", "-c"):
                return _sub(" ".join(args[k + 1:]), "ps", ctx, depth)
        return
    if cw == "cmd":
        al = [a.lower() for a in args]
        for k, a in enumerate(al):
            if a in ("/c", "//c", "/k", "//k"):
                return _sub(" ".join(args[k + 1:]).replace("//", "/") if d == "bash" else " ".join(args[k + 1:]),
                            "cmd", ctx, depth)
        return
    # destructive commands
    if d == "bash":
        if cw == "rm":
            return _cmd_rm_gnu(args, ctx, excerpt, xargs)
    elif d == "ps":
        if cw in ("remove-item", "ri", "rm", "del", "erase", "rd", "rmdir"):
            if any(a.startswith("/") and a.lower().lstrip("/") in ("s", "q") for a in args):
                return _cmd_cmd_rd_del(cw, args, ctx, excerpt)
            return _cmd_remove_item(args, ctx, excerpt, previous)
    elif d == "cmd":
        if cw in ("rd", "rmdir", "del", "erase"):
            return _cmd_cmd_rd_del(cw, args, ctx, excerpt)
    if cw == "find":
        return _cmd_find(args, ctx, excerpt)
    if cw == "git":
        return _cmd_git(args, ctx, excerpt)
    if cw in ("python", "python3", "py", "pythonw"):
        return _cmd_python(seg, ctx, excerpt, raw_text)


def _sub(text, dialect, ctx, depth):
    texts = [text]
    if ctx.dialect == "bash" and "$" in text:      # the outer bash expands `$w` before handing it over
        try:
            texts = _expand(text, ctx)
        except Deny:
            texts = [text]
    old = ctx.dialect
    try:
        for t in texts:
            ctx.dialect = dialect
            _analyze_text(t.replace(PH, "$"), ctx, depth + 1)
    finally:
        ctx.dialect = old


# ───────────────────────────── counting ─────────────────────────────
class _Deadline(Exception):
    pass


class _Count:
    def __init__(self, deadline):
        self.n, self.size, self.sample, self.deadline = 0, 0, [], deadline

    def file(self, path, size):
        if time.time() > self.deadline or self.n >= COUNT_CEILING:
            raise _Deadline()
        self.n += 1
        self.size += size
        if len(self.sample) < 10:
            self.sample.append(_norm(path))

    def tree(self, root):
        stack = [root]
        while stack:
            d = stack.pop()
            try:
                it = list(os.scandir(d))
            except OSError:
                continue
            for e in it:
                try:
                    if e.is_dir(follow_symlinks=False):
                        stack.append(e.path)
                    else:
                        self.file(e.path, e.stat(follow_symlinks=False).st_size)
                except OSError:
                    continue


def _matches(preds, name, path, is_dir, mtime):
    for neg, k, v in preds:
        if k == "name":
            r = fnmatch.fnmatchcase(name, v)
        elif k == "iname":
            r = fnmatch.fnmatch(name.lower(), v.lower())
        elif k in ("path", "ipath"):
            r = fnmatch.fnmatch(path.lower(), v.lower()) or fnmatch.fnmatch(path.lower(), "*/" + v.lower().lstrip("./"))
        elif k == "type":
            r = (v == "d") == is_dir if v in ("f", "d") else True
        elif k in ("mtime", "mmin"):
            try:
                age = (time.time() - mtime) / (86400.0 if k == "mtime" else 60.0)
                x = float(v.lstrip("+-"))
                r = age > x if v.startswith("+") else age < x if v.startswith("-") else int(age) == int(x)
            except ValueError:
                r = True
        else:
            r = True
        if neg:
            r = not r
        if not r:
            return False
    return True


def _count_filtered(a, f, c):
    """find / del /s: the start folder is a container; match entry by entry down to the depth limit."""
    md, mi = f.get("maxdepth"), f.get("mindepth") or 0
    stack = [(a, 1)]
    while stack:
        d, depth = stack.pop()
        try:
            it = list(os.scandir(d))
        except OSError:
            continue
        for e in it:
            try:
                is_dir = e.is_dir(follow_symlinks=False)
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            hit = depth >= mi and (f.get("conservative") or _matches(f["preds"], e.name, _norm(e.path), is_dir,
                                                                      st.st_mtime))
            if hit and is_dir and f.get("rf"):
                c.tree(e.path)                       # -exec rm -rf {}: the whole subtree goes
                continue
            if hit and not is_dir:
                c.file(e.path, st.st_size)
            if is_dir and (md is None or depth < md):
                stack.append((e.path, depth + 1))


def _count(targets, deadline):
    c = _Count(deadline)
    try:
        for a, filt, _ in targets:
            if not os.path.lexists(a):
                continue
            if not os.path.isdir(a) or os.path.islink(a):
                try:
                    c.file(a, os.lstat(a).st_size)
                except OSError:
                    pass
            elif filt is not None:
                _count_filtered(a, filt, c)
            else:
                c.tree(a)
    except _Deadline:
        return c.n, c.size, c.sample, True
    return c.n, c.size, c.sample, False


# ───────────────────────────── verdict ─────────────────────────────
def evaluate(cmd, tool="Bash", cwd=None, env=None):
    """None = does not mass-delete. Otherwise {deny, kind, text, n, mb}."""
    cmd = str(cmd or "")
    if not PREFILTER.search(cmd):
        return None
    env = dict(os.environ) if env is None else env
    ctx = Ctx(cwd or os.getcwd(), env, "ps" if str(tool).lower().startswith("power") else "bash")
    try:
        _analyze_text(cmd, ctx)
    except Deny as e:
        ctx.destructive = True
        return {"deny": True, "kind": e.kind, "text": _deny_text(e.kind, e.text, cmd), "n": None, "mb": None,
                "recursive": ctx.recursive}
    except Exception as e:                       # own bug: deny only if it already knew it was destructive
        if not ctx.destructive:
            return None
        return {"deny": True, "kind": "error", "n": None, "mb": None,
                "text": _deny_text("unresolved", "the guard could not analyze it (%s)" % type(e).__name__, cmd)}
    if not ctx.destructive:
        return None
    max_files, max_mb = _limit(env, "BLAST_RADIUS_MAX_FILES", 200), _limit(env, "BLAST_RADIUS_MAX_MB", 500)
    n, size, sample, stopped = _count(ctx.targets, time.time() + TIME_BUDGET_S)
    mb = size / 1e6
    targets_txt = ", ".join(sorted({a for a, _, _ in ctx.targets}))[:300] or "(nothing exists yet)"
    if stopped and n <= max_files and mb <= max_mb:
        ctx.notes.append("count stopped at %d files after %.1f s (large tree, narrow filter)" % (n, TIME_BUDGET_S))
    if (n > max_files or mb > max_mb) and not CONFIRM.search(cmd):
        lst = "\n".join("   - " + x for x in sample)
        txt = ("BLAST RADIUS: would delete %s%d files (%.1f MB) in %s, above the cap of %d files / %d MB%s.\n"
               "First %d:\n%s\nIf that is really intended, repeat the command with BLAST_OK=1 in front (Bash: "
               "`BLAST_OK=1 rm -rf ...`; PowerShell: `$env:BLAST_OK=1; Remove-Item ...`). Better: delete a "
               "narrower target."
               % (">=" if stopped else "", n, mb, targets_txt, max_files, max_mb,
                  " (count stopped after %.1f s)" % TIME_BUDGET_S if stopped else "", len(sample), lst))
        return {"deny": True, "kind": "size", "text": txt, "n": n, "mb": mb}
    txt = "blast radius: deletes %d files (%.1f MB) in %s" % (n, mb, targets_txt)
    if ctx.notes:
        txt += " - note: " + "; ".join(ctx.notes)
    return {"deny": False, "kind": "note" if ctx.notes else "ok", "n": n, "mb": mb, "text": txt}


def _deny_text(kind, reason, cmd):
    excerpt = cmd.strip().replace("\n", " \\n ")[:160]
    base = "BLAST RADIUS - `%s`\n   %s.\n" % (excerpt, reason)
    if kind == "empty":
        return base + ("   An empty variable turns `rm -rf \"$VAR/\"` into `rm -rf /` (anthropics/claude-code#97660 "
                       "wiped a Windows drive this way). Every Bash/PowerShell call is a NEW shell: a variable "
                       "from a previous call does NOT exist here. Do it right: use a LITERAL absolute path, or set "
                       "the variable on the same line (`D=/path/to/build; rm -rf \"$D\"`).")
    if kind == "zone":
        return base + ("   Recursive deletion is allowed only inside the project tree, the temp folder, inside "
                       ".claude/worktrees/<x>/ and BLAST_RADIUS_ALLOW. Drive root, home, Desktop, project or "
                       "repository root and .git: never. Do it right: a tracked file goes with `git rm`, a worktree "
                       "with `git worktree remove`; anything else, ask the user to delete it.")
    return base + ("   Without knowing the target the blast radius cannot be measured. Do it right: write the target "
                   "as a literal path (no $(...), xargs, $1, or loop variable fed by a command): list first, "
                   "delete after.")


def decide(event: dict):
    """PreToolUse response for one hook event, or None."""
    ti = (event or {}).get("tool_input") or {}
    r = evaluate(ti.get("command"), (event or {}).get("tool_name") or "Bash", (event or {}).get("cwd"))
    if not r:
        return None
    out = {"hookEventName": "PreToolUse"}
    if r["deny"]:
        out.update(permissionDecision="deny", permissionDecisionReason=r["text"])
    elif r["n"] or r["kind"] == "note":
        out["additionalContext"] = r["text"]
    else:
        return None
    return {"hookSpecificOutput": out}


# ───────────────────────────── scan your own history ─────────────────────────────
def _from_transcripts(days):
    conf = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~/.claude")
    limit, seen, cmds = time.time() - days * 86400, set(), []
    for p in glob.glob(os.path.join(conf, "projects", "**", "*.jsonl"), recursive=True):
        if os.path.getmtime(p) < limit:
            continue
        with open(p, encoding="utf-8", errors="replace") as f:
            for ln in f:
                if '"tool_use"' not in ln:
                    continue
                try:
                    o = json.loads(ln)
                except Exception:
                    continue
                for c in (o.get("message") or {}).get("content") or []:
                    if isinstance(c, dict) and c.get("type") == "tool_use" and c.get("name") in ("Bash", "PowerShell"):
                        cmd = (c.get("input") or {}).get("command") or ""
                        if cmd and cmd not in seen:
                            seen.add(cmd)
                            cmds.append({"tool": c["name"], "command": cmd, "cwd": o.get("cwd") or ""})
    return cmds


def scan(cmds):
    t0, hits, denied = time.time(), [], 0
    for c in cmds:
        r = evaluate(c["command"], c.get("tool") or "Bash", c.get("cwd") or None)
        if r:
            hits.append((c, r))
            denied += 1 if r["deny"] else 0
    print("scanned %d unique commands in %.1f s - destructive %d - denied %d"
          % (len(cmds), time.time() - t0, len(hits), denied))
    for c, r in hits:
        why = r["text"].split("\n")[1].strip() if r["deny"] and r["kind"] != "size" else r["text"][:90]
        print("  %s %-10s %s\n       -> %s" % ("DENY" if r["deny"] else "ok  ", r["kind"],
                                              c["command"].replace("\n", " \\n ")[:150], why[:200]))
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--scan" in argv:
        k = argv.index("--scan")
        with open(argv[k + 1], encoding="utf-8") as f:
            return scan(json.load(f))
    if "--scan-transcripts" in argv:
        days = next((int(a.split("=")[1]) for a in argv if a.startswith("--days=")), 7)
        return scan(_from_transcripts(days))
    try:
        res = decide(json.loads(sys.stdin.read() or "{}"))
        if res:
            print(json.dumps(res, ensure_ascii=False))
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
