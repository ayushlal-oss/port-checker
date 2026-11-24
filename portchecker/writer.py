"""Safe edits to Ports.md: dry run by default, backup, atomic replace, refuse if the file changed meanwhile."""
import datetime as dt
import difflib
import hashlib
import os
import re
import shutil

from . import registry

BACKUPS = None  # default: <ports home>/backups, worked out at write time (or $PORTS_BACKUPS)
TODAY = lambda: dt.date.today().isoformat()


class Refused(Exception):
    def __init__(self, msg, code):
        super().__init__(msg)
        self.code = code


def _join(lines, like):
    """Join lines with the original file's line ending (Obsidian/OneDrive files may be CRLF)."""
    nl = "\r\n" if "\r\n" in like else "\n"
    return nl.join(lines) + (nl if like.endswith("\n") else "")


def _digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _table_end(lines, rows, section):
    """Line index after the last data row of `section`'s table (before its '(next free)' row if any).
    An empty table (header and separator only) gets its first row right after the separator."""
    data = [r for r in rows if r["section"] == section and not r["next_free"]]
    if data:
        return max(r["line"] for r in data) + 1
    nf = [r for r in rows if r["section"] == section and r["next_free"]]
    if nf:
        return min(r["line"] for r in nf)
    sec = None
    for i, line in enumerate(lines):
        if line.startswith("## "):
            sec = registry.section_of(line[3:])
        elif sec == section and re.fullmatch(r"\|?(\s*:?-+:?\s*\|)+\s*:?-*:?\s*", line.strip()):
            return i + 1
    raise Refused(f"Ports.md has no '{section}' table (run 'ports init' for a template)", 4)


def plan_claim(text, snap, port, pool, name, project, command="", kind=""):
    """Return the new Ports.md text with `port` claimed. Raises Refused(code 2) if the port is taken."""
    v = snap.row(port)["verdict"]
    if v != "free":
        raise Refused(f"port {port} is not free ({v}); nothing written", 2)
    cfg = snap.cfg["pools"].get(pool)
    if not cfg:
        raise Refused(f"unknown pool '{pool}' (have: {', '.join(snap.cfg['pools'])})", 4)
    if not cfg["start"] <= port <= cfg["end"]:
        raise Refused(f"port {port} is outside pool {pool} ({cfg['start']}-{cfg['end']})", 4)
    lines = text.splitlines()
    rows = registry.parse(text)
    proj = f"[[{project}]]" if project and not project.startswith("[[") else project
    cmd = f"`{command}`" if command else ""
    inserts = []  # (line index, new line)
    # every pm2 service has a row in the Registered table
    reg_label = proj if pool == "app" else f"{proj} {'cockpit' if pool == 'phasedoc' else 'dashboard'}"
    inserts.append((_table_end(lines, rows, "registered"),
                    f"| {port} | {name} | {reg_label} | {cmd} | online | {TODAY()} |"))
    if pool == "phasedoc":
        inserts.append((_table_end(lines, rows, "phasedoc"), f"| {port} | {name} | {proj} | {TODAY()} | online |"))
    elif pool == "robodoc":
        inserts.append((_table_end(lines, rows, "robodoc"), f"| {port} | {name} | {proj} | {kind} | {TODAY()} | online |"))
    for at, line in sorted(inserts, reverse=True):
        lines.insert(at, line)
    new = _join(lines, text)
    return _move_next_free(new, snap, pool, extra_used=port)


def _move_next_free(text, snap, pool, extra_used):
    cfg = snap.cfg["pools"][pool]
    rows = registry.parse(text)
    nf = [r for r in rows if r["next_free"] and r["section"] == cfg["section"]]
    if not nf:
        return text
    used = [p for r in rows if not r["next_free"] for p in registry.single_ports(r) if cfg["start"] <= p <= cfg["end"]]
    nxt = max(used + [extra_used]) + 1
    while nxt <= cfg["end"] and snap.row(nxt)["verdict"] != "free":
        nxt += 1
    lines = text.splitlines()
    for r in nf:
        old = lines[r["line"]]
        first = old.split("|")[1]
        lines[r["line"]] = old.replace(first, f" {nxt} ", 1)
    return _join(lines, text)


def plan_adopt(text, snap, findings):
    """Register every listener the audit calls unregistered, in the Registered table, in one go.
    Meant for the first run: afterwards the audit only reports what changes."""
    ports = sorted({f["port"] for f in findings if f["kind"] in ("unregistered-listener", "pm2-unregistered")
                    and f["port"] and f["port"] in snap.tcp})
    if not ports:
        raise Refused("nothing to adopt: every listener is registered or ignored", 4)
    lines = text.splitlines()
    at = _table_end(lines, registry.parse(text), "registered")
    new = []
    for p in ports:
        r = snap.row(p)
        name = r["pm2"] or r["process"] or "?"
        new.append(f"| {p} | {name} | | | online | {TODAY()} |")
    lines[at:at] = new
    return _join(lines, text)


def plan_retire(text, port):
    rows = [r for r in registry.parse(text) if not r["next_free"] and port in registry.single_ports(r)
            and "status" in r["header"]]
    if not rows:
        raise Refused(f"no Ports.md row with a Status column names port {port}", 4)
    lines = text.splitlines()
    for r in rows:
        c = list(r["cells"])
        c[r["header"].index("status")] = "retired"
        lines[r["line"]] = "| " + " | ".join(c) + " |"
    return _join(lines, text)


def diff(old, new, path):
    return "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True), path, path + " (new)"))


def commit(path, old, new):
    """Write `new` over `path` only if the file still holds `old`. Backup first, then atomic replace."""
    with open(path, encoding="utf-8", newline="") as f:
        now = f.read()
    if _digest(now) != _digest(old):
        raise Refused(f"{path} changed since it was read (OneDrive sync or another edit); nothing written", 3)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    bdir = BACKUPS or os.environ.get("PORTS_BACKUPS") or os.path.join(registry.home_dir(), "backups")
    os.makedirs(bdir, exist_ok=True)
    bak = os.path.join(bdir, f"{os.path.basename(path)}.bak-{stamp}")
    shutil.copy2(path, bak)
    tmp = f"{path}.tmp-{os.getpid()}"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        f.write(new)
    os.replace(tmp, path)
    return bak
