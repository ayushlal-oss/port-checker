"""pm2: apps from the saved dump + pid files (fast) or `pm2 jlist` (live, ~4 s).

Only name, pid, status, cwd and port-like env values are ever kept: pm2 env blocks carry
the whole shell environment, API keys included, and none of it may leave this module.
"""
import json
import os
import shutil

from .scan import run

PM2_HOME = os.environ.get("PM2_HOME") or os.path.join(os.path.expanduser("~"), ".pm2")
PORT_KEYS = ("PORT", "PHASEDOC_PORT")


def _port_hint(env):
    for k in PORT_KEYS:
        v = str((env or {}).get(k, ""))
        if v.isdigit():
            return int(v)
    return None


def slim(name, pid, status, cwd, env):
    return {"name": name, "pid": pid or None, "status": status, "cwd": cwd or "", "port_hint": _port_hint(env)}


def parse_jlist(text):
    """The JSON array in `pm2 jlist` output. pm2 may print '[PM2] ...' lines first, so try each '['."""
    data, dec, i = None, json.JSONDecoder(), text.find("[")
    while i >= 0:
        try:
            cand = dec.raw_decode(text[i:])[0]
            if isinstance(cand, list) and all(isinstance(x, dict) for x in cand):
                data = cand
                break
        except json.JSONDecodeError:
            pass
        i = text.find("[", i + 1)
    if data is None:
        return None
    out = []
    for a in data:
        e = a.get("pm2_env", {})
        out.append(slim(a.get("name"), a.get("pid"), e.get("status", "?"), e.get("pm_cwd") or e.get("cwd"),
                        {**(e.get("env") or {}), **{k: e.get(k) for k in PORT_KEYS if k in e}}))
    return out


def jlist():
    exe = shutil.which("pm2")
    if not exe:
        return None
    return parse_jlist(run([exe, "jlist"], timeout=30))


def parse_dump(text):
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    return [{"name": d.get("name"), "pid_path": d.get("pm_pid_path"), "cwd": d.get("pm_cwd") or d.get("cwd") or "",
             "env": {k: d.get(k) for k in PORT_KEYS if k in d} | {k: (d.get("env") or {}).get(k)
                                                                    for k in PORT_KEYS if k in (d.get("env") or {})}}
            for d in data]


def dump():
    try:
        with open(os.path.join(PM2_HOME, "dump.pm2"), encoding="utf-8") as f:
            return parse_dump(f.read())
    except OSError:
        return []


def from_dump(saved, procs):
    """Fast view: saved apps; status 'online' when the pid file names a live process."""
    out = []
    for d in saved:
        pid = None
        try:
            with open(d["pid_path"], encoding="utf-8") as f:
                pid = int(f.read().strip() or 0) or None
        except (OSError, TypeError, ValueError):
            pass
        status = "online" if pid and pid in procs else "stopped?"
        out.append(slim(d["name"], pid, status, d["cwd"], d["env"]))
    return out


def unsaved(live, saved):
    """Names running now but not in the dump, and names in the dump that pm2 no longer has."""
    ln = {a["name"] for a in live}
    sn = {d["name"] for d in saved}
    return sorted(ln - sn), sorted(sn - ln)
