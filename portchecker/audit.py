"""Drift between Ports.md, pm2 and the live machine (requirement R9)."""
from . import pm, registry
from .model import PM2_SECTIONS


def ignored(snap, port, pid):
    names = {i["process"].lower() for i in snap.cfg.get("ignore", []) if "process" in i}
    ports = {i["port"] for i in snap.cfg.get("ignore", []) if "port" in i}
    lo, hi = snap.cfg.get("dynamic_range", [49152, 65535])
    proc = snap.procs.get(pid, {}).get("name", "").lower()
    return port in ports or proc in names or (lo <= port <= hi and proc in ("", "system"))


def run(snap):
    """-> list of findings {kind, port, name, detail}. Empty list means the three sources agree."""
    f = []
    add = lambda kind, port, name, detail: f.append({"kind": kind, "port": port, "name": name, "detail": detail})
    apps = {a["name"]: a for a in snap.apps}
    app_ports = snap.app_ports()
    # rows whose table has a "pm2 name" column are pm2-managed; generic "Name" tables are not
    pm2_rows = [r for r in snap.reg if r["section"] in PM2_SECTIONS and r["name"] and "pm2 name" in r["header"]]
    reg_names = {r["name"] for r in pm2_rows}
    all_names = {r["name"] for r in snap.reg if r["name"]}

    # 1. registry says online, nothing listens
    for r in snap.reg:
        if r["next_free"] or r["section"] not in PM2_SECTIONS or "online" not in r["status"]:
            continue
        for p in registry.single_ports(r):
            if p not in snap.tcp:
                add("registered-down", p, r["name"], f"Ports.md ({r['section']}) says online; nothing listens on {p}")

    # 2. listening, not in the registry (minus the ignore list)
    for p, ls in sorted(snap.tcp.items()):
        if snap.reg_rows(p):
            continue
        pid = ls[0]["pid"]
        if ignored(snap, p, pid):
            continue
        a = snap.owner_app(pid)
        who = a["name"] if a else snap.procs.get(pid, {}).get("name", "?")
        add("unregistered-listener", p, who, f"{who} (pid {pid}) listens on {', '.join(sorted({l['addr'] for l in ls}))}; no Ports.md row")

    # 3. pm2 apps the registry does not know, or knows under another port, or that are not online
    for name, a in sorted(apps.items()):
        if name not in all_names:
            add("pm2-unregistered", (app_ports.get(name) or [None])[0], name, f"pm2 app {name} ({a['status']}) has no Ports.md row")
            continue
        want = sorted({p for r in snap.reg if r["name"] == name and r["section"] in PM2_SECTIONS
                       for p in registry.single_ports(r)})
        have = app_ports.get(name, [])
        if a["status"] != "online":
            add("pm2-not-online", want[0] if want else None, name, f"pm2 status is {a['status']}")
        elif have and want and not set(want) & set(have):
            add("port-mismatch", have[0], name, f"listens on {have}, Ports.md says {want}")
    for name in sorted(reg_names - set(apps)):
        rows = [r for r in pm2_rows if r["name"] == name]
        if any("retired" in r["status"] for r in rows):
            continue
        port = next((p for r in rows for p in registry.single_ports(r)), None)
        add("pm2-missing", port, name, "in Ports.md but pm2 does not run it")

    # 4. registered pm2 services must be loopback only
    secs = set(snap.cfg.get("loopback_only_sections", PM2_SECTIONS))
    for p, ls in sorted(snap.tcp.items()):
        regs = [r for r in snap.reg_rows(p) if r["section"] in secs]
        wide = sorted({l["addr"] for l in ls if l["addr"] not in ("127.0.0.1", "::1")})
        if regs and wide:
            add("exposed", p, regs[0]["name"], f"listens on {', '.join(wide)}; registered services bind 127.0.0.1")

    # 5. pm2 save forgotten (only knowable from the live list)
    if snap.live_pm2:
        new, gone = pm.unsaved(snap.apps, snap.saved)
        for n in new:
            add("unsaved", None, n, "running but not in dump.pm2: run pm2 save or it won't come back after a reboot")
        for n in gone:
            add("unsaved", None, n, "in dump.pm2 but not running: pm2 resurrect would bring it back; run pm2 save")

    # 6. '(next free)' rows that are out of date
    for pname, pool in snap.cfg["pools"].items():
        for r in snap.reg:
            if r["next_free"] and r["section"] == pool["section"]:
                nxt = snap.pool_next(pname)
                have = registry.single_ports(r)
                if have and have[0] != nxt:
                    add("next-free-stale", have[0], pname, f"'(next free)' row says {have[0]}, the next free {pname} port is {nxt}")
    return f
