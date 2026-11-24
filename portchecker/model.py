"""Merge scan + pm2 + registry into one row per port with a verdict."""
import time
from concurrent.futures import ThreadPoolExecutor

from . import pm, registry, scan

# Verdicts, most binding first. Only "free" means "you may take this port".
IN_USE, EXCLUDED, RETIRED, RESERVED, TRANSIENT, DOWN, FREE = (
    "in-use", "excluded", "retired", "reserved", "transient", "registered-down", "free")
PM2_SECTIONS = ("registered", "phasedoc", "robodoc")


class Snapshot:
    """Everything the commands need. Build with `collect()`, or directly from fixtures in tests."""

    def __init__(self, listeners, procs, excluded, apps, saved, reg_rows, cfg, live_pm2=False, took=0.0):
        self.listeners, self.procs, self.excluded = listeners, procs, excluded
        self.apps, self.saved, self.reg, self.cfg = apps, saved, reg_rows, cfg
        self.live_pm2, self.took = live_pm2, took
        self.by_pid = {a["pid"]: a for a in apps if a.get("pid")}
        self.tcp = {}
        for l in listeners:
            if l["proto"] == "tcp":
                self.tcp.setdefault(l["port"], []).append(l)

    # --- lookups -------------------------------------------------------------------------
    def owner_app(self, pid):
        for p in scan.chain(pid, self.procs):
            if p in self.by_pid:
                return self.by_pid[p]
        return None

    def reg_rows(self, port):
        return [r for r in self.reg if not r["next_free"] and registry.covers(r, port)]

    def is_excluded(self, port):
        return any(lo <= port <= hi for lo, hi in self.excluded)

    def app_ports(self):
        """pm2 app name -> sorted listening TCP ports owned by its process tree."""
        out = {}
        for port, ls in self.tcp.items():
            for l in ls:
                a = self.owner_app(l["pid"])
                if a:
                    out.setdefault(a["name"], set()).add(port)
        return {k: sorted(v) for k, v in out.items()}

    # --- the verdict ---------------------------------------------------------------------
    def row(self, port):
        ls = self.tcp.get(port, [])
        regs = self.reg_rows(port)
        pid = ls[0]["pid"] if ls else None
        app = self.owner_app(pid) if pid else None
        secs = {r["section"] for r in regs}
        if ls:
            v = IN_USE
        elif self.is_excluded(port):
            v = EXCLUDED
        elif any("retired" in r["status"] for r in regs):
            v = RETIRED
        elif "reserved" in secs:
            v = RESERVED
        elif "transient" in secs:
            v = TRANSIENT
        elif regs:
            v = DOWN
        else:
            v = FREE
        return {
            "port": port, "verdict": v, "pid": pid,
            "process": self.procs.get(pid, {}).get("name", "?") if pid else "",
            "binds": sorted({f"{l['addr']}" for l in ls}),
            "exposure": _widest([scan.exposure(l["addr"]) for l in ls]),
            "pm2": app["name"] if app else "", "pm2_status": app["status"] if app else "",
            "registry": [{"section": r["section"], "name": r["name"], "label": r["label"],
                          "project": r["project"], "status": r["status"]} for r in regs],
        }

    def explicit_ports(self):
        """Ports the registry names one by one (open ranges like 49664+ are not expanded)."""
        return {p for r in self.reg if not r["next_free"] for p in registry.single_ports(r)}

    def rows(self, include_dynamic=False):
        """Every listening TCP port plus every explicitly registered port. Listeners in the Windows
        dynamic range (RPC and friends) are left out unless asked for or registered by number."""
        named = self.explicit_ports()
        lo, hi = self.cfg.get("dynamic_range", [49152, 65535])
        ports = set(self.tcp) | named
        if not include_dynamic:
            ports = {p for p in ports if not (lo <= p <= hi) or p in named}
        return [self.row(p) for p in sorted(ports)]

    # --- pools ---------------------------------------------------------------------------
    def pool_next(self, name):
        pool = self.cfg["pools"][name]
        start, end = pool["start"], pool["end"]
        used = [p for p in self.explicit_ports() if start <= p <= end]
        p = max([start - 1] + used) + 1  # never reuse: always above the highest registered port
        while p <= end:
            if self.row(p)["verdict"] == FREE:
                return p
            p += 1
        return None

    def pools(self):
        return {n: {**{k: v for k, v in p.items()}, "next": self.pool_next(n)} for n, p in self.cfg["pools"].items()}


def _widest(xs):
    for x in ("all", "lan", "loopback"):
        if x in xs:
            return x
    return ""


def collect(live_pm2=False, md=None, cfg=None):
    """Read the machine. Fast path (~1-2 s) uses pm2's dump + pid files; live_pm2 adds `pm2 jlist` (~4 s)."""
    t0 = time.time()
    cfg = cfg or registry.load_config()
    with ThreadPoolExecutor(4) as ex:
        f_l = ex.submit(scan.listeners)
        f_p = ex.submit(scan.processes)
        f_x = ex.submit(scan.excluded)
        f_j = ex.submit(pm.jlist) if live_pm2 else None
        listeners, procs, excluded = f_l.result(), f_p.result(), f_x.result()
        live = f_j.result() if f_j else None
    saved = pm.dump()
    apps = live if live is not None else pm.from_dump(saved, procs)
    _, text = registry.read(md, cfg)
    return Snapshot(listeners, procs, excluded, apps, saved, registry.parse(text), cfg,
                    live_pm2=live is not None, took=round(time.time() - t0, 2))
