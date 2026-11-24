"""ports: which ports are free, who holds the rest, and where your registry, pm2 and the machine disagree.

  ports init [--force]                 create ~/.port-checker/config.json and Ports.md (your registry)
  ports ls [--json] [--all] [--urls]   every listening and registered TCP port, one verdict each
  ports open <port>                    open the app on that port in your browser
  ports check <port> [--json]          one port; exit 0 = free, 1 = don't use it
  ports next [pool] [--json]           next safe port in a pool (default: app)
  ports pools [--json]                 pools with their next free port
  ports audit [--json] [--fast]        drift report; exit 1 when anything disagrees
  ports claim <port> --pool P --name N --project X [--cmd C] [--kind K] [--write]
  ports retire <port> [--write]        mark rows retired (ports are never reused)
  ports adopt [--write]                register everything listening now that has no row (first run)
  ports serve [--port 8801]            read-only dashboard on 127.0.0.1

claim/retire only print a diff unless --write is given. Exit codes: 2 port taken, 3 Ports.md changed
while we worked, 4 bad request.
"""
import argparse
import json
import sys

from . import audit, model, registry, writer

MARK = {"in-use": "IN USE", "free": "free", "registered-down": "DOWN", "reserved": "reserved",
        "excluded": "excluded", "retired": "retired", "transient": "transient"}


def _out(obj):
    print(json.dumps(obj, indent=2, default=list))


def _owner(r):
    reg = r["registry"][0] if r["registry"] else None
    who = r["pm2"] or (reg["name"] if reg and reg["name"] else (reg["label"] if reg else "")) or r["process"]
    proj = reg["project"] if reg else ""
    return who, proj


def table(rows):
    out = [f"{'PORT':>6}  {'VERDICT':<10} {'BIND':<9} {'PID':>6}  {'OWNER':<38} PROJECT"]
    for r in rows:
        who, proj = _owner(r)
        out.append(f"{r['port']:>6}  {MARK[r['verdict']]:<10} {r['exposure'] or '-':<9} {r['pid'] or '-':>6}  "
                   f"{who[:38]:<38} {proj[:40]}")
    return "\n".join(out)


def explain(r):
    v, p = r["verdict"], r["port"]
    who, proj = _owner(r)
    if v == "free":
        return f"{p} is free: nothing listens, and it is not registered, reserved or blocked by the OS."
    if v == "in-use":
        extra = f" (pm2 {r['pm2']})" if r["pm2"] else ""
        reg = f"; registered to {proj or who}" if r["registry"] else "; NOT in Ports.md"
        return f"{p} is in use by {r['process']} pid {r['pid']}{extra} on {', '.join(r['binds'])}{reg}."
    if v == "excluded":
        return f"{p} is inside a Windows excluded port range: binding to it fails even though nothing listens."
    if v == "retired":
        return f"{p} is retired ({who}); ports are never reused."
    if v == "reserved":
        return f"{p} is reserved for {who} ({proj}); its service is just not running right now."
    if v == "transient":
        return f"{p} is a transient port for {who}; it opens only while that task runs."
    return f"{p} is registered to {who} ({proj}) but nothing listens: the service is down. Still taken."


def main(argv=None):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    ap = argparse.ArgumentParser(prog="ports", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="verb", required=True)
    s = sub.add_parser("init"); s.add_argument("--force", action="store_true")
    s = sub.add_parser("ls"); s.add_argument("--json", action="store_true"); s.add_argument("--all", action="store_true")
    s.add_argument("--urls", action="store_true", help="probe each listener for a web page (adds ~1 s)")
    s = sub.add_parser("open"); s.add_argument("port", type=int)
    s = sub.add_parser("check"); s.add_argument("port", type=int); s.add_argument("--json", action="store_true")
    s = sub.add_parser("next"); s.add_argument("pool", nargs="?", default="app"); s.add_argument("--json", action="store_true")
    s = sub.add_parser("pools"); s.add_argument("--json", action="store_true")
    s = sub.add_parser("audit"); s.add_argument("--json", action="store_true")
    s.add_argument("--fast", action="store_true", help="skip pm2 jlist (no unsaved check)")
    s = sub.add_parser("claim"); s.add_argument("port", type=int)
    for a in ("--pool", "--name", "--project"):
        s.add_argument(a, required=True)
    s.add_argument("--cmd", default=""); s.add_argument("--kind", default=""); s.add_argument("--write", action="store_true")
    s = sub.add_parser("retire"); s.add_argument("port", type=int); s.add_argument("--write", action="store_true")
    s = sub.add_parser("adopt"); s.add_argument("--write", action="store_true")
    s = sub.add_parser("serve"); s.add_argument("--port", type=int, default=8801)
    a = ap.parse_args(argv)

    if a.verb == "serve":
        from . import web
        return web.serve(a.port)
    if a.verb == "init":
        return init(a.force)

    snap = model.collect(live_pm2=(a.verb == "audit" and not a.fast))
    if a.verb == "adopt":
        findings = audit.run(snap)

    if a.verb == "ls":
        rows = snap.rows(include_dynamic=a.all)
        if a.urls:
            from . import probe
            probe.probe_rows(rows)
            if not a.json:
                print(table(rows))
                for r in rows:
                    if r.get("url"):
                        print(f"{r['port']:>6}  {r['url']}  {r['title']}")
                return 0
        if a.json:
            return _out({"took": snap.took, "rows": rows}) or 0
        print(table(rows)); print(f"\n{len(rows)} ports · scanned in {snap.took}s"); return 0

    if a.verb == "open":
        from . import probe
        r = snap.row(a.port)
        res = probe.probe(a.port, r["binds"]) if r["verdict"] == "in-use" else None
        if not res:
            print(f"{a.port}: no web page answers there ({explain(r)})", file=sys.stderr)
            return 1
        import webbrowser
        print(f"opening {res['url']}  {res['title']}")
        webbrowser.open(res["url"])
        return 0

    if a.verb == "check":
        r = snap.row(a.port)
        if a.json:
            _out({**r, "free": r["verdict"] == "free", "explain": explain(r)})
        else:
            print(explain(r))
        return 0 if r["verdict"] == "free" else 1

    if a.verb == "next":
        if a.pool not in snap.cfg["pools"]:
            print(f"unknown pool '{a.pool}'; pools: {', '.join(snap.cfg['pools'])}", file=sys.stderr); return 4
        n = snap.pool_next(a.pool)
        if a.json:
            _out({"pool": a.pool, "next": n})
        else:
            print(n if n else f"pool {a.pool} is full")
        return 0 if n else 1

    if a.verb == "pools":
        p = snap.pools()
        if a.json:
            return _out(p) or 0
        for n, v in p.items():
            print(f"{n:<9} {v['start']}-{v['end']:<6} next {v['next']}   {v.get('note', '')}")
        return 0

    if a.verb == "audit":
        f = audit.run(snap)
        if a.json:
            _out({"findings": f, "live_pm2": snap.live_pm2, "took": snap.took})
        else:
            for x in f:
                print(f"{x['kind']:<22} {str(x['port'] or '-'):>6}  {x['detail']}")
            import shutil
            note = "" if snap.live_pm2 else (" (pm2 not installed)" if not shutil.which("pm2")
                                              else " (fast: pm2 save not checked)")
            print(f"\n{len(f)} finding(s){note} · {snap.took}s" if f else f"clean: Ports.md, pm2 and the machine agree{note} · {snap.took}s")
        return 1 if f else 0

    path, text = registry.read(None, snap.cfg)
    if not text:
        print(f"no registry at {path}: run 'ports init' first", file=sys.stderr)
        return 4
    try:
        if a.verb == "claim":
            new = writer.plan_claim(text, snap, a.port, a.pool, a.name, a.project, a.cmd, a.kind)
        elif a.verb == "adopt":
            new = writer.plan_adopt(text, snap, findings)
        else:
            new = writer.plan_retire(text, a.port)
    except writer.Refused as e:
        print(f"refused: {e}", file=sys.stderr)
        return e.code
    print(writer.diff(text, new, path) or "(no change)")
    if not a.write:
        print("dry run: add --write to apply")
        return 0
    try:
        bak = writer.commit(path, text, new)
    except writer.Refused as e:
        print(f"refused: {e}", file=sys.stderr)
        return e.code
    print(f"written; backup {bak}")
    return 0


TEMPLATE = """# Port Registry

Ports this machine uses, kept by `ports claim` / `ports retire` (or by hand: one row per port).
`ports audit` compares this file with what is really listening.

## Registered

| Port | Name | Project | Command | Status | Added |
|---|---|---|---|---|---|

## Transient

Ports opened only while a task runs.

| Port | What | Started by | Stopped by | Added |
|---|---|---|---|---|

## Reserved

Ports to keep clear even when their service is stopped (databases, other apps).

| Port | Owner | Managed by |
|---|---|---|
"""


def init(force=False):
    import os
    home = registry.home_dir()
    os.makedirs(home, exist_ok=True)
    cfg_path, md = registry.user_config_path(), os.path.join(home, "Ports.md")
    wrote = []
    if force or not os.path.exists(cfg_path):
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump({"_help": "Overrides the packaged defaults; see README. ports_md = your registry file.",
                       "ports_md": md,
                       "pools": {"app": {"start": 8100, "end": 8999, "section": "registered",
                                         "note": "your apps and dev servers"}},
                       "ignore": []}, f, indent=2)
        wrote.append(cfg_path)
    if force or not os.path.exists(md):
        with open(md, "w", encoding="utf-8") as f:
            f.write(TEMPLATE)
        wrote.append(md)
    for w in wrote:
        print(f"created {w}")
    if not wrote:
        print(f"already set up in {home} (use --force to overwrite)")
    print("next: 'ports adopt --write' records what is running now; then 'ports next' for a free port,")
    print("      'ports audit' for changes, 'ports serve' for the dashboard")
    return 0


def run():
    """Console-script entry point."""
    sys.exit(main())


if __name__ == "__main__":
    run()
