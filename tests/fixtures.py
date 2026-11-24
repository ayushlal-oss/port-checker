"""Small, stable stand-ins for netstat, the process table, netsh, pm2 and Ports.md."""
from portchecker import model, registry

PORTS_MD = """---
type: registry
updated: 2026-11-24
---
# Port Registry

## Registered (pm2)

| Port | pm2 name | Project | Command | Status | Added |
|---|---|---|---|---|---|
| 6789 | phasedoc-a | [[A]] cockpit | `pm2 start x` | online | 2026-09-29 |
| 8791 | app-a | [[A]] | `pm2 start y` | online | 2026-10-01 |
| 8792 | app-b | [[B]] | `pm2 start z` | online | 2026-10-02 |
| 8793 | app-old | [[Old]] | `pm2 start q` | retired | 2026-10-03 |

## Phasedoc cockpits (6789 +1 per phasedoc)

| Port | pm2 name | Arc / project | Started | Status |
|---|---|---|---|---|
| 6789 | phasedoc-a | [[A]] | 2026-09-29 | online |
| 6790 | (next free) | | | |

## robodoc dashboards (7801 +, next free port)

| Port | pm2 name | Tracker | Kind | Started | Status |
|---|---|---|---|---|---|
| 7801 | robodoc-hub | hub | | 2026-10-30 | online |
| 7802 | (next free) | | | | |

## Transient (not pm2, on purpose)

| Port | What | Started by | Stopped by | Added |
|---|---|---|---|---|
| 9333 | Throwaway Edge | `cdp.py start` | `cdp.py stop` | 2026-10-10 |

## Reserved on this machine (don't use)

| Port | Owner | Managed by |
|---|---|---|
| 1521, 8080 | Oracle XE listener | Windows service |
| 135, 445, 5040, 7680, 49664+ | Windows | OS |

## Projects that declare ports
```dataview
TABLE ports
```
""".replace("\n", "\r\n")

NETSTAT = """
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1564
  TCP    127.0.0.1:6789         0.0.0.0:0              LISTENING       848
  TCP    127.0.0.1:8791         0.0.0.0:0              LISTENING       900
  TCP    0.0.0.0:8792           0.0.0.0:0              LISTENING       950
  TCP    127.0.0.1:7801         0.0.0.0:0              LISTENING       990
  TCP    127.0.0.1:13469        0.0.0.0:0              LISTENING       16912
  TCP    127.0.0.1:5555         0.0.0.0:0              LISTENING       777
  TCP    127.0.0.1:6789         127.0.0.1:52000        ESTABLISHED     848
  TCP    [::]:135               [::]:0                 LISTENING       1564
  TCP    [::1]:8791             [::]:0                 LISTENING       900
  UDP    0.0.0.0:5353           *:*                                    2000
  UDP    [::]:5353              *:*                                    2000
"""

PROCS = {
    1: {"name": "pm2-daemon(node.exe)", "ppid": 0},
    100: {"name": "cmd.exe", "ppid": 1},          # pm2 spawned phasedoc-a via cmd
    848: {"name": "python.exe", "ppid": 100},
    900: {"name": "node.exe", "ppid": 1},          # app-a: pm2 pid is the listener itself
    950: {"name": "node.exe", "ppid": 1},          # app-b: listens on 0.0.0.0 -> exposed
    990: {"name": "pythonw.exe", "ppid": 1},
    1564: {"name": "svchost.exe", "ppid": 1},
    16912: {"name": "StudioMCP.exe", "ppid": 1},
    777: {"name": "mystery.exe", "ppid": 1},
    2000: {"name": "svchost.exe", "ppid": 1},
}

NETSH = """
Protocol tcp Port Exclusion Ranges

Start Port    End Port
----------    --------
     50000       50059     *

* - Administered port exclusions.
"""

CFG = {
    "pools": {
        "phasedoc": {"start": 6789, "end": 6799, "section": "phasedoc"},
        "robodoc": {"start": 7801, "end": 7899, "section": "robodoc"},
        "app": {"start": 8791, "end": 8999, "section": "registered"},
    },
    "dynamic_range": [49152, 65535],
    "ignore": [{"process": "svchost.exe"}, {"process": "StudioMCP.exe"}],
    "loopback_only_sections": ["registered", "phasedoc", "robodoc"],
}

APPS = [
    {"name": "phasedoc-a", "pid": 100, "status": "online", "cwd": "", "port_hint": 6789},
    {"name": "app-a", "pid": 900, "status": "online", "cwd": "", "port_hint": None},
    {"name": "app-b", "pid": 950, "status": "online", "cwd": "", "port_hint": None},
    {"name": "robodoc-hub", "pid": 990, "status": "online", "cwd": "", "port_hint": None},
]


def snap(md=PORTS_MD, netstat=NETSTAT, apps=None, saved=None, procs=None, live=True):
    from portchecker import scan
    apps = APPS if apps is None else apps
    return model.Snapshot(scan.parse_netstat(netstat), procs or PROCS, scan.parse_excluded(NETSH), apps,
                          saved if saved is not None else [{"name": a["name"]} for a in apps],
                          registry.parse(md), CFG, live_pm2=live)
