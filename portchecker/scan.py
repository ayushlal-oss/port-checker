"""Live machine: listening sockets, the process table, and (Windows) excluded port ranges.

Backends, chosen by sys.platform:
  Windows  netstat -ano + one PowerShell CIM call + netsh excludedportrange
  Linux    /proc/net/{tcp,tcp6,udp,udp6} + /proc/<pid>/fd + /proc/<pid>/stat (no extra tools)
  macOS    lsof -F + ps
Each listener is {proto, addr, port, pid, family}; pid is 0 when the OS won't say (another user's process).
"""
import ipaddress
import json
import os
import re
import subprocess
import sys

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)  # under pythonw/pm2, never flash a console
PLATFORM = "windows" if sys.platform.startswith("win") else "mac" if sys.platform == "darwin" else "linux"


def run(cmd, timeout=20):
    """Run a command quietly and return stdout ('' on failure or when the tool is missing)."""
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout, creationflags=NO_WINDOW)
        return p.stdout.decode("utf-8", "replace")
    except (OSError, subprocess.TimeoutExpired):
        return ""


def split_addr(s):
    """'127.0.0.1:6789' / '[::1]:6789' / '*:8080' / '*:*' -> (addr, port or None)."""
    addr, _, port = s.rpartition(":")
    addr = addr.strip("[]")
    if addr == "*":
        addr = "0.0.0.0"
    return addr, (int(port) if port.isdigit() else None)


def _row(proto, addr, port, pid):
    return {"proto": proto, "addr": addr, "port": port, "pid": pid, "family": "v6" if ":" in addr else "v4"}


def exposure(addr):
    if addr in ("127.0.0.1", "::1") or addr.startswith("127."):
        return "loopback"
    if addr in ("0.0.0.0", "::"):
        return "all"
    return "lan"


def chain(pid, procs, limit=32):
    """pid, parent, grandparent, ... (stops at unknown pids, cycles from pid reuse, or `limit`)."""
    seen = []
    while pid and pid in procs and pid not in seen and len(seen) < limit:
        seen.append(pid)
        pid = procs[pid]["ppid"]
    return seen


# --- Windows ------------------------------------------------------------------------------
def parse_netstat(text):
    """TCP rows that are listening (foreign port 0: works whatever language Windows prints the
    state in) and all bound UDP rows."""
    out = []
    for line in text.splitlines():
        f = line.split()
        if not f or f[0] not in ("TCP", "UDP"):
            continue
        if f[0] == "TCP":
            if len(f) < 5 or split_addr(f[2])[1] != 0:
                continue
            local, pid = f[1], f[-1]
        else:
            if len(f) < 4:
                continue
            local, pid = f[1], f[-1]
        addr, port = split_addr(local)
        if port is None or not pid.isdigit():
            continue
        out.append(_row(f[0].lower(), addr, port, int(pid)))
    return out


PS_PROCS = ("Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name "
            "| ConvertTo-Json -Compress")


def parse_processes(text):
    try:
        data = json.loads(text) if text.strip() else []
    except json.JSONDecodeError:
        return {}
    if isinstance(data, dict):
        data = [data]
    return {d["ProcessId"]: {"name": d.get("Name") or "?", "ppid": d.get("ParentProcessId") or 0} for d in data}


def parse_excluded(text):
    """netsh excludedportrange output -> [(lo, hi)]."""
    out = []
    for line in text.splitlines():
        m = re.match(r"\s*(\d+)\s+(\d+)\b", line)
        if m:
            out.append((int(m.group(1)), int(m.group(2))))
    return out


# --- Linux --------------------------------------------------------------------------------
def hex_addr(h):
    """/proc/net hex address (host byte order per 32-bit word) -> text address."""
    raw = bytes.fromhex(h)
    if len(raw) == 4:
        return str(ipaddress.IPv4Address(raw[::-1]))
    words = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
    ip = ipaddress.IPv6Address(words)
    return str(ip.ipv4_mapped) if ip.ipv4_mapped else str(ip)


def parse_proc_net(text, proto, inode_pid):
    """One /proc/net/{tcp,tcp6,udp,udp6} file. TCP keeps state 0A (LISTEN); UDP keeps 07 (bound)."""
    want = "0A" if proto == "tcp" else "07"
    out = []
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) < 10 or f[3] != want:
            continue
        a, p = f[1].split(":")
        out.append(_row(proto, hex_addr(a), int(p, 16), inode_pid.get(f[9], 0)))
    return out


def _linux_inodes(root="/proc"):
    m = {}
    for pid in os.listdir(root):
        if not pid.isdigit():
            continue
        try:
            for fd in os.listdir(f"{root}/{pid}/fd"):
                t = os.readlink(f"{root}/{pid}/fd/{fd}")
                if t.startswith("socket:["):
                    m[t[8:-1]] = int(pid)
        except OSError:  # other users' processes, or gone meanwhile
            continue
    return m


def parse_proc_stat(text):
    """'/proc/<pid>/stat' -> (name, ppid). The name sits in parentheses and may contain spaces."""
    l, r = text.index("("), text.rindex(")")
    return text[l + 1:r], int(text[r + 2:].split()[1])


def _linux_listeners(root="/proc"):
    inode_pid, out = _linux_inodes(root), []
    for proto, files in (("tcp", ("tcp", "tcp6")), ("udp", ("udp", "udp6"))):
        for name in files:
            try:
                with open(f"{root}/net/{name}") as f:
                    out += parse_proc_net(f.read(), proto, inode_pid)
            except OSError:
                pass
    return out


def _linux_processes(root="/proc"):
    procs = {}
    for pid in os.listdir(root):
        if pid.isdigit():
            try:
                with open(f"{root}/{pid}/stat") as f:
                    name, ppid = parse_proc_stat(f.read())
                procs[int(pid)] = {"name": name, "ppid": ppid}
            except (OSError, ValueError):
                pass
    return procs


# --- macOS --------------------------------------------------------------------------------
def parse_lsof(text, proto):
    """`lsof -nP -F pn` output: 'p<pid>' then one 'n<addr:port>' per socket."""
    out, pid = [], 0
    for line in text.splitlines():
        if line.startswith("p"):
            pid = int(line[1:]) if line[1:].isdigit() else 0
        elif line.startswith("n") and "->" not in line:
            addr, port = split_addr(line[1:])
            if port is not None:
                out.append(_row(proto, addr, port, pid))
    return out


def parse_ps(text):
    """`ps -axo pid=,ppid=,comm=` -> {pid: {name, ppid}}; comm may be a full path."""
    procs = {}
    for line in text.splitlines():
        f = line.split(None, 2)
        if len(f) == 3 and f[0].isdigit() and f[1].isdigit():
            procs[int(f[0])] = {"name": os.path.basename(f[2].strip()), "ppid": int(f[1])}
    return procs


# --- public API ---------------------------------------------------------------------------
def listeners():
    if PLATFORM == "windows":
        return parse_netstat(run(["netstat", "-ano"]))
    if PLATFORM == "linux":
        return _linux_listeners()
    return (parse_lsof(run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-F", "pn"]), "tcp")
            + parse_lsof(run(["lsof", "-nP", "-iUDP", "-F", "pn"]), "udp"))


def processes():
    if PLATFORM == "windows":
        return parse_processes(run(["powershell", "-NoProfile", "-NonInteractive", "-Command", PS_PROCS]))
    if PLATFORM == "linux":
        return _linux_processes()
    return parse_ps(run(["ps", "-axo", "pid=,ppid=,comm="]))


def excluded():
    if PLATFORM != "windows":
        return []
    return parse_excluded(run(["netsh", "int", "ipv4", "show", "excludedportrange", "protocol=tcp"]))
