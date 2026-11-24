"""The registry: a Ports.md of markdown tables + config (pools, ignore list): packaged defaults overlaid by ~/.port-checker/config.json."""
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULTS = os.path.join(HERE, "defaults.json")

SECTIONS = {"registered": "registered", "phasedoc": "phasedoc", "robodoc": "robodoc",
            "transient": "transient", "reserved": "reserved"}
NAME_COLS = ("pm2 name", "name", "what", "owner")
PROJECT_COLS = ("project", "arc / project", "tracker", "managed by")


def home_dir():
    """Per-user folder (~/.port-checker, or $PORTS_HOME). Read at call time so tests can point it elsewhere."""
    return os.environ.get("PORTS_HOME") or os.path.join(os.path.expanduser("~"), ".port-checker")


def user_config_path():
    return os.environ.get("PORTS_CONFIG") or os.path.join(home_dir(), "config.json")


def _read_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_config(path=None):
    """Packaged defaults, overlaid by the user's config: pools are replaced as a whole when the user
    gives any, ignore lists are added together, every other key is replaced."""
    cfg = _read_json(DEFAULTS)
    p = path or user_config_path()
    if os.path.exists(p):
        user = _read_json(p)
        extra = user.pop("ignore", [])
        cfg.update({k: v for k, v in user.items() if not k.startswith("_")})
        cfg["ignore"] = cfg.get("ignore", []) + extra
    return cfg


def md_path(cfg=None):
    p = os.environ.get("PORTS_MD") or (cfg or {}).get("ports_md") or os.path.join(home_dir(), "Ports.md")
    return os.path.expandvars(os.path.expanduser(p))


def plain(s):
    """Strip [[wiki links]], `code`, **bold** for display."""
    s = re.sub(r"\[\[([^\]|]+)(?:\|([^\]]+))?\]\]", lambda m: m.group(2) or m.group(1), s)
    return s.replace("`", "").replace("**", "").strip()


def parse_port_cell(cell):
    """'6789' / '1521, 8080' / '49664+' -> [(lo, hi)]; [] when no port."""
    out = []
    for tok in cell.split(","):
        tok = tok.strip()
        m = re.fullmatch(r"(\d+)\s*\+", tok)
        if m:
            out.append((int(m.group(1)), 65535))
            continue
        m = re.fullmatch(r"(\d+)\s*[-–]\s*(\d+)", tok)
        if m:
            out.append((int(m.group(1)), int(m.group(2))))
            continue
        if tok.isdigit():
            out.append((int(tok), int(tok)))
    return out


def cells(line):
    return [c.strip() for c in line.strip().strip("|").split("|")]


def section_of(heading):
    h = heading.lower()
    for key, sec in SECTIONS.items():
        if h.startswith(key):
            return sec
    return None


def parse(text):
    """Every table row under a known '## ' section -> dict. Line numbers are 0-based."""
    rows, section, header = [], None, None
    for i, line in enumerate(text.splitlines()):
        if line.startswith("## "):
            section, header = section_of(line[3:]), None
            continue
        if not section or not line.lstrip().startswith("|"):
            header = None if not line.strip() else header
            continue
        c = cells(line)
        if header is None:
            header = [h.lower() for h in c]
            continue
        if all(re.fullmatch(r":?-+:?", x or "-") for x in c):
            continue
        get = lambda names: next((c[header.index(n)] for n in names if n in header and header.index(n) < len(c)), "")
        name = plain(get(NAME_COLS))
        rows.append({
            "section": section, "line": i, "ports": parse_port_cell(c[0]),
            "name": "" if name.startswith("(next free)") else name.split(" ")[0] if section != "reserved" and section != "transient" else name,
            "label": name, "project": plain(get(PROJECT_COLS)), "status": plain(get(("status",))).lower(),
            "next_free": "(next free)" in name, "header": header, "cells": c,
        })
    return rows


def read(path=None, cfg=None):
    """(path, text). A missing registry reads as empty, so the tool works before `ports init`."""
    p = path or md_path(cfg)
    if not os.path.exists(p):
        return p, ""
    with open(p, encoding="utf-8", newline="") as f:  # keep CRLF so writes preserve it
        return p, f.read()


def covers(row, port):
    return any(lo <= port <= hi for lo, hi in row["ports"])


def single_ports(row):
    """Explicit ports only (open-ended ranges like 49664+ are not listed one by one)."""
    out = []
    for lo, hi in row["ports"]:
        if hi - lo <= 64:
            out.extend(range(lo, hi + 1))
    return out
