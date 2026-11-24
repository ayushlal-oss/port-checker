"""Which listeners serve a web page? One GET / per port (short timeout), plus the page <title>.

Results are cached per (port, pid), so a dashboard refresh only probes listeners that are new or restarted.
"""
import html
import http.client
import re
import ssl
from concurrent.futures import ThreadPoolExecutor

SKIP = {135, 139, 445, 5040, 7680}  # Windows RPC/SMB/etc.: never HTTP, don't poke them
TIMEOUT = 0.8
_cache = {}


def host_for(binds):
    """Pick the address to reach a listener from this machine."""
    if not binds or any(b in ("0.0.0.0", "127.0.0.1") for b in binds):
        return "127.0.0.1"
    if any(b in ("::", "::1") for b in binds):
        return "::1"
    return sorted(binds)[0]


def _get(host, port, tls, path="/", hops=2):
    cls = http.client.HTTPSConnection if tls else http.client.HTTPConnection
    kw = {"context": ssl._create_unverified_context()} if tls else {}  # local dev certs are self-signed
    c = cls(host, port, timeout=TIMEOUT, **kw)
    try:
        c.request("GET", path, headers={"User-Agent": "port-checker", "Accept": "text/html"})
        r = c.getresponse()
        body = r.read(65536).decode("utf-8", "replace") if "html" in (r.getheader("Content-Type") or "") else ""
        loc = r.getheader("Location") or ""
        if 300 <= r.status < 400 and loc.startswith("/") and not loc.startswith("//") and hops:
            c.close()  # same-app redirect (e.g. to /login): follow it for the title, keep the root URL
            return r.status, _get(host, port, tls, loc, hops - 1)[1]
        return r.status, body
    finally:
        c.close()


def probe(port, binds=()):
    """-> {"url", "title", "status"} when the port answers HTTP(S), else None."""
    if port in SKIP:
        return None
    host = host_for(binds)
    netloc = f"[{host}]" if ":" in host else host
    for tls in (False, True):
        try:
            status, body = _get(host, port, tls)
        except (OSError, http.client.HTTPException, ssl.SSLError, ValueError):
            continue
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        title = html.unescape(re.sub(r"\s+", " ", m.group(1))).strip()[:120] if m else ""
        return {"url": f"{'https' if tls else 'http'}://{netloc}:{port}/", "title": title, "status": status}
    return None


def probe_rows(rows, workers=16):
    """Add url/title to every in-use row (cached per port+pid)."""
    todo = [r for r in rows if r["verdict"] == "in-use" and (r["port"], r["pid"]) not in _cache]
    with ThreadPoolExecutor(workers) as ex:
        for r, res in zip(todo, ex.map(lambda r: probe(r["port"], r["binds"]), todo)):
            _cache[(r["port"], r["pid"])] = res
    for r in rows:
        res = _cache.get((r["port"], r["pid"])) if r["verdict"] == "in-use" else None
        r["url"], r["title"] = (res["url"], res["title"]) if res else ("", "")
    return rows
