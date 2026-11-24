"""Read-only dashboard on 127.0.0.1: / (page), /api/ports (everything), /api/check?port=N.

A background thread refreshes one live snapshot (pm2 jlist included) every REFRESH seconds;
requests read that cached snapshot, so the page never waits on pm2.
"""
import datetime as dt
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import audit, model, probe

REFRESH = int(os.environ.get("PORTS_REFRESH", "20"))
_state = {"snap": None, "payload": None, "err": ""}
_lock = threading.Lock()


def build():
    s = model.collect(live_pm2=True)
    payload = {
        "generated": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "took": s.took, "live_pm2": s.live_pm2,
        "rows": probe.probe_rows(s.rows()), "pools": s.pools(), "findings": audit.run(s),
        "excluded": [list(x) for x in s.excluded], "refresh": REFRESH,
    }
    with _lock:
        _state.update(snap=s, payload=json.dumps(payload, default=list).encode("utf-8"), err="")


def loop():
    while True:
        try:
            build()
        except Exception as e:  # keep serving the last good snapshot
            with _lock:
                _state["err"] = repr(e)
        time.sleep(REFRESH)


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            return self.send(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")
        if u.path == "/favicon.ico":
            return self.send(204, b"", "image/x-icon")
        with _lock:
            snap, payload, err = _state["snap"], _state["payload"], _state["err"]
        if snap is None:
            return self.send(503, json.dumps({"error": err or "first scan still running"}).encode(), "application/json")
        if u.path == "/api/ports":
            return self.send(200, payload, "application/json")
        if u.path == "/api/check":
            q = parse_qs(u.query).get("port", [""])[0]
            if not q.isdigit() or not 0 < int(q) < 65536:
                return self.send(400, b'{"error":"port must be 1-65535"}', "application/json")
            from .cli import explain
            r = snap.row(int(q))
            return self.send(200, json.dumps({**r, "free": r["verdict"] == "free", "explain": explain(r)}).encode(),
                             "application/json")
        self.send(404, b'{"error":"not found"}', "application/json")


def serve(port=8801, host="127.0.0.1"):
    threading.Thread(target=loop, daemon=True).start()
    ThreadingHTTPServer((host, port), H).serve_forever()


PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Port Checker</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Urbanist:wght@400;500;600;700&display=swap" rel="stylesheet">
<script>try{var t=localStorage.getItem("ports-theme");if(t)document.documentElement.dataset.theme=t}catch(e){}</script>
<style>
:root{--paper:#f5f4eb;--raised:#ecebe0;--ink:#020202;--muted:#55544d;--accent:#fb8148;--on-block:#020202;
--ok:#1f6b3a;--warn:#8a5a00;--bad:#a1260d;--pill-ok:#8fd19e;--pill-warn:#f5c35b;--pill-bad:#f4a48a;--pill-off:#e2e1d4;color-scheme:light}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--paper:#020202;--raised:#1a1a17;--ink:#f5f4eb;--muted:#bdbbb0;
--on-block:#020202;--pill-ok:#1f6b3a;--pill-warn:#8a5a00;--pill-bad:#7a2410;--pill-off:#3a3935;color-scheme:dark}}
:root[data-theme="dark"]{--paper:#020202;--raised:#1a1a17;--ink:#f5f4eb;--muted:#bdbbb0;--on-block:#020202;
--pill-ok:#1f6b3a;--pill-warn:#8a5a00;--pill-bad:#7a2410;--pill-off:#3a3935;color-scheme:dark}
*{box-sizing:border-box}html,body{margin:0}
body{background:var(--paper);color:var(--ink);font:16px/1.5 Urbanist,system-ui,-apple-system,"Segoe UI",sans-serif}
.wrap{width:80vw;margin:0 auto;padding:24px 0 40px}@media (max-width:960px){.wrap{width:auto;padding:16px}}
header{display:grid;grid-template-columns:1fr auto 1fr;align-items:center;gap:12px;margin-bottom:20px}
h1{margin:0;font-size:22px;font-weight:700}
nav{display:flex;flex-wrap:wrap;gap:6px;justify-content:center}
nav button,.tog{font:inherit;font-size:15px;border:0;border-radius:8px;padding:6px 14px;background:var(--raised);color:var(--ink);cursor:pointer}
nav button[aria-pressed="true"]{background:var(--ink);color:var(--paper)}
.tog{justify-self:end}
@media (max-width:640px){header{grid-template-columns:1fr auto}nav{grid-column:1/-1;grid-row:2}}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:16px}
.card{background:var(--raised);border-radius:16px;padding:16px 18px}
.card.lead{background:var(--accent);color:var(--on-block)}.card.lead .lbl{color:var(--on-block)}
.lbl{font-size:14px;font-weight:600;color:var(--muted)}
.big{font-size:34px;font-weight:700;line-height:1.1;font-family:ui-monospace,Consolas,monospace}.big.word{font-family:inherit}
td[data-k="Bind"],td[data-k="Port"],td[data-k="PID"]{white-space:nowrap;overflow-wrap:normal}
.small{font-size:14px;color:var(--muted)}.card.lead .small{color:var(--on-block)}
.check{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:16px}
.check input{font:inherit;width:9em;padding:6px 10px;border-radius:8px;border:0;background:var(--raised);color:var(--ink)}
.check button{font:inherit;border:0;border-radius:8px;padding:6px 14px;background:var(--ink);color:var(--paper);cursor:pointer}
#ans{flex-basis:100%;font-size:16px}
.find{background:var(--raised);border-radius:16px;padding:12px 18px;margin-bottom:16px}
.find h2,.tbl h2{font-size:16px;margin:0 0 6px}
.find li{margin:4px 0}
.tbl{background:var(--raised);border-radius:16px;padding:12px 8px}
table{width:100%;border-collapse:collapse;font-size:15px}
th{text-align:left;font-size:14px;color:var(--muted);font-weight:600;padding:6px 10px}
td{padding:7px 10px;vertical-align:top;overflow-wrap:anywhere}
tbody tr:nth-child(odd){background:color-mix(in srgb,var(--paper) 55%,transparent)}
.mono{font-family:ui-monospace,Consolas,monospace}
.pill{display:inline-block;border-radius:8px;padding:1px 9px;font-size:14px;font-weight:600;white-space:nowrap}
.v-in-use{background:var(--pill-ok)}.v-free{background:var(--pill-off)}.v-registered-down{background:var(--pill-bad)}
.v-reserved,.v-transient,.v-retired,.v-excluded{background:var(--pill-warn)}
@media (max-width:640px){thead{display:none}table,tbody,tr,td{display:block}tr{padding:8px 6px;border-radius:8px}
td{padding:2px 6px}td[data-k]::before{content:attr(data-k)": ";color:var(--muted);font-size:14px}}
a.app{color:var(--ink);font-weight:600;text-decoration:underline;text-decoration-thickness:2px;text-underline-offset:3px;text-decoration-color:var(--accent)}
a.app:hover{text-decoration-color:var(--ink)}a.app:focus-visible{outline:2px solid var(--ink);outline-offset:2px;border-radius:4px}
.ttl{display:block;font-size:14px;color:var(--muted)}
footer{margin-top:18px;font-size:14px;color:var(--muted)}
@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
</style></head><body><div class="wrap">
<header><h1>Ports</h1>
<nav id="f"><button data-f="all" aria-pressed="true">All</button><button data-f="in-use">In use</button><button data-f="web">Web apps</button>
<button data-f="idle">Not listening</button><button data-f="drift">Drift</button></nav>
<button class="tog" id="tog" aria-label="Toggle light or dark">Theme</button></header>
<section class="cards" id="cards"></section>
<form class="check" id="chk"><label for="cp" class="lbl">Check a port</label><input id="cp" inputmode="numeric" placeholder="e.g. 8802">
<button>Check</button><div id="ans" aria-live="polite"></div></form>
<section class="find" id="find"></section>
<section class="tbl"><h2 id="th">Ports</h2><table><thead><tr><th>Port</th><th>Verdict</th><th>Owner</th><th>Project</th><th>Bind</th><th>PID</th></tr></thead>
<tbody id="rows"></tbody></table></section>
<footer id="foot">Loading…</footer></div>
<script>
const $=s=>document.querySelector(s);
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const LBL={"in-use":"in use","free":"free","registered-down":"down","reserved":"reserved","transient":"transient","retired":"retired","excluded":"excluded"};
let data=null,filter="all",left=0;
try{const f=sessionStorage.getItem("ports-filter");if(f)filter=f}catch(e){}
function owner(r){const g=r.registry[0];return r.pm2||(g&&(g.name||g.label))||r.process||""}
function ownerCell(r){const o=esc(owner(r));if(!r.url)return o;
  return `<a class="app" href="${esc(r.url)}" target="_blank" rel="noopener" title="Open ${esc(r.url)}">${o||esc(r.url)}</a>`+(r.title?`<span class="ttl">${esc(r.title)}</span>`:"")}
function proj(r){const g=r.registry[0];return g?g.project:""}
function render(){
  const d=data,drift=new Set(d.findings.map(f=>f.port));
  const inuse=d.rows.filter(r=>r.verdict==="in-use").length,webn=d.rows.filter(r=>r.url).length;
  const pools=Object.entries(d.pools).map(([n,p])=>`<div class="card"><div class="lbl">Next ${esc(n)} port</div><div class="big">${esc(p.next??"full")}</div><div class="small">pool ${p.start}-${p.end}</div></div>`).join("");
  $("#cards").innerHTML=`<div class="card lead"><div class="lbl">Audit</div><div class="big${d.findings.length?"":" word"}">${d.findings.length?d.findings.length:"Clean"}</div><div class="small">${d.findings.length?"disagreements between Ports.md, pm2 and the machine":"Ports.md, pm2 and the machine agree"}</div></div>
   <div class="card"><div class="lbl">Listening now</div><div class="big">${inuse}</div><div class="small">of ${d.rows.length} known ports · ${webn} web apps</div></div>`+pools;
  $("#find").innerHTML=d.findings.length?`<h2>Findings</h2><ul>${d.findings.map(f=>`<li><span class="pill v-registered-down">${esc(f.kind)}</span> <span class="mono">${esc(f.port??"")}</span> ${esc(f.detail)}</li>`).join("")}</ul>`
    :`<h2>Findings</h2><div class="small">None. ${d.live_pm2?"pm2 save state checked too.":""}</div>`;
  const rows=d.rows.filter(r=>filter==="all"||(filter==="in-use"&&r.verdict==="in-use")||(filter==="web"&&r.url)||(filter==="idle"&&r.verdict!=="in-use")||(filter==="drift"&&drift.has(r.port)));
  $("#th").textContent=`Ports (${rows.length})`;
  $("#rows").innerHTML=rows.map(r=>`<tr><td class="mono" data-k="Port">${r.url?`<a class="app" href="${esc(r.url)}" target="_blank" rel="noopener" aria-label="Open port ${r.port}">${r.port}</a>`:r.port}</td><td data-k="Verdict"><span class="pill v-${r.verdict}">${LBL[r.verdict]}</span></td>
   <td data-k="Owner">${ownerCell(r)}</td><td data-k="Project">${esc(proj(r))}</td><td data-k="Bind">${esc(r.exposure||"-")}</td><td class="mono" data-k="PID">${esc(r.pid??"-")}</td></tr>`).join("")
   ||`<tr><td colspan="6" class="small">Nothing here.</td></tr>`;
  document.querySelectorAll("#f button").forEach(b=>b.setAttribute("aria-pressed",String(b.dataset.f===filter)));
}
async function load(){
  try{const r=await fetch("/api/ports",{cache:"no-store"});if(r.status===503){$("#foot").textContent="First scan running…";setTimeout(load,1500);return}
    data=await r.json();render();left=data.refresh;tick()}catch(e){$("#foot").textContent="Could not reach the server."}
}
let timer=null;
function tick(){clearTimeout(timer);$("#foot").textContent=`Scanned ${data.generated} in ${data.took}s · refresh in ${left}s`;
  if(left--<=0){load();return}timer=setTimeout(tick,1000)}
$("#f").addEventListener("click",e=>{const b=e.target.closest("button");if(!b)return;filter=b.dataset.f;try{sessionStorage.setItem("ports-filter",filter)}catch(x){}if(data)render()});
$("#chk").addEventListener("submit",async e=>{e.preventDefault();const p=$("#cp").value.trim();
  const r=await fetch("/api/check?port="+encodeURIComponent(p));const j=await r.json();$("#ans").textContent=j.explain||j.error});
$("#tog").addEventListener("click",()=>{const root=document.documentElement;const dark=root.dataset.theme?root.dataset.theme==="dark":matchMedia("(prefers-color-scheme: dark)").matches;
  root.dataset.theme=dark?"light":"dark";try{localStorage.setItem("ports-theme",root.dataset.theme)}catch(e){}});
load();
</script></body></html>"""
