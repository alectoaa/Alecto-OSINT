"""
server.py — OSINT Intelligence Engine
Endpoint'ler:
  GET  /                      → HTML arayüz
  GET  /stream?target=        → SSE (gerçek zamanlı sonuçlar)
  GET  /scan?target=          → JSON toplu
  GET  /discord?id=           → Discord profil JSON
  GET  /ip?address=           → IP geolocation JSON
  GET  /domain?q=             → Subdomain JSON
  GET  /scanners              → Scanner listesi
  POST /scanners              → Scanner oluştur
  DELETE /scanners/{uid}      → Scanner sil
  POST /scanners/{uid}/pause  → Duraklat
  POST /scanners/{uid}/resume → Devam et
  POST /scanners/{uid}/trigger → Hemen çalıştır
"""

import asyncio
import json
import logging
import os
import aiohttp
import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

load_dotenv()

from intelligence.orchestrator     import Orchestrator, classify_input
from intelligence.osint_lookups    import OsintLookups, ip_geolocation
from intelligence.scanner_monitor  import ScannerMonitor
from intelligence.breach_catalog import BreachCatalog

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Application setup
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI()
_scanner_monitor = ScannerMonitor()
_breach_catalog = BreachCatalog()


@app.get("/catalog")
async def breach_catalog(q: str = ""):
    return JSONResponse(content=_breach_catalog.search(q))


@app.post("/catalog/refresh")
async def refresh_breach_catalog():
    try:
        indexed = await _breach_catalog.refresh()
    except (aiohttp.ClientError, TimeoutError, ValueError) as exc:
        logger.warning("Breach catalogue refresh failed: %s", type(exc).__name__)
        return JSONResponse(status_code=502, content={"error": "Breach catalogue unavailable"})
    return JSONResponse(content={"indexed": indexed})


# ─────────────────────────────────────────────────────────────────────────────
# SSE helper
# ─────────────────────────────────────────────────────────────────────────────

def _sse(data: str, event: str = "result") -> str:
    return f"event: {event}\ndata: {data}\n\n"


async def _scan_generator(target: str):
    """SSE stream — her servis tamamlandığında JSON chunk gönderir."""
    orchestrator = Orchestrator()
    total = 0
    input_type = classify_input(target)

    try:
        yield _sse(json.dumps({"status": "started", "query": target, "type": input_type}), event="status")

        # Discord ID ise önce profil bilgisini çek ve özel event olarak gönder
        if input_type == "DISCORD_ID":
            from surface_scanner.discord_lookup import lookup_discord_user
            discord_data = await lookup_discord_user(target)
            if discord_data and not discord_data.get("error"):
                yield _sse(json.dumps(discord_data), event="discord_profile")
                # Profil verisini aynı zamanda result olarak da gönder (tablo satırı)
                profile_row = {
                    "target":     target,
                    "type":       "DISCORD_ID",
                    "title":      f"Discord — {discord_data.get('global_name') or discord_data.get('username', '?')}",
                    "url":        f"https://discord.com/users/{target}",
                    "source":     "Discord",
                    "snippet":    (
                        f"👤 {discord_data.get('username','?')} | "
                        f"Oluşturulma: {discord_data.get('created_at','?')} | "
                        f"Rozetler: {', '.join(discord_data.get('badges',[])) or 'Yok'}"
                    ),
                    "avatar_url": discord_data.get("avatar_url", ""),
                    "banner_url": discord_data.get("banner_url"),
                    "_discord":   discord_data,   # detay paneli için tam veri
                }
                yield _sse(json.dumps([profile_row]))
                total += 1
                await asyncio.sleep(0)

        async for chunk in orchestrator.stream_run(target):
            total += len(chunk)
            yield _sse(json.dumps(chunk))
            await asyncio.sleep(0)

    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.error(f"[SSE] {e}")
        yield _sse(json.dumps({"error": str(e)}), event="error")
    finally:
        yield _sse(json.dumps({"status": "done", "total": total}), event="status")


# ─────────────────────────────────────────────────────────────────────────────
# HTML — Alecto dark UI (inline)
# ─────────────────────────────────────────────────────────────────────────────

_HTML_HEAD = r"""<!DOCTYPE html>
<html lang="tr">
<head>
<title>OSINT Intelligence</title>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<!-- Live result cards will be rendered by client JS -->
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0a0a0f;
  --sidebar:#0d0d16;
  --card:#111120;
  --border:#1c1c2e;
  --accent:#ef4444;
  --accent-dim:#ef444422;
  --accent-mid:#ef444444;
  --text:#e2e2e2;
  --muted:#555;
  --green:#22c55e;
  --orange:#f97316;
  --purple:#a855f7;
  --blue:#3b82f6;
  --discord:#5865f2;
  --teal:#14b8a6;
  --yellow:#eab308;
}
html,body{height:100%;overflow:hidden}
body{background:var(--bg);color:var(--text);font-family:'Inter',sans-serif;display:flex;flex-direction:row}

/* ── SIDEBAR ── */
.sidebar{
  width:220px;min-width:220px;height:100vh;background:var(--sidebar);
  border-right:1px solid var(--border);display:flex;flex-direction:column;
  padding:0;overflow:hidden;flex-shrink:0;
}
.sidebar-logo{
  padding:24px 20px 20px;border-bottom:1px solid var(--border);
}
.logo-mark{font-size:1.25rem;font-weight:800;color:#fff;letter-spacing:1px}
.logo-sub{font-size:.62rem;color:var(--muted);letter-spacing:2px;margin-top:2px;text-transform:uppercase}
.sidebar-nav{flex:1;padding:12px 0;overflow-y:auto}
.nav-section{font-size:.58rem;color:var(--muted);letter-spacing:2px;text-transform:uppercase;padding:12px 20px 6px}
.nav-item{
  display:flex;align-items:center;gap:10px;padding:10px 20px;cursor:pointer;
  font-size:.82rem;color:#888;border-left:2px solid transparent;transition:all .15s;
  white-space:nowrap;user-select:none;
}
.nav-item:hover{color:#ccc;background:#ffffff06}
.nav-item.active{color:#fff;border-left-color:var(--accent);background:var(--accent-dim)}
.nav-item .nav-icon{font-size:1rem;width:18px;text-align:center;flex-shrink:0}
.sidebar-footer{padding:14px 20px;border-top:1px solid var(--border);font-size:.65rem;color:var(--muted)}

/* ── MAIN ── */
.main{flex:1;height:100vh;display:flex;flex-direction:column;overflow:hidden}

/* ── TOP BAR ── */
.topbar{
  padding:14px 24px;border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:12px;background:var(--sidebar);flex-shrink:0;
}
.topbar-title{font-size:.75rem;font-weight:700;color:var(--accent);letter-spacing:2px;text-transform:uppercase;margin-right:4px;white-space:nowrap}
.search-wrap{flex:1;position:relative}
.search-wrap input{
  width:100%;padding:10px 16px;background:#0a0a14;border:1px solid var(--border);
  border-radius:8px;color:#fff;font-family:inherit;font-size:.88rem;transition:border-color .2s;
}
.search-wrap input:focus{outline:none;border-color:var(--accent)}
.search-wrap input::placeholder{color:var(--muted)}
.btn-search{
  padding:10px 22px;background:var(--accent);border:none;color:#fff;cursor:pointer;
  border-radius:8px;font-size:.82rem;font-weight:600;letter-spacing:.5px;
  font-family:inherit;transition:background .2s;white-space:nowrap;
}
.btn-search:hover{background:#dc2626}
.btn-search:disabled{background:#333;cursor:not-allowed}
.type-badge{
  font-size:.62rem;font-weight:700;letter-spacing:1.5px;padding:4px 10px;
  border-radius:12px;border:1px solid var(--accent-mid);color:var(--accent);
  text-transform:uppercase;white-space:nowrap;
}

/* ── CONTENT AREA ── */
.content{flex:1;display:flex;flex-direction:column;overflow:hidden;padding:20px 24px}

/* ── STATUS BAR ── */
.statusbar{
  display:flex;align-items:center;gap:12px;margin-bottom:14px;flex-wrap:wrap;flex-shrink:0;
}
.status-text{font-size:.75rem;color:var(--muted);display:flex;align-items:center;gap:6px}
.spinner{width:12px;height:12px;border:2px solid #222;border-top-color:var(--accent);
  border-radius:50%;animation:spin .7s linear infinite;flex-shrink:0}
@keyframes spin{to{transform:rotate(360deg)}}
.counter-pills{display:flex;gap:6px;flex-wrap:wrap;margin-left:auto}
.counter-pill{
  font-size:.65rem;font-weight:600;letter-spacing:1px;padding:3px 10px;
  border-radius:20px;border:1px solid var(--border);color:var(--muted);transition:all .2s;
}
.counter-pill.active{border-color:var(--c,var(--accent));color:var(--c,var(--accent))}
.counter-pill span{font-weight:800;margin-right:3px}

/* ── TABLE / CARD VIEW ── */
.table-wrap{flex:1;overflow:auto;border-radius:10px;border:1px solid var(--border);padding:12px}
.cards-wrap{flex:1;overflow:auto;border-radius:10px;border:1px solid var(--border);padding:12px}
.card-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}
.result-card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:14px;display:flex;flex-direction:column;gap:10px;cursor:pointer;transition:transform .18s ease,box-shadow .18s ease,background .18s ease;overflow:hidden}
.result-card:hover{transform:translateY(-2px);box-shadow:0 18px 50px rgba(0,0,0,.18);background:rgba(255,255,255,.02)}
.result-card .line{font-family:ui-monospace,Menlo,Monaco,monospace;font-size:.82rem;color:#e6e6e6;white-space:pre-wrap;max-height:130px;overflow:hidden}
.result-card .meta{font-size:.72rem;color:var(--muted)}
.table-wrap table{display:none}

/* ── TYPE BADGE ── */
.type-chip{
  display:inline-block;font-size:.58rem;font-weight:700;letter-spacing:1px;
  padding:2px 7px;border-radius:10px;border:1px solid;text-transform:uppercase;
}
.chip-breach  {color:#ef4444;border-color:#ef444444;background:#ef44440d}
.chip-stealer {color:#f97316;border-color:#f9731644;background:#f973160d}
.chip-platform{color:#22c55e;border-color:#22c55e44;background:#22c55e0d}
.chip-osint   {color:#14b8a6;border-color:#14b8a644;background:#14b8a60d}
.chip-dark    {color:#a855f7;border-color:#a855f744;background:#a855f70d}
.chip-discord {color:#5865f2;border-color:#5865f244;background:#5865f20d}
.chip-ip      {color:#eab308;border-color:#eab30844;background:#eab3080d}
.chip-sub     {color:#3b82f6;border-color:#3b82f644;background:#3b82f60d}
.chip-steam   {color:#22c55e;border-color:#22c55e44;background:#22c55e0d}
.chip-default {color:#888;border-color:#33333388;background:#1a1a1a}

/* ── DETAIL PANEL ── */
.detail-panel{
  position:fixed;top:0;right:0;width:420px;height:100vh;background:#0e0e1a;
  border-left:1px solid var(--border);z-index:100;overflow-y:auto;
  transform:translateX(100%);transition:transform .25s ease;padding:24px;
}
.detail-panel.open{transform:translateX(0)}
.detail-close{
  position:absolute;top:16px;right:16px;background:#1a1a2a;border:1px solid var(--border);
  color:#aaa;width:28px;height:28px;border-radius:50%;cursor:pointer;
  font-size:1rem;display:flex;align-items:center;justify-content:center;
}
.detail-close:hover{background:var(--accent);color:#fff}
.detail-type{font-size:.6rem;font-weight:700;letter-spacing:2px;color:var(--accent);text-transform:uppercase;margin-bottom:6px}
.detail-title{font-size:1rem;font-weight:700;color:#fff;margin-bottom:16px;line-height:1.4}
.detail-field{margin-bottom:14px}
.detail-label{font-size:.58rem;font-weight:700;letter-spacing:1.5px;color:var(--muted);text-transform:uppercase;margin-bottom:4px}
.detail-value{
  font-size:.8rem;color:#ccc;background:#13131f;border-radius:7px;
  padding:9px 12px;word-break:break-all;white-space:pre-wrap;line-height:1.5;
}
.detail-value a{color:var(--accent);text-decoration:none}
.detail-value a:hover{text-decoration:underline}
.detail-actions{display:flex;gap:8px;margin-top:20px;flex-wrap:wrap}
.btn-action{
  flex:1;padding:9px 14px;border-radius:7px;border:1px solid var(--border);
  background:transparent;color:#aaa;cursor:pointer;font-size:.75rem;
  font-family:inherit;font-weight:600;transition:all .2s;
}
.btn-action:hover{background:var(--accent);color:#fff;border-color:var(--accent)}
.discord-avatar-big{width:72px;height:72px;border-radius:50%;border:3px solid var(--accent);object-fit:cover;display:block;margin-bottom:12px}
.discord-banner-big{width:100%;height:90px;object-fit:cover;border-radius:8px;margin-bottom:14px;background:#1a1a2a}

/* ── EMPTY STATE ── */
.empty-state{
  flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;
  color:var(--muted);gap:10px;
}
.empty-icon{font-size:2.5rem;opacity:.4}
.empty-text{font-size:.85rem;letter-spacing:.5px}

.chart-panel{
  background:var(--card);border:1px solid var(--border);border-radius:12px;
  padding:14px 16px;margin-bottom:14px;display:flex;flex-direction:column;gap:10px;
}
.chart-header{font-size:.9rem;font-weight:700;color:#fff;letter-spacing:.5px}
.chart-row{display:flex;align-items:center;gap:10px;min-height:28px}
.chart-label{font-size:.78rem;color:#ccc;min-width:90px;white-space:nowrap}
.chart-track{flex:1;height:10px;background:rgba(255,255,255,.06);border-radius:999px;overflow:hidden}
.chart-fill{height:100%;border-radius:999px;transition:width .25s ease}
.chart-value{font-size:.78rem;color:#aaa;min-width:24px;text-align:right}

/* ── SCANNER PANEL ── */
.scanner-grid{display:grid;grid-template-columns:1fr 340px;gap:20px;flex:1;overflow:hidden;min-height:0}
.scanner-list{overflow-y:auto;display:flex;flex-direction:column;gap:10px;padding-right:4px}
.scanner-card{
  background:var(--card);border:1px solid var(--border);border-radius:10px;
  padding:16px 18px;display:flex;align-items:center;gap:14px;transition:border-color .15s;
}
.scanner-card:hover{border-color:#333}
.scanner-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.scanner-dot.active{background:var(--green);box-shadow:0 0 6px var(--green)}
.scanner-dot.paused{background:var(--muted)}
.scanner-info{flex:1;min-width:0}
.scanner-name{font-size:.85rem;font-weight:600;color:#ddd;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.scanner-meta{font-size:.68rem;color:var(--muted);margin-top:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.scanner-acts{display:flex;gap:6px;flex-shrink:0}
.btn-sm{
  padding:5px 11px;border-radius:6px;border:1px solid var(--border);
  background:transparent;color:#888;cursor:pointer;font-size:.68rem;
  font-family:inherit;font-weight:600;transition:all .15s;
}
.btn-sm:hover{background:#1a1a2a;color:#ccc}
.btn-sm.danger:hover{background:#ef44440d;border-color:var(--accent);color:var(--accent)}
.btn-sm.primary:hover{background:var(--accent);border-color:var(--accent);color:#fff}

/* ── SCANNER FORM ── */
.scanner-form{
  background:var(--card);border:1px solid var(--border);border-radius:10px;
  padding:20px;display:flex;flex-direction:column;gap:12px;overflow-y:auto;
}
.form-title{font-size:.78rem;font-weight:700;color:#ddd;letter-spacing:.5px;margin-bottom:4px}
.form-group{display:flex;flex-direction:column;gap:5px}
.form-label{font-size:.62rem;font-weight:600;letter-spacing:1.5px;color:var(--muted);text-transform:uppercase}
.form-input,.form-select{
  padding:9px 12px;background:#0a0a14;border:1px solid var(--border);
  border-radius:7px;color:#ddd;font-family:inherit;font-size:.82rem;transition:border-color .2s;
}
.form-input:focus,.form-select:focus{outline:none;border-color:var(--accent)}
.form-select{appearance:none}
.btn-create{
  padding:10px;background:var(--accent);border:none;color:#fff;cursor:pointer;
  border-radius:7px;font-size:.82rem;font-weight:700;font-family:inherit;
  letter-spacing:.5px;transition:background .2s;margin-top:4px;
}
.btn-create:hover{background:#dc2626}

/* ── PANEL VISIBILITY ── */
.view{display:none;flex-direction:column;flex:1;overflow:hidden;min-height:0}
.view.active{display:flex}

/* ── SCROLLBAR ── */
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:#222;border-radius:4px}
::-webkit-scrollbar-thumb:hover{background:#333}
/* ── LIVE RESULT CARDS ── */
.result-card{
  background:var(--card);border:1px solid var(--border);border-radius:8px;padding:10px;display:flex;gap:10px;align-items:flex-start;cursor:pointer;animation:rowIn .2s ease forwards
}
.result-card .line{font-family:ui-monospace,Menlo,Monaco,monospace;font-size:.82rem;color:#e6e6e6;white-space:pre-wrap}
.result-card .meta{font-size:.72rem;color:var(--muted)}
.card-conf{font-weight:700;padding:4px 8px;border-radius:8px;font-size:.72rem}
.card-conf.high{background:#052e19;color:var(--green);border:1px solid rgba(34,197,94,0.15)}
.card-conf.medium{background:#2b1200;color:var(--orange);border:1px solid rgba(249,115,22,0.12)}
.card-conf.low{background:#1a1a1a;color:#bbb;border:1px solid rgba(255,255,255,0.02)}
</style>
</head>
"""

_HTML_BODY = r"""<body>
<!-- SIDEBAR -->
<div class="sidebar">
  <div class="sidebar-logo">
    <div class="logo-mark">⬡ Alecto</div>
    <div class="logo-sub">Breach Monitor</div>
  </div>
  <div class="sidebar-nav">
    <div class="nav-section">Modüller</div>
    <div class="nav-item active" onclick="switchView('search',this)" id="nav-search">
      <span class="nav-icon">🔍</span> Search
    </div>
    <div class="nav-item" onclick="switchView('breach',this)" id="nav-breach">
      <span class="nav-icon">💥</span> Breach
    </div>
    <div class="nav-item" onclick="switchView('catalog',this)" id="nav-catalog">
      <span class="nav-icon">🗂️</span> İhlal Kataloğu
    </div>
    <div class="nav-item" onclick="switchView('osint',this)" id="nav-osint">
      <span class="nav-icon">👤</span> OSINT
    </div>
    <div class="nav-item" onclick="switchView('scanners',this)" id="nav-scanners">
      <span class="nav-icon">📡</span> Scanners
    </div>
  </div>
  <div class="sidebar-footer">v2.0 · Alecto OSINT</div>
</div>

<!-- MAIN -->
<div class="main">

  <!-- TOP BAR -->
  <div class="topbar">
    <span class="topbar-title">Alecto</span>
    <div class="search-wrap">
      <input id="target" type="text"
        placeholder="E-posta veya sahipliği doğrulanmış alan adı"
        onkeydown="if(event.key==='Enter')runScan()">
    </div>
    <span class="type-badge" id="type-badge">—</span>
    <button class="btn-search" id="btn-search" onclick="runScan()">Tara</button>
  </div>
  <div style="padding:7px 22px;color:var(--muted);font-size:.72rem">Gizlilik: HIBP anahtarı tanımlıysa e-posta sorgusunda yalnızca SHA-1 öneki gönderilir. Anahtar yoksa ücretsiz XposedOrNot kontrolüne tam e-posta gönderilir.</div>

  <!-- CONTENT -->
  <div class="content">

    <!-- LIVE CARDS -->
    <div id="live-cards" style="display:flex;flex-direction:column;gap:10px;margin-bottom:14px;max-height:220px;overflow:auto"></div>

    <!-- STATUS -->
    <div class="statusbar" id="statusbar" style="display:none">
      <div class="status-text" id="status-text"></div>
      <div class="counter-pills" id="counter-pills"></div>
    </div>

    <!-- GRAPH PANEL -->
    <div class="chart-panel" id="graph-panel" style="display:none">
      <div class="chart-header">Sonuç Dağılımı</div>
      <div class="chart-bars" id="chart-bars"></div>
    </div>

    <!-- VIEW: SEARCH -->
    <div class="view active" id="view-search">
      <div class="cards-wrap" id="table-wrap-search">
        <div class="empty-state" id="empty-search">
          <div class="empty-icon">🔍</div>
          <div class="empty-text">Aramak için yukarıya bir hedef girin</div>
        </div>
        <div class="card-grid" id="cards-search"></div>
      </div>
    </div>

    <!-- VIEW: BREACH -->
    <div class="view" id="view-breach">
      <div class="cards-wrap">
        <div class="empty-state" id="empty-breach">
          <div class="empty-icon">💥</div>
          <div class="empty-text">Breach sonucu yok</div>
        </div>
        <div class="card-grid" id="cards-breach"></div>
      </div>
    </div>

    <div class="view" id="view-catalog">
      <div style="display:flex;gap:8px;margin-bottom:12px">
        <input id="catalog-query" type="search" placeholder="İhlal adı veya etkilenen hizmet" style="flex:1;min-width:0;background:#111120;color:#eee;border:1px solid #29293d;border-radius:8px;padding:10px">
        <button class="btn-sm" onclick="loadCatalog()">Ara</button>
        <button class="btn-sm" onclick="refreshCatalog()">Kataloğu güncelle</button>
      </div>
      <div id="catalog-status" class="status-text" style="margin-bottom:8px">Katalog henüz yerel indekse alınmadı.</div>
      <div style="font-size:.75rem;color:var(--muted);margin-bottom:10px">Kaynak: <a href="https://haveibeenpwned.com/" target="_blank" rel="noopener noreferrer" style="color:var(--accent)">Have I Been Pwned</a></div>
      <div id="catalog-results" class="card-grid"></div>
    </div>

    <!-- VIEW: STEALER -->
    <div class="view" id="view-stealer">
      <div class="cards-wrap">
        <div class="empty-state" id="empty-stealer">
          <div class="empty-icon">🦠</div>
          <div class="empty-text">Stealer log yok</div>
        </div>
        <div class="card-grid" id="cards-stealer"></div>
      </div>
    </div>

    <!-- VIEW: OSINT -->
    <div class="view" id="view-osint">
      <div class="cards-wrap">
        <div class="empty-state" id="empty-osint">
          <div class="empty-icon">👤</div>
          <div class="empty-text">OSINT sonucu yok</div>
        </div>
        <div class="card-grid" id="cards-osint"></div>
      </div>
    </div>

    <!-- VIEW: SCANNERS -->
    <div class="view" id="view-scanners">
      <div class="scanner-grid">
        <div class="scanner-list" id="scanner-list">
          <div class="empty-state" id="empty-scanners" style="height:200px">
            <div class="empty-icon">📡</div>
            <div class="empty-text">Henüz scanner yok</div>
          </div>
        </div>
        <div class="scanner-form">
          <div class="form-title">Yeni Scanner Oluştur</div>
          <div class="form-group">
            <div class="form-label">İsim</div>
            <input class="form-input" id="sc-name" placeholder="Benim Scanner'ım">
          </div>
          <div class="form-group">
            <div class="form-label">Tür</div>
            <select class="form-select" id="sc-type">
              <option value="email">Email</option>
              <option value="username">Username</option>
              <option value="discord_id">Discord ID</option>
              <option value="ip">IP</option>
              <option value="domain">Domain</option>
              <option value="steam_id">Steam ID</option>
            </select>
          </div>
          <div class="form-group">
            <div class="form-label">Query</div>
            <input class="form-input" id="sc-query" placeholder="hedef@email.com">
          </div>
          <div class="form-group">
            <div class="form-label">Bildirim</div>
            <select class="form-select" id="sc-notif">
              <option value="none">Yok</option>
              <option value="discord_webhook">Discord Webhook</option>
              <option value="http_webhook">HTTP Webhook</option>
            </select>
          </div>
          <div class="form-group">
            <div class="form-label">Webhook URL</div>
            <input class="form-input" id="sc-webhook" placeholder="https://discord.com/api/webhooks/...">
          </div>
          <button class="btn-create" onclick="createScanner()">+ Scanner Oluştur</button>
        </div>
      </div>
    </div>

    <!-- VIEW: DARK WEB -->
    <div class="view" id="view-dark">
      <div class="cards-wrap">
        <div class="empty-state" id="empty-dark">
          <div class="empty-icon">🧅</div>
          <div class="empty-text">Dark web sonucu yok</div>
        </div>
        <div class="card-grid" id="cards-dark"></div>
      </div>
    </div>

  </div><!-- /content -->
</div><!-- /main -->

<!-- DETAIL PANEL -->
<div class="detail-panel" id="detail-panel">
  <button class="detail-close" onclick="closeDetail()">✕</button>
  <div id="detail-content"></div>
</div>
"""

_HTML_SCRIPT = r"""<script>
// ─────────────────────────────────────────────────────────────────────────
// State
// ─────────────────────────────────────────────────────────────────────────
let allRows    = [];   // {item, cat, rowNum}
let rowCounter = 0;
let es         = null; // EventSource
let currentView = 'search';
let counts = {breach:0, stealer:0, osint:0, dark:0, other:0};

// ─────────────────────────────────────────────────────────────────────────
// Navigation
// ─────────────────────────────────────────────────────────────────────────
function switchView(view, el) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('view-' + view).classList.add('active');
  if (el) el.classList.add('active');
  currentView = view;
  if (view === 'scanners') loadScanners();
  if (view === 'catalog') loadCatalog();
  closeDetail();
}

async function loadCatalog() {
  const query = document.getElementById('catalog-query')?.value || '';
  const status = document.getElementById('catalog-status');
  const container = document.getElementById('catalog-results');
  if (!status || !container) return;
  try {
    const response = await fetch('/catalog?q=' + encodeURIComponent(query));
    const rows = await response.json();
    container.replaceChildren();
    for (const row of rows) {
      const card = document.createElement('article');
      card.className = 'result-card';
      const heading = document.createElement('h3');
      heading.textContent = row.title || row.name;
      const details = document.createElement('p');
      details.textContent = [row.domain, row.breach_date, row.pwn_count == null ? '' : `${Number(row.pwn_count).toLocaleString()} kayıt`, ...(row.data_classes || [])].filter(Boolean).join(' · ');
      card.append(heading, details);
      container.append(card);
    }
    status.textContent = rows.length ? `${rows.length} katalog kaydı` : 'Eşleşme yok. Önce kataloğu güncelleyin.';
  } catch {
    status.textContent = 'Katalog okunamadı.';
  }
}

async function refreshCatalog() {
  const status = document.getElementById('catalog-status');
  status.textContent = 'Resmî ihlal kataloğu indiriliyor…';
  try {
    const response = await fetch('/catalog/refresh', {method:'POST'});
    const data = await response.json();
    if (!response.ok) throw new Error('refresh failed');
    status.textContent = `${data.indexed} katalog kaydı yerel indekse alındı.`;
    await loadCatalog();
  } catch {
    status.textContent = 'Katalog güncellenemedi. Ağ bağlantısını kontrol edip tekrar deneyin.';
  }
}

// ─────────────────────────────────────────────────────────────────────────
// Input type detection
// ─────────────────────────────────────────────────────────────────────────
function detectType(v) {
  v = v.trim();
  if (/^7656\d{13}$/.test(v))                          return 'STEAM_ID';
  if (/^\d{17,19}$/.test(v))                            return 'DISCORD_ID';
  if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v))            return 'EMAIL';
  if (/^https?:\/\//.test(v))                           return 'URL';
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(v))             return 'IP';
  if (/^[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/.test(v)) return 'DOMAIN';
  return 'USERNAME';
}

document.getElementById('target').addEventListener('input', function() {
  const t = this.value.trim();
  document.getElementById('type-badge').textContent = t ? detectType(t) : '—';
});

// ─────────────────────────────────────────────────────────────────────────
// Category detection
// ─────────────────────────────────────────────────────────────────────────
function categorize(item) {
  const src = (item.source || '').toLowerCase();
  const typ = (item.type  || '').toLowerCase();
  if (['breach','paste','email_account'].includes(typ) ||
      ['xposedornot','leakcheck','breachdirectory','breachcheck'].some(k => src.includes(k)))
    return 'breach';
  if (['stealer','dark_index'].includes(typ) ||
      ['stealer','intelx','intelligencex'].some(k => src.includes(k)))
    return 'stealer';
  if (['dark_index'].includes(typ) || src.includes('onion') || src.includes('tor'))
    return 'dark';
  if (['username','roblox','steam','xbox','minecraft','discord_history',
       'ip_info','subdomain','email_account'].includes(typ) ||
      ['steam','roblox','xbox','minecraft','twitch','youtube','reddit','instagram',
       'twitter','github','discord','holehe','platform','ip geolocation','subdomainfinder']
      .some(k => src.includes(k)))
    return 'osint';
  return 'other';
}

// ─────────────────────────────────────────────────────────────────────────
// Chip CSS class
// ─────────────────────────────────────────────────────────────────────────
const CHIP_MAP = {
  breach:'chip-breach', stealer:'chip-stealer', osint:'chip-osint',
  dark:'chip-dark', platform:'chip-platform', other:'chip-default',
  BREACH:'chip-breach', STEALER:'chip-stealer', PASTE:'chip-breach',
  USERNAME:'chip-platform', DISCORD_ID:'chip-discord', DISCORD_HISTORY:'chip-discord',
  IP_INFO:'chip-ip', SUBDOMAIN:'chip-sub', STEAM:'chip-steam',
  ROBLOX:'chip-osint', XBOX:'chip-osint', MINECRAFT:'chip-osint',
  EMAIL_ACCOUNT:'chip-osint', DARK_INDEX:'chip-dark',
};
function chip(label, cls) {
  return `<span class="type-chip ${cls||'chip-default'}">${escapeHtml(label)}</span>`;
}

// ─────────────────────────────────────────────────────────────────────────
// Table row builder
// ─────────────────────────────────────────────────────────────────────────
function buildRow(item, n, tbody) {
  const cat  = categorize(item);
  const typ  = (item.type || 'INFO').toUpperCase();
  const src  = item.source || '?';
  const tgt  = item.target || '-';
  const ttl  = (item.title || '').slice(0, 60);
  const url  = item.url  || '';
  const snip = (item.snippet || '').slice(0, 80);
  const urlShort = url ? (() => { try { return new URL(url).hostname; } catch { return url.slice(0,30); } })() : '-';
  const chipHtml = chip(typ, CHIP_MAP[typ] || CHIP_MAP[cat] || 'chip-default');
  const tr = document.createElement('tr');
  tr.innerHTML = `
    <td class="num">${n}</td>
    <td>${chipHtml}</td>
    <td>${escapeHtml(src)}</td>
    <td title="${escapeHtml(tgt)}">${escapeHtml(tgt.slice(0,28))}</td>
    <td title="${escapeHtml(ttl)}">${escapeHtml(ttl || '-')}</td>
    <td title="${escapeHtml(url)}">${escapeHtml(urlShort)}</td>
    <td title="${escapeHtml(snip)}">${escapeHtml(snip)}</td>`;
  tr.onclick = () => openDetail(item);
  tbody.appendChild(tr);
  return cat;
}

// ─────────────────────────────────────────────────────────────────────────
// Append results to appropriate tables
// ─────────────────────────────────────────────────────────────────────────
function buildCardElement(item, n) {
  const typ = (item.type || 'INFO').toUpperCase();
  const src = item.source || '?';
  const title = item.title || typ;
  const line = item.line || item.snippet || '';
  const url = item.url || '';
  const chipHtml = chip(typ, CHIP_MAP[typ] || CHIP_MAP[categorize(item)] || 'chip-default');

  const card = document.createElement('div');
  card.className = 'result-card';
  card.innerHTML = `
    <div style="flex:1;min-width:0">
      <div style="display:flex;justify-content:space-between;gap:8px;margin-bottom:8px">
        <div style="font-weight:700;color:#fff;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(title)}</div>
        <div style="color:var(--muted);font-size:.78rem">#${n}</div>
      </div>
      <div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:8px">
        ${chipHtml}
        <div class="meta">${escapeHtml(src)}</div>
      </div>
      <div class="line">${escapeHtml(line)}</div>
      <div style="margin-top:10px;display:flex;gap:10px;flex-wrap:wrap;align-items:center">
        ${url ? `<a href="${escapeHtml(url)}" target="_blank" style="color:var(--accent);text-decoration:none">Link</a>` : ''}
        <div class="meta">${escapeHtml(item.target || '-')}</div>
      </div>
    </div>`;
  card.onclick = () => openDetail(item);
  return card;
}

function appendResults(items) {
  const cardsSearch = document.getElementById('cards-search');
  if (!cardsSearch) { console.error('cards-search not found'); return; }
  const cardsBreach = document.getElementById('cards-breach');
  const cardsStealer = document.getElementById('cards-stealer');
  const cardsOsint = document.getElementById('cards-osint');
  const cardsDark = document.getElementById('cards-dark');

  cardsSearch.style.display = 'grid';

  for (const item of items) {
    rowCounter++;
    const n = rowCounter;
    const cat = categorize(item);
    allRows.push({ item, cat, n });
    counts[cat] = (counts[cat] || 0) + 1;

    const card = buildCardElement(item, n);
    cardsSearch.append(card);
    const emptySearch = document.getElementById('empty-search');
    if (emptySearch) emptySearch.style.display = 'none';

    const categoryCards = {
      breach:  cardsBreach,
      stealer: cardsStealer,
      osint:   cardsOsint,
      dark:    cardsDark,
    };
    const emptyStates = {
      breach:  'empty-breach',
      stealer: 'empty-stealer',
      osint:   'empty-osint',
      dark:    'empty-dark',
    };

    if (categoryCards[cat]) {
      const categoryCard = buildCardElement(item, counts[cat]);
      categoryCards[cat].append(categoryCard);
      const emptyState = document.getElementById(emptyStates[cat]);
      if (emptyState) emptyState.style.display = 'none';
    }
    try { appendCard(item); } catch (e) { console.error('card err', e); }
  }
  updateCounters();
  updateGraph();
}

function updateCounters() {
  const pills = document.getElementById('counter-pills');
  const defs = [
    ['breach', '💥 Breach',  '--accent'],
    ['stealer','🦠 Stealer', '--orange'],
    ['osint',  '👤 OSINT',   '--teal'],
    ['dark',   '🧅 Dark',    '--purple'],
  ];
  pills.innerHTML = defs
    .filter(([k]) => counts[k] > 0)
    .map(([k, label, col]) =>
      `<div class="counter-pill active" style="--c:var(${col})"><span>${counts[k]}</span>${label}</div>`
    ).join('');
}
// ─────────────────────────────────────────────────────────────────────────
// Live Result Cards
// ─────────────────────────────────────────────────────────────────────────
function escapeHtml(s){ return String(s||'').replace(/[&<>\"]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

function appendCard(item){
  const container = document.getElementById('live-cards');
  if(!container) return;
  const dataset = item.dataset || item.source || 'Unknown';
  const typ = (item.type||'').toUpperCase();
  const line = item.line || item.snippet || '';
  const lineNo = item.line_number ? `#${item.line_number}` : '';
  const url = item.url || '';
  const conf = (item.confidence || '').toLowerCase();
  const confHtml = conf ? `<span class="card-conf ${conf}">${conf}</span>` : '';

  const card = document.createElement('div');
  card.className = 'result-card';
  card.innerHTML = `
    <div style="flex:1;min-width:0">
      <div style="display:flex;justify-content:space-between;gap:8px;margin-bottom:6px">
        <div style="font-weight:700;color:#fff">${escapeHtml(dataset)} · ${escapeHtml(typ)}</div>
        <div style="color:var(--muted);font-size:.78rem">${escapeHtml(lineNo)}</div>
      </div>
      <div class="line">${escapeHtml(line)}</div>
      <div style="margin-top:8px;display:flex;gap:8px;align-items:center">
        <div class="meta">${escapeHtml(item.source || '-')}</div>
        ${url ? `<a href="${escapeHtml(url)}" target="_blank" style="color:var(--accent);text-decoration:none">Link</a>` : ''}
        <div style="margin-left:auto">${confHtml}</div>
      </div>
    </div>`;
  card.onclick = ()=>openDetail(item);
  container.insertBefore(card, container.firstChild);
  while(container.children.length>60) container.removeChild(container.lastChild);
}

// ─────────────────────────────────────────────────────────────────────────
// Status
// ─────────────────────────────────────────────────────────────────────────
function setStatus(msg, loading=false) {
  document.getElementById('statusbar').style.display = 'flex';
  document.getElementById('status-text').innerHTML = loading
    ? `<div class="spinner"></div>${msg}`
    : msg;
}

// ─────────────────────────────────────────────────────────────────────────
// Reset
// ─────────────────────────────────────────────────────────────────────────
function resetResults() {
  allRows = []; rowCounter = 0;
  counts = {breach:0, stealer:0, osint:0, dark:0, other:0};
  ['search','breach','stealer','osint','dark'].forEach(v => {
    const cards = document.getElementById('cards-' + v);
    if (cards) cards.innerHTML = '';
    const emp = document.getElementById('empty-' + v);
    if (emp) emp.style.display = '';
  });
  document.getElementById('counter-pills').innerHTML = '';
  const graph = document.getElementById('graph-panel');
  if (graph) graph.style.display = 'none';
  const oldBanner = document.getElementById('discord-banner-bar');
  if (oldBanner) oldBanner.remove();
}

function updateGraph() {
  const graph = document.getElementById('graph-panel');
  const bars = document.getElementById('chart-bars');
  if (!graph || !bars) return;
  const data = [
    ['breach', 'Breach', '--accent'],
    ['stealer', 'Stealer', '--orange'],
    ['osint',   'OSINT',   '--teal'],
    ['dark',    'Dark',    '--purple'],
  ];
  const max = Math.max(...data.map(([k]) => counts[k] || 0), 1);
  bars.innerHTML = data.map(([k,label,col]) => {
    const value = counts[k] || 0;
    return `<div class="chart-row"><div class="chart-label">${label}</div>` +
           `<div class="chart-track"><div class="chart-fill" style="width:${Math.round((value/max)*100)}%;background:var(${col})"></div></div>` +
           `<div class="chart-value">${value}</div></div>`;
  }).join('');
  graph.style.display = rowCounter > 0 ? 'flex' : 'none';
}

// ─────────────────────────────────────────────────────────────────────────
// Scan
// ─────────────────────────────────────────────────────────────────────────
function runScan() {
  const query = document.getElementById('target').value.trim();
  if (!query) return;

  const btn = document.getElementById('btn-search');
  btn.disabled = true; btn.textContent = '⏹ Durdur';
  btn.onclick = stopScan;

  resetResults();
  closeDetail();
  if (currentView !== 'search') switchView('search', document.getElementById('nav-search'));
  setStatus('Tarama başlatılıyor…', true);

  if (es) { es.close(); es = null; }
  es = new EventSource('/stream?target=' + encodeURIComponent(query));

  es.addEventListener('result', e => {
    try {
      const items = JSON.parse(e.data);
      if (Array.isArray(items) && items.length) {
        appendResults(items);
        setStatus(`⏳ ${rowCounter} sonuç — taranıyor…`, true);
      }
    } catch(err) {
      console.error('[result] parse hatası:', err, e.data?.slice(0,100));
    }
  });

  es.addEventListener('discord_profile', e => {
    try {
      const d = JSON.parse(e.data);
      if (d && d.found) {
        showDiscordBanner(d);
        setStatus(`✅ Discord profili bulundu — ${d.username || d.id}`, false);
      }
    } catch(err) {
      console.error('[discord_profile] parse hatası:', err, e.data);
    }
  });

  es.addEventListener('status', e => {
    try {
      const d = JSON.parse(e.data);
      if (d.status === 'done') {
        es.close(); es = null;
        btn.disabled = false; btn.textContent = 'Tara'; btn.onclick = runScan;
        if (rowCounter > 0) setStatus(`✅ ${rowCounter} sonuç bulundu`);
        else {
          setStatus('⚠️ Sonuç bulunamadı');
          document.getElementById('empty-search').style.display = '';
        }
      }
    } catch {}
  });

  es.onerror = () => {
    if (es && es.readyState === EventSource.CLOSED) {
      btn.disabled = false; btn.textContent = 'Tara'; btn.onclick = runScan;
      setStatus(`${rowCounter > 0 ? '✅ ' + rowCounter + ' sonuç' : '⚠️ Bağlantı kesildi'}`);
    }
  };
}

function stopScan() {
  if (es) { es.close(); es = null; }
  const btn = document.getElementById('btn-search');
  btn.disabled = false; btn.textContent = 'Tara'; btn.onclick = runScan;
  setStatus(`⏹ Durduruldu — ${rowCounter} sonuç`);
}

// ─────────────────────────────────────────────────────────────────────────
// Discord Banner (üst kısma büyük profil kartı)
// ─────────────────────────────────────────────────────────────────────────
function showDiscordBanner(d) {
  // Varsa eski banner'ı kaldır
  const old = document.getElementById('discord-banner-bar');
  if (old) old.remove();

  const badges = d.badges && d.badges.length
    ? d.badges.map(b => `<span style="font-size:.65rem;padding:2px 8px;border-radius:10px;border:1px solid #5865f244;color:#7289da;background:#5865f20d">${b}</span>`).join('')
    : '';

  const bar = document.createElement('div');
  bar.id = 'discord-banner-bar';
  bar.style.cssText = 'display:flex;align-items:center;gap:14px;padding:12px 16px;background:#0d0d1a;border:1px solid #5865f244;border-radius:10px;margin-bottom:12px;flex-shrink:0;animation:rowIn .3s ease forwards;position:relative';
  bar.innerHTML = `
    <img src="${d.avatar_url}" style="width:52px;height:52px;border-radius:50%;border:2px solid #5865f2;flex-shrink:0;object-fit:cover" onerror="this.src='https://cdn.discordapp.com/embed/avatars/0.png'">
    <div style="flex:1;min-width:0">
      <div style="font-size:.65rem;font-weight:700;letter-spacing:2px;color:#5865f2;text-transform:uppercase;margin-bottom:3px">Discord Profili</div>
      <div style="font-size:1rem;font-weight:700;color:#fff">${d.global_name || d.username}</div>
      <div style="font-size:.75rem;color:#7289da;margin-top:2px">@${d.display || d.username}${d.bot ? ' · 🤖 BOT' : ''}</div>
      <div style="display:flex;gap:5px;flex-wrap:wrap;margin-top:5px">${badges}</div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;font-size:.72rem;color:#aaa;flex-shrink:0">
      <div><span style="color:#555;display:block;font-size:.58rem;letter-spacing:1px;text-transform:uppercase">USER ID</span>${d.id}</div>
      <div><span style="color:#555;display:block;font-size:.58rem;letter-spacing:1px;text-transform:uppercase">OLUŞTURULMA</span>${d.created_at}</div>
    </div>
    <button onclick="this.parentElement.remove()" style="position:absolute;top:8px;right:8px;background:#1a1a2a;border:1px solid #333;color:#888;width:22px;height:22px;border-radius:50%;cursor:pointer;font-size:.75rem">✕</button>`;

  // statusbar'dan sonra, table-wrap'tan önce ekle
  const content = document.getElementById('view-search');
  const tableWrap = document.getElementById('table-wrap-search');
  content.insertBefore(bar, tableWrap);
}

// ─────────────────────────────────────────────────────────────────────────
// Detail Panel
// ─────────────────────────────────────────────────────────────────────────
function openDetail(item) {
  const panel   = document.getElementById('detail-panel');
  const content = document.getElementById('detail-content');
  const typ = (item.type || 'INFO').toUpperCase();
  const src = item.source || '?';
  const url = item.url || '';
  const snip = item.snippet || '';

  // Discord özel detay
  if (typ === 'DISCORD_ID' && item._discord) {
    const d = item._discord;
    const badges = d.badges && d.badges.length
      ? d.badges.map(b => `<span style="font-size:.6rem;padding:2px 7px;border-radius:10px;border:1px solid #5865f244;color:#7289da">${b}</span>`).join('')
      : '<span style="color:#555;font-size:.7rem">Rozet yok</span>';
    content.innerHTML = `
      <div class="detail-type">Discord</div>
      ${d.banner_url ? `<img style="width:100%;height:80px;object-fit:cover;border-radius:8px;margin-bottom:12px" src="${d.banner_url}">` : ''}
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:14px">
        <img class="discord-avatar-big" src="${d.avatar_url}" onerror="this.src='https://cdn.discordapp.com/embed/avatars/0.png'">
        <div>
          <div class="detail-title" style="margin-bottom:3px">${d.global_name || d.username}</div>
          <div style="font-size:.78rem;color:#7289da">@${d.display || d.username}${d.bot ? ' · 🤖 BOT' : ''}</div>
        </div>
      </div>
      <div style="display:flex;flex-wrap:wrap;gap:5px;margin-bottom:14px">${badges}</div>
      ${[
        ['User ID',      d.id],
        ['Username',     d.username],
        ['Global Name',  d.global_name || '-'],
        ['Oluşturulma',  d.created_at],
        ['Bot',          d.bot ? 'Evet' : 'Hayır'],
      ].map(([l,v]) => `<div class="detail-field"><div class="detail-label">${l}</div><div class="detail-value">${v}</div></div>`).join('')}
      <div class="detail-actions">
        <button class="btn-action" onclick="navigator.clipboard.writeText(${JSON.stringify(JSON.stringify(d, null, 2))})">📋 Kopyala</button>
        <button class="btn-action" onclick="window.open('https://discord.com/users/${d.id}','_blank')">🔗 Profil</button>
      </div>`;
    panel.classList.add('open');
    return;
  }

  // Genel detay paneli
  let html = `<div class="detail-type">${escapeHtml(src)}</div>`;
  html += `<div class="detail-title">${escapeHtml(item.title || typ)}</div>`;
  if (item.avatar_url) html += `<img class="discord-avatar-big" src="${item.avatar_url}" alt="" onerror="this.style.display='none'">`;

  const fields = [
    ['Tür',    typ],
    ['Hedef',  escapeHtml(item.target || '-')],
    ['Kaynak', escapeHtml(src)],
    ['URL',    /^https?:\/\//i.test(url) ? `<a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(url)}</a>` : '-'],
    ['Özet',   escapeHtml(snip || '-')],
  ];
  for (const [label, val] of fields) {
    html += `<div class="detail-field">
      <div class="detail-label">${escapeHtml(label)}</div>
      <div class="detail-value">${val}</div>
    </div>`;
  }
  html += `<div class="detail-actions">
    <button class="btn-action" onclick="copyDetail(${JSON.stringify(JSON.stringify(item, null, 2))})">📋 Kopyala</button>
    ${/^https?:\/\//i.test(url) ? `<a class="btn-action" href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">🔗 Aç</a>` : ''}
  </div>`;

  content.innerHTML = html;
  panel.classList.add('open');
}

function closeDetail() {
  document.getElementById('detail-panel').classList.remove('open');
}

function copyDetail(jsonStr) {
  navigator.clipboard.writeText(jsonStr);
}

// ─────────────────────────────────────────────────────────────────────────
// Scanners
// ─────────────────────────────────────────────────────────────────────────
async function loadScanners() {
  const res  = await fetch('/scanners');
  const data = await res.json();
  const list = document.getElementById('scanner-list');
  const emp  = document.getElementById('empty-scanners');
  if (!data.length) { emp.style.display = ''; return; }
  emp.style.display = 'none';
  list.innerHTML = data.map(s => `
    <div class="scanner-card" id="sc-${s.uid}">
      <div class="scanner-dot ${s.status === 'active' ? 'active' : 'paused'}"></div>
      <div class="scanner-info">
        <div class="scanner-name">${s.name}</div>
        <div class="scanner-meta">${s.scanner_type.toUpperCase()} · ${s.query} · Son: ${s.last_run ? s.last_run.slice(0,19) : 'hiç'}</div>
      </div>
      <div class="scanner-acts">
        <button class="btn-sm primary" onclick="triggerScanner('${s.uid}')">▶</button>
        <button class="btn-sm" onclick="toggleScanner('${s.uid}','${s.status}')">${s.status === 'active' ? '⏸' : '▶'}</button>
        <button class="btn-sm danger" onclick="deleteScanner('${s.uid}')">✕</button>
      </div>
    </div>`).join('');
}

async function createScanner() {
  const name  = document.getElementById('sc-name').value.trim();
  const type  = document.getElementById('sc-type').value;
  const query = document.getElementById('sc-query').value.trim();
  const notif = document.getElementById('sc-notif').value;
  const wh    = document.getElementById('sc-webhook').value.trim();
  if (!name || !query) { alert('İsim ve Query zorunludur'); return; }
  await fetch('/scanners', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ name, scanner_type: type, query, notification_type: notif, webhook_url: wh }),
  });
  ['sc-name','sc-query','sc-webhook'].forEach(id => document.getElementById(id).value = '');
  loadScanners();
}

async function deleteScanner(uid) {
  if (!confirm('Silmek istediğinden emin misin?')) return;
  await fetch('/scanners/' + uid, { method: 'DELETE' });
  loadScanners();
}

async function toggleScanner(uid, status) {
  const action = status === 'active' ? 'pause' : 'resume';
  await fetch(`/scanners/${uid}/${action}`, { method: 'POST' });
  loadScanners();
}

async function triggerScanner(uid) {
  const btn = event.target;
  btn.disabled = true; btn.textContent = '…';
  await fetch(`/scanners/${uid}/trigger`, { method: 'POST' });
  btn.disabled = false; btn.textContent = '▶';
  loadScanners();
}
</script>
</body>
</html>
"""

HTML = _HTML_HEAD + _HTML_BODY + _HTML_SCRIPT


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(
        content=HTML,
        headers={"Cache-Control": "no-store, no-cache, must-revalidate"},
    )


@app.get("/stream")
async def stream(target: str):
    """SSE endpoint — sonuçlar chunk chunk gönderilir."""
    return StreamingResponse(
        _scan_generator(target),
        media_type="text/event-stream",
        headers={
            "Cache-Control":      "no-cache",
            "X-Accel-Buffering":  "no",
            "Connection":         "keep-alive",
        },
    )


@app.get("/scan")
async def scan(target: str):
    """JSON toplu — geriye dönük uyumluluk."""
    orchestrator = Orchestrator()
    results = await orchestrator.run(target)
    return JSONResponse(content=results)


@app.get("/discord")
async def discord_lookup(id: str):
    lookups = OsintLookups()
    result  = await lookups.lookup_discord(id)
    return JSONResponse(content=result)


@app.get("/ip")
async def ip_lookup(address: str):
    async with aiohttp.ClientSession() as session:
        result = await ip_geolocation(session, address)
    return JSONResponse(content=result)


@app.get("/domain")
async def domain_lookup(q: str):
    lookups = OsintLookups()
    results = await lookups.lookup_domain(q)
    return JSONResponse(content=results)


# ─────────────────────────────────────────────────────────────────────────────
# Scanner endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/scanners")
async def scanners_list():
    return JSONResponse(content=_scanner_monitor.list_scanners())


@app.post("/scanners")
async def scanners_create(payload: dict):
    scanner = _scanner_monitor.create_scanner(
        name              = payload.get("name", "Unnamed"),
        scanner_type      = payload.get("scanner_type", "username"),
        query             = payload.get("query", ""),
        notification_type = payload.get("notification_type", "none"),
        webhook_url       = payload.get("webhook_url", ""),
    )
    return JSONResponse(content=scanner)


@app.delete("/scanners/{uid}")
async def scanners_delete(uid: str):
    ok = _scanner_monitor.delete_scanner(uid)
    return JSONResponse(content={"ok": ok})


@app.post("/scanners/{uid}/pause")
async def scanners_pause(uid: str):
    ok = _scanner_monitor.pause_scanner(uid)
    return JSONResponse(content={"ok": ok})


@app.post("/scanners/{uid}/resume")
async def scanners_resume(uid: str):
    ok = _scanner_monitor.resume_scanner(uid)
    return JSONResponse(content={"ok": ok})


@app.post("/scanners/{uid}/trigger")
async def scanners_trigger(uid: str):
    results = await _scanner_monitor.trigger_scanner(uid)
    return JSONResponse(content={"results": results, "count": len(results)})

from raw_engine import RawLeakEngine

raw_engine = RawLeakEngine()
ENABLE_RAW_SEARCH = os.getenv("ENABLE_RAW_SEARCH", "false").lower() in {
    "1", "true", "yes", "on",
}

@app.get("/raw-search")
async def raw_search(target: str):
    """
    Yetkili yerel test veri setlerinde ham arama.

    Güvenlik nedeniyle varsayılan olarak devre dışıdır; yalnızca
    ENABLE_RAW_SEARCH=true ile açıkça etkinleştirilir.
    """
    if not ENABLE_RAW_SEARCH:
        return JSONResponse(
            status_code=404,
            content={"error": "Raw search is disabled"},
        )
    matches = raw_engine.search_credential(target)
    return {
        "query": target,
        "total_matches": len(matches),
        "results": matches
    }
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000, reload=False)
