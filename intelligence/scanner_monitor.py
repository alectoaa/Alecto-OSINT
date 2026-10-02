"""
intelligence/scanner_monitor.py
---------------------------
Automated monitoring karşılığı — yerel izleme sistemi.

Scanner'lar scanners.json dosyasında saklanır. Her scanner için:
  - Tanım: isim, tip, query, bildirim türü, webhook URL
  - Durum: active/paused, son tarama zamanı, son sonuç hash'i

Bildirim yöntemleri:
  - discord_webhook  → Discord embed mesajı
  - http_webhook     → HTTP POST (JSON)
  - none             → Sadece kayıt

Kullanım:
  monitor = ScannerMonitor()
  await monitor.create_scanner("Kemal Email", "email", "k@example.com", "discord_webhook", "https://discord.com/api/webhooks/...")
  await monitor.run_all_scanners()
"""

import asyncio
import hashlib
import json
import logging
import time
import uuid
from pathlib import Path
from typing import Literal

import aiohttp

logger = logging.getLogger(__name__)

SCANNERS_FILE = Path(__file__).parent.parent / "scanners.json"
WEBHOOK_TIMEOUT = aiohttp.ClientTimeout(total=10)

NotificationType = Literal["discord_webhook", "http_webhook", "none"]
ScannerType = Literal["email", "username", "discord_id", "ip", "domain", "steam_id"]


# ─────────────────────────────────────────────────────────────────────────────
# Veri yükleme / kaydetme
# ─────────────────────────────────────────────────────────────────────────────

def _load() -> dict:
    if SCANNERS_FILE.exists():
        try:
            return json.loads(SCANNERS_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {"scanners": []}
    return {"scanners": []}


def _save(data: dict) -> None:
    SCANNERS_FILE.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _hash_results(results: list[dict]) -> str:
    """Sonuç listesinin hash'i — değişiklik tespiti için."""
    serialized = json.dumps(results, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(serialized.encode()).hexdigest()[:16]


# ─────────────────────────────────────────────────────────────────────────────
# Webhook gönderimi
# ─────────────────────────────────────────────────────────────────────────────

async def _send_discord_webhook(webhook_url: str, scanner: dict, new_results: list[dict]) -> bool:
    """Discord Embed formatında bildirim gönder."""
    count = len(new_results)
    query = scanner.get("query", "?")
    name  = scanner.get("name", "Scanner")

    # Özet alanlar
    fields = []
    for r in new_results[:5]:
        fields.append({
            "name":   f"{r.get('type', '?')} — {r.get('source', '?')}",
            "value":  (r.get("snippet") or r.get("title") or r.get("url") or "-")[:200],
            "inline": False,
        })
    if count > 5:
        fields.append({
            "name":   "...",
            "value":  f"ve {count - 5} sonuç daha",
            "inline": False,
        })

    payload = {
        "embeds": [{
            "title":       f"🔔 Scanner: {name}",
            "description": f"**{query}** için **{count}** yeni sonuç bulundu.",
            "color":       0xEF4444,
            "fields":      fields,
            "footer":      {"text": "Automated Scanner"},
            "timestamp":   _now_iso(),
        }]
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                webhook_url,
                json=payload,
                timeout=WEBHOOK_TIMEOUT,
            ) as resp:
                ok = resp.status in (200, 204)
                if not ok:
                    logger.debug(f"[Scanner] Discord webhook HTTP {resp.status}")
                return ok
    except Exception as e:
        logger.debug(f"[Scanner] Discord webhook hatası: {e}")
        return False


async def _send_http_webhook(webhook_url: str, scanner: dict, new_results: list[dict]) -> bool:
    """HTTP POST (JSON) webhook gönder."""
    payload = {
        "scanner_name":  scanner.get("name"),
        "scanner_id":    scanner.get("uid"),
        "query":         scanner.get("query"),
        "new_results":   new_results,
        "result_count":  len(new_results),
        "timestamp":     _now_iso(),
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                webhook_url,
                json=payload,
                timeout=WEBHOOK_TIMEOUT,
            ) as resp:
                ok = resp.status < 400
                if not ok:
                    logger.debug(f"[Scanner] HTTP webhook {resp.status}")
                return ok
    except Exception as e:
        logger.debug(f"[Scanner] HTTP webhook hatası: {e}")
        return False


async def _notify(scanner: dict, new_results: list[dict]) -> None:
    """Bildirim türüne göre webhook gönder."""
    notif = scanner.get("notification_type", "none")
    url   = scanner.get("webhook_url", "")
    if not url or notif == "none":
        return
    if notif == "discord_webhook":
        await _send_discord_webhook(url, scanner, new_results)
    elif notif == "http_webhook":
        await _send_http_webhook(url, scanner, new_results)


# ─────────────────────────────────────────────────────────────────────────────
# Yardımcı
# ─────────────────────────────────────────────────────────────────────────────

def _now_ts() -> float:
    return time.time()


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(tz=timezone.utc).isoformat()


# ─────────────────────────────────────────────────────────────────────────────
# ScannerMonitor
# ─────────────────────────────────────────────────────────────────────────────

class ScannerMonitor:
    """Automated Scanners — yerel izleme sistemi."""

    # ── CRUD ─────────────────────────────────────────────────────────────

    def create_scanner(
        self,
        name: str,
        scanner_type: ScannerType,
        query: str,
        notification_type: NotificationType = "none",
        webhook_url: str = "",
    ) -> dict:
        """Yeni scanner oluştur ve scanners.json'a kaydet."""
        scanner = {
            "uid":               str(uuid.uuid4()),
            "name":              name,
            "scanner_type":      scanner_type,
            "query":             query,
            "notification_type": notification_type,
            "webhook_url":       webhook_url,
            "status":            "active",
            "created_at":        _now_iso(),
            "last_run":          None,
            "last_result_hash":  None,
            "run_count":         0,
        }
        data = _load()
        data["scanners"].append(scanner)
        _save(data)
        logger.info(f"[ScannerMonitor] Scanner oluşturuldu: {name} ({scanner['uid']})")
        return scanner

    def list_scanners(self) -> list[dict]:
        """Tüm scanner'ları döndür."""
        return _load().get("scanners", [])

    def get_scanner(self, uid: str) -> dict | None:
        """UID ile scanner bul."""
        for s in self.list_scanners():
            if s["uid"] == uid:
                return s
        return None

    def delete_scanner(self, uid: str) -> bool:
        """Scanner'ı sil."""
        data = _load()
        before = len(data["scanners"])
        data["scanners"] = [s for s in data["scanners"] if s["uid"] != uid]
        if len(data["scanners"]) < before:
            _save(data)
            logger.info(f"[ScannerMonitor] Scanner silindi: {uid}")
            return True
        return False

    def pause_scanner(self, uid: str) -> bool:
        """Scanner'ı duraklat."""
        return self._set_status(uid, "paused")

    def resume_scanner(self, uid: str) -> bool:
        """Scanner'ı devam ettir."""
        return self._set_status(uid, "active")

    def _set_status(self, uid: str, status: str) -> bool:
        data = _load()
        for s in data["scanners"]:
            if s["uid"] == uid:
                s["status"] = status
                _save(data)
                return True
        return False

    def _update_scanner(self, uid: str, **kwargs) -> None:
        """Scanner alanlarını güncelle."""
        data = _load()
        for s in data["scanners"]:
            if s["uid"] == uid:
                s.update(kwargs)
                _save(data)
                return

    # ── Tarama ───────────────────────────────────────────────────────────

    async def run_scanner(self, scanner: dict) -> list[dict]:
        """
        Tek bir scanner'ı çalıştır.
        Yeni sonuç varsa bildir ve döndür.
        """
        from intelligence.orchestrator import Orchestrator

        query = scanner.get("query", "")
        uid   = scanner.get("uid", "")
        if not query:
            return []

        logger.info(f"[ScannerMonitor] Çalıştırılıyor: {scanner['name']} → {query!r}")
        orchestrator = Orchestrator()

        try:
            results = await orchestrator.run(query)
        except Exception as e:
            logger.debug(f"[ScannerMonitor] {scanner['name']} hata: {e}")
            results = []

        # Yeni sonuç kontrolü
        new_hash = _hash_results(results)
        old_hash = scanner.get("last_result_hash")
        new_results: list[dict] = []

        if results and new_hash != old_hash:
            new_results = results
            await _notify(scanner, new_results)

        # Meta güncelle
        self._update_scanner(
            uid,
            last_run=_now_iso(),
            last_result_hash=new_hash,
            run_count=scanner.get("run_count", 0) + 1,
        )

        return new_results

    async def run_all_scanners(self) -> dict[str, list[dict]]:
        """
        Aktif tüm scanner'ları paralel çalıştır.
        {uid: new_results} dict'i döndür.
        """
        scanners = [s for s in self.list_scanners() if s.get("status") == "active"]
        if not scanners:
            logger.info("[ScannerMonitor] Aktif scanner yok.")
            return {}

        logger.info(f"[ScannerMonitor] {len(scanners)} scanner çalıştırılıyor...")

        tasks = {
            s["uid"]: asyncio.create_task(self.run_scanner(s), name=s["name"])
            for s in scanners
        }

        results_map: dict[str, list[dict]] = {}
        done_tasks = await asyncio.gather(*tasks.values(), return_exceptions=True)
        for uid, result in zip(tasks.keys(), done_tasks):
            if isinstance(result, list):
                results_map[uid] = result
            else:
                logger.debug(f"[ScannerMonitor] {uid} hata: {result}")
                results_map[uid] = []

        return results_map

    async def trigger_scanner(self, uid: str) -> list[dict]:
        """Belirli bir scanner'ı hemen çalıştır (durum gözetmeksizin)."""
        scanner = self.get_scanner(uid)
        if not scanner:
            return []
        return await self.run_scanner(scanner)
