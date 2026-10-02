"""
intelligence/orchestrator.py
------------------------
Search Session mantığını uygulayan orkestratör.

classify_input(query) — email / username / discord_id / ip / domain / steam_id tespiti
stream_run(query)     — async generator, tamamlanan servisler anında yield
run(query)            — toplu sonuç (geriye dönük uyumluluk)

Input tipine göre servis haritası:
  EMAIL      → authorized breach metadata
  DOMAIN     → verified-domain breach metadata
  USERNAME   → platform_scan + gaming_lookup
  DISCORD_ID → discord_full
  IP         → ip_geo
  STEAM_ID   → steam_profile (17 haneli sayı)
"""

import asyncio
import logging
import re
from typing import AsyncGenerator

import aiohttp

from surface_scanner.scanner   import SurfaceScanner
from intelligence.breach_engine     import BreachEngine
from intelligence.osint_lookups     import (
    OsintLookups,
    ip_geolocation,
    steam_profile,
    subdomain_finder,
)
from data_processor.processor  import DataProcessor

logger = logging.getLogger(__name__)

# ── Sabitler ──────────────────────────────────────────────────────────────


# ─────────────────────────────────────────────────────────────────────────────
# Input Classifier
# ─────────────────────────────────────────────────────────────────────────────

def classify_input(query: str) -> str:
    """
    Search Session'daki classify mantığı.
    Öncelik sırası: STEAM_ID > DISCORD_ID > EMAIL > IP > DOMAIN > USERNAME
    """
    q = query.strip()

    # Steam ID — 17 haneli sayı (76561... ile başlar)
    if re.match(r'^7656\d{13}$', q):
        return "STEAM_ID"

    # Genel 17-19 haneli sayı → Discord Snowflake
    if re.match(r'^\d{17,19}$', q):
        return "DISCORD_ID"

    # Email
    if re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', q):
        return "EMAIL"

    # URL → domain çıkar
    if re.match(r'^https?://', q):
        return "URL"

    # IPv4
    if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', q):
        return "IP"

    # Domain (en az bir nokta içeren, geçerli TLD)
    if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$', q):
        return "DOMAIN"

    # Varsayılan
    return "USERNAME"


# ─────────────────────────────────────────────────────────────────────────────
# Servis coroutine fabrikası
# ─────────────────────────────────────────────────────────────────────────────

def _build_tasks(
    query: str,
    input_type: str,
    breach: BreachEngine,
    surface: SurfaceScanner,
    lookups: OsintLookups,
) -> list[tuple[str, object]]:
    """
    Input tipine göre (isim, coroutine) çiftlerini döner.
    Her tip için configured service servis haritasına birebir uygun.
    """
    tasks: list[tuple[str, object]] = []

    # ── EMAIL ─────────────────────────────────────────────────────────────
    if input_type == "EMAIL":
        # Authorized breach notification sources return catalogue metadata only.
        tasks.append(("breach", breach.search(query, "EMAIL")))

    # ── USERNAME ──────────────────────────────────────────────────────────
    elif input_type == "USERNAME":
        # Platform scan (SurfaceScanner)
        tasks.append(("platform_scan", surface.search(query)))
        # Gaming lookup (Steam, Xbox, Roblox, Minecraft)
        tasks.append(("gaming_lookup", lookups.lookup_username(query)))

    # ── DISCORD_ID ────────────────────────────────────────────────────────
    elif input_type == "DISCORD_ID":
        # Discord full (history + Roblox bağlantısı)
        tasks.append(("discord_full", lookups.lookup_discord_full(query)))

    # ── IP ────────────────────────────────────────────────────────────────
    elif input_type == "IP":
        tasks.append(("ip_geo", _ip_coro(query)))

    # ── DOMAIN ────────────────────────────────────────────────────────────
    elif input_type == "DOMAIN":
        # Domain breach results require a verified HIBP domain API key.
        tasks.append(("breach", breach.search(query, "DOMAIN")))

    # ── STEAM_ID ─────────────────────────────────────────────────────────
    elif input_type == "STEAM_ID":
        tasks.append(("steam_profile", _steam_coro(query)))

    # ── URL / GENERIC ─────────────────────────────────────────────────────
    else:
        tasks.append(("surface", surface.search(query)))

    return tasks


# ─────────────────────────────────────────────────────────────────────────────
# Yardımcı coroutine sarmalayıcılar
# ─────────────────────────────────────────────────────────────────────────────

async def _ip_coro(ip: str) -> list[dict]:
    async with aiohttp.ClientSession() as s:
        result = await ip_geolocation(s, ip)
        return [result] if result else []


async def _subdomain_coro(domain: str) -> list[dict]:
    async with aiohttp.ClientSession() as s:
        return await subdomain_finder(s, domain)


async def _steam_coro(steam_id: str) -> list[dict]:
    async with aiohttp.ClientSession() as s:
        result = await steam_profile(s, steam_id)
        return [result] if result else []


# ─────────────────────────────────────────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

class Orchestrator:
    """
    Search Session mantığını uygular.
    Her servis tamamlandığı anda işlenmiş sonuçları yield eder.
    """

    def __init__(self) -> None:
        self.breach    = BreachEngine()
        self.surface   = SurfaceScanner()
        self.lookups   = OsintLookups()
        self.processor = DataProcessor()

    async def import_snapshot(self, snapshot_path: str, query: str) -> list[dict]:
        """Read a VSCode browser snapshot file and return processed results.
        This is a convenience used when the user shares a browser page snapshot.
        """
        try:
            from intelligence.snapshot_importer import parse_vscode_snapshot_text
        except Exception:
            return []

        try:
            with open(snapshot_path, 'r', encoding='utf-8', errors='ignore') as fh:
                txt = fh.read()
        except Exception:
            return []

        raw = parse_vscode_snapshot_text(txt, query)
        return self.processor.process_raw_results(raw)

    async def stream_run(self, query: str) -> AsyncGenerator[list[dict], None]:
        """
        Async generator — her servis tamamlandığı anda işlenmiş
        sonuç listesini yield eder. Boş listeler yield edilmez.
        Hatalar sessizce logger.debug ile geçilir.
        """
        input_type = classify_input(query)
        logger.info("[Orchestrator] stream_run: input_type=%s", input_type)

        task_defs = _build_tasks(
            query, input_type,
            self.breach, self.surface, self.lookups,
        )

        # Her coroutine'i asyncio.Task'e çevir
        pending: dict[asyncio.Task, str] = {}
        for name, coro in task_defs:
            t = asyncio.create_task(coro, name=name)
            pending[t] = name

        remaining = set(pending.keys())
        while remaining:
            done, remaining = await asyncio.wait(
                remaining, return_when=asyncio.FIRST_COMPLETED
            )
            for task in done:
                name = pending[task]
                try:
                    result = task.result()
                    if isinstance(result, list) and result:
                        clean = self.processor.process_raw_results(result)
                        if clean:
                            logger.info(f"[Orchestrator] {name}: {len(clean)} sonuç")
                            yield clean
                    else:
                        logger.debug(f"[Orchestrator] {name}: 0 sonuç")
                except Exception as exc:
                    logger.debug(f"[Orchestrator] {name} hatası: {exc}")

    async def run(self, query: str) -> list[dict]:
        """Toplu sonuç — geriye dönük uyumluluk."""
        all_results: list[dict] = []
        async for chunk in self.stream_run(query):
            all_results.extend(chunk)
        return all_results
