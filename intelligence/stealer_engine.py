"""
intelligence/stealer_engine.py
--------------------------
Stealer log tespiti — infostealer credential formatını içeren
paste/dump sayfalarını DDG ile bulur ve içerik doğrular.

IntelX taraması breach_engine.py'de zaten yapılıyor, burada tekrar edilmez.
"""

import asyncio
import logging
import re

import aiohttp
from bs4 import BeautifulSoup

try:
    from ddgs import DDGS
except ImportError:
    from duckduckgo_search import DDGS

logger = logging.getLogger(__name__)

HEADERS = {
    "User-Agent":    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Accept":        "text/html,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

# Stealer log formatı — URL:user:pass veya email:pass
STEALER_RE = [
    re.compile(r'https?://\S+\s*[:;|]\s*\S+\s*[:;|]\s*\S{4,}'),
    re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\s*[:;|]\s*\S{4,}'),
    re.compile(r'(?:password|pass|pwd)\s*[:=]\s*\S+', re.IGNORECASE),
]

DORKS = [
    '"{q}" "password" "url" filetype:txt site:pastebin.com',
    '"{q}" stealer credentials site:pastebin.com',
    '"{q}" "redline" OR "raccoon" OR "vidar" credentials',
]


def _has_stealer_format(text: str) -> bool:
    for pat in STEALER_RE:
        if pat.search(text):
            return True
    return False


def _extract(text: str, target: str) -> str | None:
    idx = text.lower().find(target.lower())
    if idx == -1:
        return None
    window = text[max(0, idx - 150): idx + 500]
    if _has_stealer_format(window):
        return window.strip()
    return None


async def _check_url(session: aiohttp.ClientSession, url: str, title: str, target: str) -> dict | None:
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=5),
            headers=HEADERS,
            allow_redirects=True,
            ssl=False,
        ) as resp:
            if resp.status != 200:
                return None
            text = BeautifulSoup(await resp.text(errors="ignore"), "html.parser").get_text("\n", strip=True)
            ctx  = _extract(text, target)
            if ctx:
                return {
                    "target":  target,
                    "type":    "STEALER",
                    "title":   title or url[:50],
                    "url":     url,
                    "source":  "Stealer Log",
                    "snippet": ctx[:400],
                }
    except Exception:
        pass
    return None


class StealerEngine:

    async def search(self, query: str, input_type: str) -> list[dict]:
        if input_type not in ("EMAIL", "USERNAME"):
            return []

        candidates, seen = [], set()
        try:
            with DDGS() as ddgs:
                for dork in DORKS:
                    try:
                        for r in ddgs.text(dork.format(q=query), max_results=5):
                            u = r.get("href", "")
                            if u and u not in seen:
                                seen.add(u)
                                candidates.append({"url": u, "title": r.get("title", "")})
                        await asyncio.sleep(0.3)
                    except Exception:
                        continue
        except Exception as e:
            logger.debug(f"[StealerEngine] DDG: {type(e).__name__}")

        if not candidates:
            return []

        async with aiohttp.ClientSession() as session:
            tasks   = [_check_url(session, c["url"], c["title"], query) for c in candidates]
            checked = await asyncio.gather(*tasks, return_exceptions=True)

        results = [r for r in checked if isinstance(r, dict)]
        logger.debug(f"[StealerEngine] {len(results)} stealer sonucu")
        return results
