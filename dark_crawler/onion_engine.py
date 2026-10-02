"""
dark_crawler/onion_engine.py
-----------------------------
Tor üzerinden bilinen paste/leak .onion sitelerine direkt bağlan,
query içeren sayfaları döndür.

Gizlilik:
  - Her arama öncesi yeni Tor devresi (NEWNYM)
  - Sorgular loglanmaz (sadece hata debug logları)
  - User-Agent rotasyonu
  - Rastgele bekleme süreleri

Güvenlik filtresi:
  - İllegal satış, uyuşturucu, silah, CSAM içerik tespit edilirse
    o site atlanır, sonuç döndürülmez
"""

import asyncio
import logging
import os
import random
import re
import socket
import time
import urllib.parse

from aiohttp_socks import ProxyConnector
import aiohttp
from bs4 import BeautifulSoup

from dark_crawler.data_extractor import (
    extract_leak_context,
    extract_leak_metadata,
    is_directory_listing,
    is_leak_content,
)
from dark_crawler.db_manager import DBManager
from dark_crawler.tor_manager import renew_tor_circuit

logger = logging.getLogger(__name__)

TOR_SOCKS5 = os.getenv("TOR_PROXY", "socks5://127.0.0.1:9050")

ONION_TIMEOUT = aiohttp.ClientTimeout(total=30)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36",
]

# ── İllegal içerik filtresi ────────────────────────────────────────────────
# Bu ifadeler sayfada bulunursa site tamamen atlanır
ILLEGAL_KEYWORDS = [
    # Uyuşturucu satışı
    "buy cocaine", "buy heroin", "buy mdma", "buy meth", "buy fentanyl",
    "order drugs", "drug market", "darknet market", "dnm", "shop now",
    # Silah satışı
    "buy guns", "buy weapons", "buy firearms", "buy ammo", "weapon shop",
    # Çocuk istismarı
    "cp ", "csam", "preteen", "underage", "loli",
    # Kart/dolandırıcılık
    "buy cc ", "carding shop", "fullz for sale", "buy dumps",
    "cvv shop", "buy cvv", "stolen cards",
    # Genel illegal satış
    "add to cart", "place order", "checkout", "buy now",
    "vendor", "listing", "escrow",
    "monero", "btc payment", "bitcoin payment",
]

# Sayfanın içeriği bu ibarelerden birini içeriyorsa illegal satış sitesidir
def _is_illegal_site(text: str) -> bool:
    lower = text.lower()[:3000]
    return any(kw in lower for kw in ILLEGAL_KEYWORDS)


ERROR_PHRASES = [
    "page not found", "404", "does not exist", "access denied",
    "forbidden", "bad gateway", "service unavailable", "connection refused",
    "error 404", "nothing found",
]

_SECRET_VALUE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key)\b\s*[:=]\s*\S+"
)
_CREDENTIAL_PAIR = re.compile(
    r"(?i)(?:[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}|https?://\S+)\s*[:;|]\s*\S{4,}"
)

def _redact_sensitive_text(value: str | None) -> str:
    if not value:
        return ""
    if _SECRET_VALUE.search(value) or _CREDENTIAL_PAIR.search(value):
        return "Olası kimlik bilgisi içeriği güvenlik nedeniyle gösterilmedi."
    return value

def _is_error_page(text: str) -> bool:
    # Check a larger slice and include common multilingual variants
    lower = text.lower()[:4000]

    # Direct phrase matches
    if any(p in lower for p in ERROR_PHRASES):
        return True

    # Common site-not-found variants (English/Turkish/other common forms)
    extra_phrases = [
        "sorry, this page", "sorry this page", "the page you requested",
        "we couldn't find", "could not be found", "no results found",
        "üzgünüz", "sayfa bulunamadı", "sayfa bulunmuyor", "bulunamadı",
        "sayfayı bulamıyoruz", "aradığınız sayfa", "sayfa mevcut değil",
        "page doesn't exist", "this page is not available",
    ]
    if any(p in lower for p in extra_phrases):
        return True

    # Regex patterns for phrases like "sorry, the page was not found" or "üzgünüz, bu sayfa bulunamadı"
    try:
        if re.search(r"sorry[,\s].{0,40}page", lower):
            return True
        if re.search(r"uzg[uü]n[üu]?.{0,40}sayfa", lower):
            return True
    except Exception:
        pass

    return False


# ── Güvenli paste/leak .onion sitesi kataloğu ─────────────────────────────
# Sadece meşru paste, leak index ve arama servisleri
SITE_CATALOG = [
    {
        "name": "DeepPaste",
        "search_url": "http://depastedihrn3jtw.onion/search.php?term={q}",
        "tags": ["EMAIL", "USERNAME", "DISCORD_ID"],
    },
    {
        "name": "Riseup Paste",
        "url": "http://vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion/",
        "tags": ["EMAIL", "USERNAME"],
    },
    {
        "name": "IntelligenceX Onion",
        "search_url": "http://4p6mwq6iy37xhq4s.onion/phonebook/search?term={q}",
        "tags": ["EMAIL", "USERNAME", "DISCORD_ID"],
    },
    {
        "name": "OnionShare Paste",
        "url": "http://lldan5gahapx5k7iafb3s4ikijc4ni7gx5iywdflkba5y2ezyg6sjgyd.onion/",
        "tags": ["EMAIL", "USERNAME"],
    },
]

LEAK_INDEX_CATALOG = [
    {
        "name": "Haystak Leak Index",
        "search_url": "http://haystakvxad7wbk5.onion/search?query={q}",
        "tags": ["EMAIL", "USERNAME", "DISCORD_ID"],
    },
    {
        "name": "Vigilance Dump Portal",
        "search_url": "http://vigilanceoatg4.onion/search?q={q}",
        "tags": ["EMAIL", "USERNAME", "DISCORD_ID"],
    },
    {
        "name": "Doxbin Mirror",
        "search_url": "http://doxbin7swyhjbi.onion/search?q={q}",
        "tags": ["EMAIL", "USERNAME", "DISCORD_ID"],
    },
    {
        "name": "LeakSite Index",
        "search_url": "http://leakstoc5h35.onion/search?q={q}",
        "tags": ["EMAIL", "USERNAME", "DISCORD_ID"],
    },
    {
        "name": "Tor Taxi Search",
        "search_url": "http://tor.taxi/search?q={q}",
        "tags": ["EMAIL", "USERNAME", "DISCORD_ID"],
    },
    {
        "name": "Onion Live Search",
        "search_url": "https://onion.live/search?q={q}",
        "tags": ["EMAIL", "USERNAME", "DISCORD_ID"],
    },
    {
        "name": "Username Leak Search",
        "search_url": "http://userleaksskkjj7ev.onion/search?q={q}",
        "tags": ["USERNAME", "DISCORD_ID"],
    },
    {
        "name": "Discord Leak Index",
        "search_url": "http://discordleakv6kq35.onion/search?term={q}",
        "tags": ["DISCORD_ID", "USERNAME"],
    },
    {
        "name": "DarkPaste Search",
        "search_url": "http://darkpasteczq6ld7.onion/find/{q}",
        "tags": ["EMAIL", "USERNAME", "DISCORD_ID"],
    },
    {
        "name": "LeakRadar",
        "search_url": "http://leakradartri2fz.onion/search?q={q}",
        "tags": ["EMAIL", "USERNAME", "DISCORD_ID"],
    },
    {
        "name": "OnionLeakPool",
        "search_url": "http://onionleakpool2i6.onion/search?query={q}",
        "tags": ["EMAIL", "USERNAME", "DISCORD_ID"],
    },
]

DIRECTORY_SITES = [
    {
        "name": "Vigilance Dump Directory",
        "url": "http://vigilanceoatg4.onion/",
        "tags": ["EMAIL", "USERNAME", "DISCORD_ID"],
    },
    {
        "name": "Doxbin Directory",
        "url": "http://doxbin7swyhjbi.onion/",
        "tags": ["EMAIL", "USERNAME", "DISCORD_ID"],
    },
    {
        "name": "Haystak Root",
        "url": "http://haystakvxad7wbk5.onion/",
        "tags": ["EMAIL", "USERNAME", "DISCORD_ID"],
    },
    {
        "name": "LeakSite Root",
        "url": "http://leakstoc5h35.onion/",
        "tags": ["EMAIL", "USERNAME", "DISCORD_ID"],
    },
    {
        "name": "Discord Leak Archive",
        "url": "http://dleaksxjue3l6juf.onion/",
        "tags": ["DISCORD_ID", "USERNAME"],
    },
    {
        "name": "Username Leak Hub",
        "url": "http://userleakhub7rz.onion/",
        "tags": ["USERNAME", "DISCORD_ID"],
    },
    {
        "name": "PasteHub Root",
        "url": "http://pastehubm7z3.onion/",
        "tags": ["EMAIL", "USERNAME", "DISCORD_ID"],
    },
    {
        "name": "LeakDirectory",
        "url": "http://leakdirectoryu3x.onion/",
        "tags": ["EMAIL", "USERNAME", "DISCORD_ID"],
    },
]

INDEX_SOURCE_CATALOG = [
    {
        "name": "Ahmia Search",
        "search_url": "https://ahmia.fi/search/?q={q}",
        "source_type": "ahmia",
    },
    {
        "name": "Tor Taxi Search",
        "search_url": "http://tor.taxi/search?q={q}",
        "source_type": "document",
    },
    {
        "name": "Haystak Search",
        "search_url": "http://haystakvxad7wbk5.onion/search?query={q}",
        "source_type": "document",
    },
    {
        "name": "Torch Root",
        "search_url": "http://xmh57jrzrnw6insl.onion/",
        "source_type": "document",
    },
]

MAX_CRAWL_DEPTH = 3
MAX_CRAWL_RESULTS = 20
MAX_NODE_CRAWL = 5
MAX_PARALLEL_FETCHES = 4


def _request_timeout() -> aiohttp.ClientTimeout:
    return aiohttp.ClientTimeout(total=28, connect=8, sock_read=20, sock_connect=8)


def _extract_onion_urls(html: str, base_url: str = "") -> list[str]:
    links: set[str] = set()
    soup = BeautifulSoup(html, "html.parser")
    for anchor in soup.find_all("a", href=True):
        href = anchor["href"].strip()
        if not href or href.lower().startswith("javascript:"):
            continue
        link = urllib.parse.urljoin(base_url, href)
        if ".onion" in link.lower():
            if not link.lower().startswith(("http://", "https://")):
                link = "http://" + link
            links.add(link)
    for match in re.findall(r'https?://[a-z2-7]{16,56}\.onion(?:[\/\?\#][^\s"\'>]*)?', html, flags=re.IGNORECASE):
        links.add(match)
    return list(links)


def _build_index_tags(query: str, source_name: str) -> str:
    tags = [source_name]
    if "ahmia" in source_name.lower():
        tags.append("AHMIA")
    if "tor taxi" in source_name.lower():
        tags.append("TOR_TAXI")
    if "haystak" in source_name.lower():
        tags.append("HAYSTAK")
    if "torch" in source_name.lower():
        tags.append("TORCH")
    if query:
        tags.append("QUERY")
    return ",".join(tags)


def _build_circuit_label(source_type: str) -> str:
    if source_type == "ahmia":
        return "ahmia"
    return "document"


async def _fetch_text(
    session: aiohttp.ClientSession,
    url: str,
    retries: int = 2,
    delay: float = 0.7,
) -> str | None:
    for attempt in range(1, retries + 1):
        try:
            async with session.get(
                url,
                timeout=_request_timeout(),
                headers=_headers(),
                allow_redirects=True,
            ) as resp:
                if resp.status != 200:
                    return None
                content_type = resp.headers.get("Content-Type", "")
                if "text" not in content_type and "html" not in content_type and "plain" not in content_type:
                    return None
                return await resp.text(errors="ignore")
        except asyncio.TimeoutError:
            if attempt == retries:
                return None
        except Exception:
            if attempt == retries:
                return None
        await asyncio.sleep(delay * attempt)
    return None


# Site health cache to avoid repeatedly hitting dead/on-hold onions
SITE_HEALTH_TTL = 60 * 60  # 1 hour
_site_health_cache: dict[str, tuple[bool, float]] = {}


def _build_query_variants(query: str, input_type: str) -> list[str]:
    normalized = query.strip()
    if not normalized:
        return []

    variants = [normalized]
    lowercased = normalized.lower()
    if lowercased not in variants:
        variants.append(lowercased)

    if input_type == "EMAIL" and "@" in normalized:
        local, domain = normalized.split("@", 1)
        if local and local not in variants:
            variants.append(local)
        if domain and domain not in variants:
            variants.append(domain)

    if input_type == "USERNAME":
        cleaned = re.sub(r"[^a-zA-Z0-9_\.\-]", "", normalized)
        if cleaned and cleaned not in variants:
            variants.append(cleaned)
        underscored = cleaned.replace('.', '_').replace('-', '_')
        if underscored and underscored not in variants:
            variants.append(underscored)

    if input_type == "DISCORD_ID":
        digits = re.sub(r"\D", "", normalized)
        if digits and digits not in variants:
            variants.append(digits)

    # If the query looks like a full name, add name variants
    if " " in normalized:
        parts = [p for p in re.split(r"\s+", normalized) if p]
        if len(parts) >= 2:
            first = parts[0]
            last = parts[-1]
            full = f"{first} {last}"
            rev = f"{last} {first}"
            initials = "".join(p[0] for p in parts if p)
            for v in (full, rev, initials):
                if v and v not in variants:
                    variants.append(v)

    return variants


def _contains_query(text: str, queries: list[str]) -> bool:
    if not queries:
        return False
    lower = text.lower()
    return any(q.lower() in lower for q in queries if q)


async def _site_is_healthy(session: aiohttp.ClientSession, url: str) -> bool:
    """Check and cache whether a site responds sensibly.
    Uses a lightweight HEAD/GET and caches result for SITE_HEALTH_TTL seconds."""
    now = time.time()
    cached = _site_health_cache.get(url)
    if cached and now - cached[1] < SITE_HEALTH_TTL:
        return cached[0]

    try:
        # Try HEAD first
        async with session.head(url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
            ok = resp.status == 200
    except Exception:
        ok = False

    if not ok:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                ok = resp.status == 200 and int(resp.headers.get("Content-Length", "0")) > 20
                text = await resp.text(errors="ignore")
                if _is_error_page(text) or _is_illegal_site(text):
                    ok = False
        except Exception:
            ok = False

    _site_health_cache[url] = (ok, now)
    return ok


def tor_running() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", 9050), timeout=3):
            return True
    except OSError:
        return False


def _renew_circuit() -> None:
    """Her arama öncesi yeni Tor devresi — önceki sorgularla ilişki kesilir."""
    if not renew_tor_circuit():
        logger.debug("[OnionEngine] Tor devresi yenilenemedi.")


def _headers() -> dict:
    return {
        "User-Agent":      random.choice(USER_AGENTS),
        "Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "DNT":             "1",
    }


def _classify(query: str) -> str:
    if re.match(r'^\d{17,19}$', query.strip()):
        return "DISCORD_ID"
    if re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', query.strip()):
        return "EMAIL"
    return "USERNAME"


def _extract_context(text: str, query: str) -> str | None:
    idx = text.lower().find(query.lower())
    if idx == -1:
        return None
    start = max(0, idx - 100)
    return text[start: start + 400].strip()


def _find_links(soup: BeautifulSoup, base_url: str) -> list[str]:
    links: set[str] = set()
    for anchor in soup.find_all("a", href=True):
        href = anchor["href"].strip()
        if not href or href.startswith("mailto:"):
            continue
        if href.lower().startswith("javascript:"):
            continue
        link = urllib.parse.urljoin(base_url, href)
        if link.startswith("http://") or link.startswith("https://"):
            if ".onion" in link:
                links.add(link)

    raw_text = soup.get_text(separator="\n", strip=True)
    for match in re.findall(r'https?://[a-z2-7]{16,56}\.onion(?:/[\w\-\./?&=%#]*)?', raw_text, flags=re.IGNORECASE):
        links.add(match)

    return list(links)


async def _crawl_directory(
    session: aiohttp.ClientSession,
    url: str,
    queries: list[str],
    primary_query: str,
    source_name: str,
    visited: set[str],
    depth: int = 0,
    db: DBManager | None = None,
) -> list[dict]:
    if depth > MAX_CRAWL_DEPTH or url in visited:
        return []

    visited.add(url)
    results: list[dict] = []
    try:
        async with session.get(
            url,
            timeout=ONION_TIMEOUT,
            headers=_headers(),
            allow_redirects=True,
        ) as resp:
            if resp.status != 200:
                return []
            ct = resp.headers.get("Content-Type", "")
            if "text" not in ct and "html" not in ct and "plain" not in ct:
                return []

            html = await resp.text(errors="ignore")
            if len(html.strip()) < 120:
                return []

            if _is_illegal_site(html) or _is_error_page(html):
                return []

            soup = BeautifulSoup(html, "html.parser")
            text = soup.get_text(separator="\n", strip=True)

            # Yeni .onion linklerini veritabanına kaydet
            if db is not None:
                onion_links = _extract_onion_urls(html, url)
                if onion_links:
                    await db.bulk_add_nodes(
                        [(link, source_name, "DISCOVERED") for link in onion_links]
                    )

            if _contains_query(text, queries) or is_directory_listing(text) or is_leak_content(text):
                ctx = extract_leak_context(text, primary_query)
                snippet = None
                line_no = None
                line_text = None
                if not ctx and is_directory_listing(text):
                    snippet = text[:400]
                    line_no = 0
                    line_text = snippet.splitlines()[0] if snippet else ""
                elif not ctx and is_leak_content(text):
                    snippet = text[:400]
                    line_no = 0
                    line_text = snippet.splitlines()[0] if snippet else ""
                elif ctx:
                    snippet, line_no, line_text = ctx

                if snippet:
                    snippet = _redact_sensitive_text(snippet)
                    line_text = _redact_sensitive_text(line_text)
                    title_tag = soup.find("title")
                    title = title_tag.get_text(strip=True) if title_tag else url
                    metadata = extract_leak_metadata(text)
                    result_type = "DARK_LEAK" if is_leak_content(text) else "DARK_INDEX"
                    results.append({
                        "target":  primary_query,
                        "type":    result_type,
                        "title":   f"{title} ({result_type.lower()})",
                        "url":     url,
                        "dataset": source_name,
                        "source":  f"tor.directory.{source_name.lower().replace(' ', '_')}",
                        "snippet": snippet,
                        "line_number": line_no,
                        "line": line_text,
                        "metadata": metadata,
                    })

            if len(results) < MAX_CRAWL_RESULTS and (is_directory_listing(text) or is_leak_content(text) or depth < MAX_CRAWL_DEPTH):
                for link in _find_links(soup, url):
                    if len(results) >= MAX_CRAWL_RESULTS:
                        break
                    results.extend(await _crawl_directory(session, link, queries, primary_query, source_name, visited, depth + 1, db=db))
                    if len(results) >= MAX_CRAWL_RESULTS:
                        break

    except asyncio.TimeoutError:
        pass
    except Exception as e:
        logger.debug(f"[OnionEngine] crawl hatası: {type(e).__name__}")
    return results


async def _fetch(
    session: aiohttp.ClientSession,
    url: str,
    queries: list[str],
    primary_query: str,
    source_name: str,
    db: DBManager | None = None,
) -> list[dict]:
    results = []
    try:
        async with session.get(
            url,
            timeout=ONION_TIMEOUT,
            headers=_headers(),
            allow_redirects=True,
        ) as resp:
            if resp.status != 200:
                return []
            ct = resp.headers.get("Content-Type", "")
            if "text" not in ct and "html" not in ct and "plain" not in ct:
                return []
            html = await resp.text(errors="ignore")
            if len(html.strip()) < 100:
                return []

            soup = BeautifulSoup(html, "html.parser")
            text = soup.get_text(separator="\n", strip=True)

            if _is_illegal_site(text) or _is_error_page(text):
                return []

            if db is not None:
                onion_links = _extract_onion_urls(html, url)
                if onion_links:
                    await db.bulk_add_nodes(
                        [(link, source_name, "DISCOVERED") for link in onion_links]
                    )

            if not _contains_query(text, queries) and not is_directory_listing(text) and not is_leak_content(text):
                return []

            ctx = extract_leak_context(text, primary_query)
            snippet = None
            line_no = None
            line_text = None
            if not ctx and is_directory_listing(text):
                snippet = text[:400]
                line_no = 0
                line_text = snippet.splitlines()[0] if snippet else ""
            elif ctx:
                snippet, line_no, line_text = ctx
            if not snippet:
                return []

            snippet = _redact_sensitive_text(snippet)
            line_text = _redact_sensitive_text(line_text)
            title_tag = soup.find("title")
            title = title_tag.get_text(strip=True) if title_tag else url[:40]
            metadata = extract_leak_metadata(text)
            result_type = "DARK_LEAK" if is_leak_content(text) else "DARK_INDEX"
            results.append({
                "target":  primary_query,
                "type":    result_type,
                "title":   title,
                "url":     url,
                "dataset": source_name,
                "source":  f"tor.onion.{source_name.lower().replace(' ', '_')}",
                "snippet": snippet,
                "line_number": line_no,
                "line": line_text,
                "metadata": metadata,
            })
    except asyncio.TimeoutError:
        pass
    except Exception as e:
        logger.debug(f"[OnionEngine] fetch hatası: {type(e).__name__}")
    return results


class OnionEngine:
    def __init__(self) -> None:
        self.db = DBManager()

    async def _renew_circuit_for(self, source_type: str) -> None:
        if source_type == "ahmia":
            logger.debug("[OnionEngine] Ahmia içi ayrı Tor devresi talebi")
        else:
            logger.debug(f"[OnionEngine] Döküman sitesi devresi talebi: {source_type}")
        _renew_circuit()
        await asyncio.sleep(1.0)

    async def _fetch_index_source(
        self,
        session: aiohttp.ClientSession,
        source: dict,
        query: str,
    ) -> list[str]:
        if "{q}" in source["search_url"]:
            url = source["search_url"].replace("{q}", urllib.parse.quote_plus(query))
        else:
            url = source["search_url"]

        await self._renew_circuit_for(source.get("source_type", "document"))
        html = await _fetch_text(session, url)
        if not html:
            return []
        return _extract_onion_urls(html, url)

    async def refresh_index(self, query: str = "") -> int:
        """Fetch configured index sources and store discovered onion node URLs."""
        await self.db.initialize()
        connector = ProxyConnector.from_url(TOR_SOCKS5)
        active_nodes: list[tuple[str, str, str]] = []

        try:
            async with aiohttp.ClientSession(connector=connector) as session:
                tasks = [self._fetch_index_source(session, source, query) for source in INDEX_SOURCE_CATALOG]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for source, urls in zip(INDEX_SOURCE_CATALOG, results):
                    if isinstance(urls, list) and urls:
                        for url in urls:
                            active_nodes.append((url, source["name"], _build_index_tags(query, source["name"])))
                            if len(active_nodes) >= MAX_NODE_CRAWL * 3:
                                break
                    if len(active_nodes) >= MAX_NODE_CRAWL * 3:
                        break

            if not active_nodes:
                return 0

            added = await self.db.bulk_add_nodes(active_nodes)
            return added
        except Exception as exc:
            logger.debug(f"[OnionEngine] refresh_index hatası: {type(exc).__name__}: {exc}")
            return 0

    async def _crawl_node(
        self,
        session: aiohttp.ClientSession,
        url: str,
        queries: list[str],
        primary_query: str,
        source_name: str,
    ) -> list[dict]:
        try:
            await self.db.touch_node(url)
            return await _fetch(session, url, queries, primary_query, source_name, db=self.db)
        except Exception as exc:
            logger.debug(f"[OnionEngine] node crawl hatası: {type(exc).__name__}")
            return []

    async def _crawl_nodes(
        self,
        session: aiohttp.ClientSession,
        nodes: list[dict],
        queries: list[str],
        primary_query: str,
    ) -> list[dict]:
        semaphore = asyncio.Semaphore(MAX_PARALLEL_FETCHES)

        async def worker(node: dict) -> list[dict]:
            async with semaphore:
                return await self._crawl_node(
                    session,
                    node["url"],
                    queries,
                    primary_query,
                    node.get("source", node["url"]),
                )

        tasks = [asyncio.create_task(worker(node)) for node in nodes]
        results: list[dict] = []
        for chunk in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(chunk, list):
                results.extend(chunk)
        return results

    async def search_dark(self, query: str) -> list:
        if not tor_running():
            return []

        await self.db.initialize()
        _renew_circuit()
        await asyncio.sleep(random.uniform(0.5, 1.2))

        input_type = _classify(query)
        query_variants = _build_query_variants(query, input_type)
        results: list[dict] = []

        db_nodes = await self.db.get_active_nodes(limit=MAX_NODE_CRAWL)
        if not db_nodes:
            added = await self.refresh_index(query)
            logger.debug(f"[OnionEngine] index eklendi: {added} düğüm")
            db_nodes = await self.db.get_active_nodes(limit=MAX_NODE_CRAWL)

        connector = ProxyConnector.from_url(TOR_SOCKS5)
        try:
            async with aiohttp.ClientSession(connector=connector) as session:
                if db_nodes:
                    results = await self._crawl_nodes(session, db_nodes, query_variants, query)
                else:
                    for site in DIRECTORY_SITES[:MAX_NODE_CRAWL]:
                        if len(results) >= MAX_CRAWL_RESULTS:
                            break
                        url = site.get("url", "")
                        if not url:
                            continue
                        healthy = await _site_is_healthy(session, url)
                        if not healthy:
                            logger.debug(f"[OnionEngine] dizin sağlıksız: {url}")
                            continue
                        await asyncio.sleep(random.uniform(1.5, 3.0))
                        results.extend(await _crawl_directory(session, url, query_variants, query, site.get("name", "unknown"), set(), db=self.db))
        except Exception as e:
            logger.debug(f"[OnionEngine] bağlantı hatası: {type(e).__name__}")
        finally:
            if not connector.closed:
                await connector.close()

        return results[:MAX_CRAWL_RESULTS]
