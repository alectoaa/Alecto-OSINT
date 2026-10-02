"""intelligence/remote_scraper.py
----------------------------
Lightweight HTML scraper/parser for intelligence.org search pages.
This provides a fallback when the remote API key is not configured.

Functions:
  - search(query) -> list[dict]  (async)
  - parse_search_html(html, query) -> list[dict]
"""
from __future__ import annotations

import logging
import re
from typing import List

import aiohttp
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

BASE = "https://oathnet.org"


def _clean_text(el) -> str:
    if not el:
        return ""
    return " ".join(el.stripped_strings)


def parse_search_html(html: str, query: str) -> List[dict]:
    """Parse HTML returned from remote service search page into normalized result dicts.
    The parser is forgiving and will try multiple heuristics to extract title, url and snippet.
    """
    soup = BeautifulSoup(html, "html.parser")
    results: List[dict] = []

    # Common result containers: articles, .result, .card, .search-item
    # Prefer structured sections (headings like 'Security Breaches', 'Stolen Information', 'Gaming Profiles')
    section_headings = soup.find_all(re.compile(r'h[2-5]'))
    known_sections = [
        'Security Breaches', 'Stolen Information', 'Gaming Profiles',
        'Website Signups', 'Roblox Profiles', 'Instagram Profiles',
        'X / Twitter Profiles', 'Summary', 'Search Report'
    ]

    candidates = []
    for h in section_headings:
        txt = (h.get_text(" ", strip=True) or "").strip()
        if any(ks.lower() in txt.lower() for ks in known_sections):
            # collect anchors within the same parent/section
            parent = h.find_parent()
            if parent:
                anchors = parent.select('a[href]')
                for a in anchors:
                    candidates.append(a)

    # fallback: broad selection
    if not candidates:
        candidates = soup.select("article, .result, .card, .search-item, .row a")
    seen = set()
    for c in candidates:
        # find first anchor with href
        a = c.find("a", href=True)
        if not a:
            # sometimes candidate itself is an <a>
            if c.name == 'a' and c.get('href'):
                a = c
            else:
                continue
        href = a.get('href')
        if not href:
            continue
        # normalize url
        if href.startswith("/"):
            url = BASE + href
        else:
            url = href

        if url in seen:
            continue
        seen.add(url)

        # If candidate is an <a>, its container is 'c'
        c = a if a.name == 'a' else a.parent
        # title: anchor text or nearby heading
        title = a.get_text(strip=True) or (c.find(['h2', 'h3', 'h4']) and _clean_text(c.find(['h2', 'h3', 'h4']))) or url

        # snippet: nearest paragraph or small text element
        snippet = ""
        p = c.find('p') or c.find('span') or c.find_next_sibling('p')
        if p:
            snippet = _clean_text(p)
        else:
            snippet = _clean_text(c)

        # Attempt to infer dataset from nearby heading or badges
        dataset = None
        # climb parents looking for a heading
        parent = c
        for _ in range(3):
            if not parent:
                break
            heading = parent.find(['h2', 'h3', 'h4'])
            if heading and heading.get_text(strip=True):
                dataset = heading.get_text(strip=True)
                break
            parent = parent.parent

        dataset = dataset or 'External API'

        # Only keep items that mention the query (case-insensitive) or are likely profiles/pastes
        combined = (title + " " + snippet)
        if query.lower() in combined.lower() or re.search(r'profile|paste|breach|stealer|comb|onion|credential|password', url + combined, re.I):
            results.append({
                "target": query,
                "type": "GENERIC",
                "title": title,
                "url": url,
                "source": "Remote API (scrape)",
                "dataset": dataset,
                "snippet": snippet[:800],
                "line_number": None,
                "line": "",
                "confidence": "medium",
            })

    # If we found nothing, try textual fallback: lines containing query
    if not results:
        text = soup.get_text(separator="\n")
        for i, line in enumerate(text.splitlines()):
            if query.lower() in line.lower():
                results.append({
                    "target": query,
                    "type": "GENERIC",
                    "title": line.strip()[:80],
                    "url": f"{BASE}/search?q={query}",
                    "source": "Remote API (scrape)",
                    "dataset": "External API",
                    "snippet": line.strip()[:800],
                    "line_number": i + 1,
                    "line": line.strip(),
                    "confidence": "low",
                })

    return results


async def search(query: str) -> List[dict]:
    """Fetch intelligence.org search page and parse results.
    This function is best-effort — Cloudflare or site blocks may cause failures.
    """
    url = f"{BASE}/search?q={query}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    logger.debug(f"[remote_scraper] HTTP {resp.status} {url}")
                    return []
                html = await resp.text()
                return parse_search_html(html, query)
    except Exception as exc:
        logger.debug(f"[remote_scraper] fetch failed: {exc}")
        return []
