"""Privacy-preserving breach metadata lookups.

Only authorized breach notification/catalogue APIs are queried. Raw leaked
records, credentials, and password material are never fetched or returned.
"""
from __future__ import annotations

import logging
import os
import hashlib
from urllib.parse import quote

import aiohttp

logger = logging.getLogger(__name__)
XON_BASE = "https://api.xposedornot.com/v1"
HIBP_BASE = "https://haveibeenpwned.com/api/v3"


def _result(query: str, source: str, breach: dict) -> dict:
    name = str(breach.get("Name") or breach.get("name") or breach.get("breach") or "Known breach")[:160]
    date = str(breach.get("BreachDate") or breach.get("breach_date") or "")[:10]
    domain = str(breach.get("Domain") or breach.get("domain") or "")[:160]
    count = breach.get("PwnCount") or breach.get("pwn_count")
    data_classes = breach.get("DataClasses") or breach.get("data_classes") or []
    # These are catalogue fields only; discard every unrecognized API field.
    metadata = []
    if date:
        metadata.append(f"İhlal tarihi: {date}")
    if domain:
        metadata.append(f"Etkilenen hizmet: {domain}")
    if isinstance(count, int) and count >= 0:
        metadata.append(f"Katalogdaki etkilenen hesap: {count:,}")
    if isinstance(data_classes, list):
        safe_classes = [str(value)[:60] for value in data_classes[:12] if isinstance(value, str)]
        if safe_classes:
            metadata.append("Veri türleri: " + ", ".join(safe_classes))
    return {
        "target": query,
        "type": "BREACH",
        "title": name,
        "url": "https://haveibeenpwned.com/" if source == "HIBP" else "https://xposedornot.com/",
        "source": "Have I Been Pwned (HIBP)" if source == "HIBP" else source,
        "snippet": " | ".join(metadata) or "İhlal kataloğunda eşleşme bulundu; yalnızca kaynak metaverisi gösteriliyor.",
        "dataset": "Security Breaches",
        "breach_date": date or None,
        "data_classes": safe_classes if isinstance(data_classes, list) else [],
        "record_count": count if isinstance(count, int) and count >= 0 else None,
    }


class BreachEngine:
    """Checks public notification metadata and authenticated account APIs."""

    async def search(self, query: str, input_type: str) -> list[dict]:
        query = query.strip()
        if not query or input_type not in {"EMAIL", "DOMAIN"}:
            return []

        timeout = aiohttp.ClientTimeout(total=15)
        results: list[dict] = []
        async with aiohttp.ClientSession(timeout=timeout) as session:
            if input_type == "EMAIL":
                api_key = os.getenv("HIBP_API_KEY", "").strip()
                if api_key:
                    await self._hibp_email(session, query, api_key, results)
                else:
                    # Public fallback sends the full email to XposedOrNot.
                    await self._xposed_email(session, query, results)
            elif input_type == "DOMAIN":
                # HIBP only returns domain data to a key with verified domain access.
                api_key = os.getenv("HIBP_API_KEY", "").strip()
                if api_key:
                    await self._hibp_domain(session, query, api_key, results)

        unique: dict[tuple[str, str], dict] = {}
        for item in results:
            unique[(item["source"], item["title"].casefold())] = item
        return list(unique.values())

    async def _xposed_email(self, session, email: str, out: list[dict]) -> None:
        url = f"{XON_BASE}/check-email/{quote(email, safe='@.+-_')}"
        try:
            async with session.get(url, headers={"Accept": "application/json"}) as response:
                if response.status == 404:
                    return
                if response.status != 200:
                    logger.info("XposedOrNot lookup unavailable (HTTP %s)", response.status)
                    return
                payload = await response.json(content_type=None)
            if not isinstance(payload, dict):
                return
            names = payload.get("breaches", [])
            if names and isinstance(names[0], list):
                names = names[0]
            if not isinstance(names, list):
                return
            for name in names[:100]:
                if isinstance(name, str):
                    out.append(_result(email, "XposedOrNot", {"name": name}))
        except (aiohttp.ClientError, TimeoutError, ValueError) as exc:
            logger.info("XposedOrNot lookup failed: %s", type(exc).__name__)

    async def _hibp_email(self, session, email: str, api_key: str, out: list[dict]) -> None:
        headers = {"hibp-api-key": api_key, "user-agent": "OSINT-Breach-Monitor"}
        digest = hashlib.sha1(email.strip().lower().encode("utf-8")).hexdigest().upper()
        try:
            # HIBP k-anonymity API: only six hash characters leave this app.
            async with session.get(f"{HIBP_BASE}/breachedaccount/range/{digest[:6]}", headers=headers) as response:
                if response.status != 200:
                    logger.info("HIBP range lookup unavailable (HTTP %s)", response.status)
                    return
                rows = await response.json(content_type=None)
            if not isinstance(rows, list):
                return
            names = []
            for row in rows:
                if not isinstance(row, dict) or str(row.get("hashSuffix", "")).upper() != digest[6:]:
                    continue
                names = row.get("websites", [])
                break
            if not names:
                return
            catalog = await self._hibp_catalog(session)
            lookup = {str(item.get("Name", "")).casefold(): item for item in catalog}
            out.extend(_result(email, "HIBP", lookup[name.casefold()])
                       for name in names if isinstance(name, str) and name.casefold() in lookup)
        except (aiohttp.ClientError, TimeoutError, ValueError) as exc:
            logger.info("HIBP account lookup failed: %s", type(exc).__name__)

    async def _hibp_domain(self, session, domain: str, api_key: str, out: list[dict]) -> None:
        headers = {"hibp-api-key": api_key, "user-agent": "OSINT-Breach-Monitor"}
        try:
            async with session.get(f"{HIBP_BASE}/breacheddomain/{quote(domain, safe='')}", headers=headers) as response:
                if response.status == 404:
                    return
                if response.status != 200:
                    logger.info("HIBP domain lookup unavailable (HTTP %s)", response.status)
                    return
                payload = await response.json(content_type=None)
            if not isinstance(payload, dict):
                return
            # Domain API returns aliases, not full email addresses; discard aliases
            # immediately and retain only per-breach aggregate counts.
            counts: dict[str, int] = {}
            for names in payload.values():
                if isinstance(names, list):
                    for name in names:
                        if isinstance(name, str):
                            key = name.casefold()
                            counts[key] = counts.get(key, 0) + 1
            if not counts:
                return
            catalog = await self._hibp_catalog(session)
            lookup = {str(item.get("Name", "")).casefold(): item for item in catalog}
            for name, count in counts.items():
                breach = lookup.get(name)
                if not breach:
                    continue
                row = _result(domain, "HIBP", breach)
                row["snippet"] = f"Doğrulanmış alan adındaki {count} posta kutusunda eşleşme | " + row["snippet"]
                row["affected_mailboxes"] = count
                out.append(row)
        except (aiohttp.ClientError, TimeoutError, ValueError) as exc:
            logger.info("HIBP domain lookup failed: %s", type(exc).__name__)

    async def _hibp_catalog(self, session) -> list[dict]:
        async with session.get(f"{HIBP_BASE}/breaches", headers={"user-agent": "OSINT-Breach-Monitor"}) as response:
            if response.status != 200:
                return []
            payload = await response.json(content_type=None)
        return [item for item in payload if isinstance(item, dict)] if isinstance(payload, list) else []
