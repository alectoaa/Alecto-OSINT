import asyncio
import logging
import os
from typing import Any

import aiohttp

logger = logging.getLogger(__name__)

REMOTE_API_KEY = os.getenv("REMOTE_API_KEY", "").strip()
REMOTE_API_BASE_URL = "https://oathnet.org/api"
REMOTE_API_TIMEOUT = aiohttp.ClientTimeout(total=20)


class RemoteAPI:
    def __init__(self, api_key: str | None = None, base_url: str = REMOTE_API_BASE_URL):
        self.api_key = (api_key or REMOTE_API_KEY or "").strip()
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Accept": "application/json",
            "x-api-key": self.api_key,
        } if self.api_key else {}
        self.search_id: str | None = None

    def enabled(self) -> bool:
        return bool(self.api_key)

    async def _request(self, method: str, path: str, params: dict | None = None, json: dict | None = None) -> dict | None:
        if not self.enabled():
            return None

        url = f"{self.base_url}{path}"
        try:
            async with aiohttp.ClientSession(headers=self.headers) as session:
                async with session.request(
                    method,
                    url,
                    params=params,
                    json=json,
                    timeout=REMOTE_API_TIMEOUT,
                ) as resp:
                    if resp.status not in (200, 201):
                        logger.debug(f"[RemoteAPI] HTTP {resp.status} {method} {url}")
                        return None
                    return await resp.json()
        except Exception as exc:
            logger.debug(f"[RemoteAPI] request failed: {type(exc).__name__}: {exc}")
            return None

    async def init_search_session(self, query: str) -> str | None:
        if not self.enabled():
            return None
        payload = await self._request("POST", "/service/search/init", json={"query": query})
        if not payload:
            return None
        self.search_id = payload.get("data", {}).get("session", {}).get("id")
        return self.search_id

    async def breach_search(self, query: str, search_id: str | None = None) -> list[dict]:
        if not self.enabled():
            return []

        params = {"q": query}
        if search_id:
            params["search_id"] = search_id

        payload = await self._request("GET", "/service/v2/breach/search", params=params)
        return self._normalize_items(payload, query, "BREACH")

    async def stealer_search(self, query: str, search_id: str | None = None) -> list[dict]:
        if not self.enabled():
            return []

        params = {"q": query}
        if search_id:
            params["search_id"] = search_id

        payload = await self._request("GET", "/service/v2/stealer/search", params=params)
        return self._normalize_items(payload, query, "STEALER")

    async def victims_search(self, query: str, search_id: str | None = None) -> list[dict]:
        if not self.enabled():
            return []

        params = {"q": query}
        if search_id:
            params["search_id"] = search_id

        payload = await self._request("GET", "/service/v2/victims/search", params=params)
        return self._normalize_items(payload, query, "VICTIM")

    async def search(self, query: str, input_type: str) -> list[dict]:
        if not self.enabled():
            return []

        if not self.search_id:
            await self.init_search_session(query)

        tasks: list[Any] = [self.breach_search(query, self.search_id)]
        if input_type in ("EMAIL", "USERNAME", "GENERIC", "DOMAIN"):
            tasks.append(self.stealer_search(query, self.search_id))
        if input_type in ("EMAIL", "USERNAME", "DOMAIN"):
            tasks.append(self.victims_search(query, self.search_id))

        results: list[dict] = []
        gathered = await asyncio.gather(*tasks, return_exceptions=True)
        for item in gathered:
            if isinstance(item, list):
                results.extend(item)
        return results

    def _normalize_items(self, payload: dict | None, query: str, default_type: str) -> list[dict]:
        results: list[dict] = []
        if not payload or not payload.get("success", False):
            return results

        items = payload.get("data", {}).get("items", [])
        for item in items:
            if not isinstance(item, dict):
                continue
            snippet_parts: list[str] = []
            if item.get("email"):
                snippet_parts.append(f"email={item['email']}")
            if item.get("username"):
                snippet_parts.append(f"username={item['username']}")
            if item.get("password"):
                snippet_parts.append(f"password={item['password']}")
            if item.get("dbname"):
                snippet_parts.append(f"source={item['dbname']}")
            if item.get("indexed_at"):
                snippet_parts.append(f"indexed_at={item['indexed_at']}")

            snippet = " | ".join(snippet_parts)[:400]
            title = item.get("dbname") or item.get("source") or item.get("id") or default_type
            url = item.get("url") or f"https://oathnet.org/search?q={query}"
            results.append({
                "target": query,
                "type": default_type,
                "title": title,
                "url": url,
                "source": "Remote API",
                "snippet": snippet,
            })
        return results
