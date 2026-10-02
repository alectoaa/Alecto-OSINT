"""Check whether a username has a public profile on selected platforms.

This module deliberately does not search paste sites or retrieve breach
content. Breach checks are handled by the breach engine.
"""
from __future__ import annotations

import asyncio
import logging
from urllib.parse import quote

import aiohttp

logger = logging.getLogger(__name__)

PLATFORMS = [
    {"name": "Steam", "url": "https://steamcommunity.com/id/{u}", "not_found": "The specified profile could not be found"},
    {"name": "Roblox", "url": "https://www.roblox.com/user.aspx?username={u}", "not_found": "Page cannot be found"},
    {"name": "Minecraft", "url": "https://api.mojang.com/users/profiles/minecraft/{u}", "not_found": None, "api": True},
    {"name": "Faceit", "url": "https://www.faceit.com/en/players/{u}", "not_found": "doesn't exist"},
    {"name": "Chess.com", "url": "https://www.chess.com/member/{u}", "not_found": "Oops"},
    {"name": "Twitch", "url": "https://www.twitch.tv/{u}", "not_found": "Sorry. Unless you've got a time machine"},
    {"name": "YouTube", "url": "https://www.youtube.com/@{u}", "not_found": "This page isn't available"},
    {"name": "Reddit", "url": "https://www.reddit.com/user/{u}", "not_found": "Sorry, nobody on Reddit goes by that name"},
    {"name": "TikTok", "url": "https://www.tiktok.com/@{u}", "not_found": "Couldn't find this account"},
    {"name": "Instagram", "url": "https://www.instagram.com/{u}/", "not_found": "Sorry, this page"},
    {"name": "Twitter/X", "url": "https://twitter.com/{u}", "not_found": "This account doesn't exist"},
    {"name": "Pinterest", "url": "https://www.pinterest.com/{u}/", "not_found": "We couldn't find"},
    {"name": "GitHub", "url": "https://github.com/{u}", "not_found": "Not Found"},
    {"name": "GitLab", "url": "https://gitlab.com/{u}", "not_found": "404"},
    {"name": "npm", "url": "https://www.npmjs.com/~{u}", "not_found": "404"},
    {"name": "Spotify", "url": "https://open.spotify.com/user/{u}", "not_found": "404"},
    {"name": "SoundCloud", "url": "https://soundcloud.com/{u}", "not_found": "404"},
    {"name": "Patreon", "url": "https://www.patreon.com/{u}", "not_found": "404"},
    {"name": "Keybase", "url": "https://keybase.io/{u}", "not_found": "404"},
]

NOT_FOUND_TEXTS = (
    "page not found", "404", "not found", "does not exist", "user not found",
    "profile not found", "no user found", "this account doesn't exist",
    "sorry, this page", "we couldn't find", "page cannot be found",
    "the specified profile could not be found", "sorry, nobody on reddit goes by that name",
)


def is_not_found_page(text: str) -> bool:
    lower = text.lower()[:2000]
    return any(phrase in lower for phrase in NOT_FOUND_TEXTS)


async def check_platform(session: aiohttp.ClientSession, platform: dict, username: str) -> dict | None:
    url = platform["url"].format(u=quote(username, safe=""))
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8), headers={"User-Agent": "Mozilla/5.0"}) as response:
            if response.status != 200:
                return None
            body = await response.text(errors="ignore")
            if platform.get("api"):
                if not body.strip() or body.strip() == "null":
                    return None
            else:
                not_found = platform.get("not_found")
                if is_not_found_page(body) or (not_found and not_found.lower() in body.lower()):
                    return None
            return {
                "target": username,
                "type": "USERNAME",
                "title": f"{platform['name']} — @{username}",
                "url": url,
                "source": platform["name"],
                "snippet": f"Kullanıcı adı {platform['name']} üzerinde mevcut.",
            }
    except (aiohttp.ClientError, TimeoutError) as exc:
        logger.debug("Platform check failed for %s: %s", platform["name"], type(exc).__name__)
        return None


class SurfaceScanner:
    async def search(self, query: str, max_results: int = 9999) -> list[dict]:
        username = query.strip()
        if not username or len(username) > 64:
            return []
        async with aiohttp.ClientSession() as session:
            checks = [check_platform(session, platform, username) for platform in PLATFORMS]
            found = await asyncio.gather(*checks, return_exceptions=True)
        return [item for item in found if isinstance(item, dict)][:max_results]
