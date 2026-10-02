"""
surface_scanner/discord_lookup.py
----------------------------------
Discord Bot Token ile kullanici bilgisi ceker.
GET https://discord.com/api/v10/users/{user_id}
"""

import os
import logging
from datetime import datetime, timezone

import aiohttp
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

DISCORD_API = "https://discord.com/api/v10"
BOT_TOKEN   = os.getenv("DISCORD_BOT_TOKEN", "")

# Discord Epoch: 2015-01-01 00:00:00 UTC
DISCORD_EPOCH = 1420070400000


def snowflake_to_datetime(snowflake_id: str) -> str:
    """Snowflake ID'den hesap olusturma tarihini hesaplar."""
    try:
        ts_ms = (int(snowflake_id) >> 22) + DISCORD_EPOCH
        dt = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return "Unknown"


def get_avatar_url(user_id: str, avatar_hash: str | None) -> str:
    if not avatar_hash:
        return "https://cdn.discordapp.com/embed/avatars/0.png"
    ext = "gif" if avatar_hash.startswith("a_") else "png"
    return f"https://cdn.discordapp.com/avatars/{user_id}/{avatar_hash}.{ext}?size=128"


def get_banner_url(user_id: str, banner_hash: str | None) -> str | None:
    if not banner_hash:
        return None
    ext = "gif" if banner_hash.startswith("a_") else "png"
    return f"https://cdn.discordapp.com/banners/{user_id}/{banner_hash}.{ext}?size=512"


FLAG_MAP = {
    1 << 0:  "Discord Staff",
    1 << 1:  "Partnered Server Owner",
    1 << 2:  "HypeSquad Events",
    1 << 3:  "Bug Hunter Lv1",
    1 << 6:  "HypeSquad Bravery",
    1 << 7:  "HypeSquad Brilliance",
    1 << 8:  "HypeSquad Balance",
    1 << 9:  "Early Supporter",
    1 << 14: "Bug Hunter Lv2",
    1 << 17: "Verified Bot Developer",
    1 << 18: "Certified Moderator",
    1 << 22: "Active Developer",
}


def _build_result(data: dict, user_id: str) -> dict:
    """Ham Discord API verisini normalize edilmiş dict'e çevirir."""
    uid           = data.get("id", user_id)
    username      = data.get("username", "")
    global_name   = data.get("global_name") or username
    discriminator = data.get("discriminator", "0")
    display       = f"{username}#{discriminator}" if discriminator != "0" else username
    avatar        = get_avatar_url(uid, data.get("avatar"))
    banner        = get_banner_url(uid, data.get("banner"))
    accent        = data.get("accent_color")
    bot           = data.get("bot", False)
    created_at    = snowflake_to_datetime(uid)
    flags         = data.get("public_flags", 0) or 0
    badges        = [name for bit, name in FLAG_MAP.items() if flags & bit]

    return {
        "found":        True,
        "id":           uid,
        "username":     username,
        "global_name":  global_name,
        "display":      display,
        "bot":          bot,
        "created_at":   created_at,
        "avatar_url":   avatar,
        "banner_url":   banner,
        "accent_color": f"#{accent:06x}" if accent else None,
        "badges":       badges,
        "source":       "Discord API",
        "type":         "DISCORD_ID",
        "target":       user_id,
    }


async def _try_with_token(session: aiohttp.ClientSession, user_id: str, token: str) -> dict | None:
    """Bot token ile /users/{id} dener. 401/403 alırsa None döner."""
    headers = {
        "Authorization": f"Bot {token}",
        "Content-Type":  "application/json",
    }
    try:
        async with session.get(
            f"{DISCORD_API}/users/{user_id}",
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            if resp.status == 200:
                return _build_result(await resp.json(), user_id)
            if resp.status == 404:
                return {"error": f"Kullanıcı bulunamadı: {user_id}"}
            if resp.status == 429:
                return {"error": "Rate limit. Biraz bekleyip tekrar dene."}
            # 401 / 403 → token geçersiz, None döndür → fallback dene
            logger.warning(f"[DiscordLookup] Bot token HTTP {resp.status} — fallback deneniyor")
            return None
    except Exception as e:
        logger.debug(f"[DiscordLookup] token denemesi hatası: {e}")
        return None


async def _try_widget_fallback(session: aiohttp.ClientSession, user_id: str) -> dict | None:
    """
    Token olmadan çalışan fallback:
    1. lookup.guru / discord.id gibi public lookup servisleri
    2. Snowflake'ten hesaplanan tarih + varsayılan avatar ile kısmi bilgi döner
    """
    # lookup.guru — ücretsiz Discord lookup API
    endpoints = [
        f"https://discord.id/api/fetch/?q={user_id}&type=user",
        f"https://lookup.guru/api/lookup?id={user_id}",
    ]
    for url in endpoints:
        try:
            async with session.get(
                url,
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=aiohttp.ClientTimeout(total=8),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    # discord.id formatı
                    if "user" in data:
                        data = data["user"]
                    # Her iki API da benzer alan adları kullanıyor
                    if data.get("username") or data.get("tag"):
                        raw_username = data.get("username") or data.get("tag","").split("#")[0]
                        return {
                            "found":        True,
                            "id":           user_id,
                            "username":     raw_username,
                            "global_name":  data.get("global_name") or data.get("globalName") or raw_username,
                            "display":      raw_username,
                            "bot":          data.get("bot", False),
                            "created_at":   snowflake_to_datetime(user_id),
                            "avatar_url":   get_avatar_url(user_id, data.get("avatar")),
                            "banner_url":   get_banner_url(user_id, data.get("banner")),
                            "accent_color": None,
                            "badges":       data.get("badges", []),
                            "source":       "Discord Public Lookup",
                            "type":         "DISCORD_ID",
                            "target":       user_id,
                        }
        except Exception as e:
            logger.debug(f"[DiscordLookup] fallback {url}: {e}")
            continue

    # Son fallback — sadece snowflake bilgisi
    return {
        "found":        True,
        "id":           user_id,
        "username":     f"user_{user_id}",
        "global_name":  "Bilinmiyor (token gerekli)",
        "display":      f"user_{user_id}",
        "bot":          False,
        "created_at":   snowflake_to_datetime(user_id),
        "avatar_url":   "https://cdn.discordapp.com/embed/avatars/0.png",
        "banner_url":   None,
        "accent_color": None,
        "badges":       [],
        "source":       "Discord (Kısmi — Token Gerekli)",
        "type":         "DISCORD_ID",
        "target":       user_id,
        "_partial":     True,
    }


async def lookup_discord_user(user_id: str) -> dict:
    """
    Discord kullanıcı bilgisini çeker.
    Önce bot token dener, 401/403 alırsa ücretsiz public lookup'a düşer.
    Her durumda sonuç döner — hiçbir zaman sadece hata vermez.
    """
    try:
        async with aiohttp.ClientSession() as session:
            # 1. Bot token varsa dene
            if BOT_TOKEN and BOT_TOKEN != "your_token_here":
                result = await _try_with_token(session, user_id, BOT_TOKEN)
                if result is not None:
                    return result
                # Token geçersizse loga yaz ama devam et

            # 2. Token yoksa veya geçersizse public fallback
            logger.info(f"[DiscordLookup] Public fallback kullanılıyor: {user_id}")
            result = await _try_widget_fallback(session, user_id)
            return result

    except aiohttp.ClientConnectorError:
        return {"error": "Discord API'ye bağlanılamadı. İnternet bağlantısını kontrol et."}
    except Exception as e:
        logger.error(f"[DiscordLookup] Hata: {e}")
        return {"error": str(e)}
