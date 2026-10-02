"""
intelligence/osint_lookups.py
-------------------------
OSINT Lookups — her servis configured service gerçek kaynaklarından beslenir.

Servis → Kaynak API eşleşmesi:
  Discord User Info        → Discord public API v10  /users/{id}
  Discord Username History → Discord + Pomelo tracker
  Discord → Roblox         → Bloxlink public API
  Steam Profile            → Steam Web API (key opsiyonel)
  Xbox Profile             → OpenXBL free tier
  Roblox User Info         → Roblox public REST API
  Minecraft History        → Mojang API
  IP Geolocation           → ip-api.com (ücretsiz, 45 req/min)
  Email Account Check      → Holehe local + manuel
  Subdomain Finder         → crt.sh + HackerTarget
"""

import asyncio
import logging
import os
from datetime import datetime, timezone

import aiohttp

logger = logging.getLogger(__name__)

H = {
    "User-Agent":    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Accept":        "application/json",
    "Accept-Language": "en-US,en;q=0.9",
}
T = aiohttp.ClientTimeout(total=10)


def _env(k: str) -> str:
    return os.getenv(k, "").strip()


# ── Discord snowflake → tarih ──────────────────────────────────────────────
def _snowflake_to_dt(sid: str) -> str:
    try:
        ts = (int(sid) >> 22) + 1420070400000
        return datetime.fromtimestamp(ts / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return "?"


DISCORD_FLAGS = {
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


# ── 1. Discord User Info ───────────────────────────────────────────────────
async def discord_user_info(session: aiohttp.ClientSession, discord_id: str) -> dict:
    token = _env("DISCORD_BOT_TOKEN")
    headers = {**H, "Authorization": f"Bot {token}"} if token else H

    try:
        async with session.get(
            f"https://discord.com/api/v10/users/{discord_id}",
            headers=headers, timeout=T,
        ) as resp:
            if resp.status == 200:
                d = await resp.json()
                uid   = d.get("id", discord_id)
                uname = d.get("username", "")
                disc  = d.get("discriminator", "0")
                av    = d.get("avatar", "")
                bn    = d.get("banner", "")
                flags = d.get("public_flags", 0) or 0
                av_fmt  = "gif" if av and av.startswith("a_") else "png"
                bn_fmt  = "gif" if bn and bn.startswith("a_") else "png"
                return {
                    "found":        True,
                    "id":           uid,
                    "username":     uname,
                    "global_name":  d.get("global_name") or uname,
                    "display":      f"{uname}#{disc}" if disc != "0" else uname,
                    "avatar_url":   (f"https://cdn.discordapp.com/avatars/{uid}/{av}.{av_fmt}?size=1024"
                                     if av else f"https://cdn.discordapp.com/embed/avatars/{int(uid)%5}.png"),
                    "banner_url":   (f"https://cdn.discordapp.com/banners/{uid}/{bn}.{bn_fmt}?size=1024"
                                     if bn else None),
                    "accent_color": (f"#{d['accent_color']:06x}" if d.get("accent_color") else None),
                    "created_at":   _snowflake_to_dt(uid),
                    "badges":       [name for bit, name in DISCORD_FLAGS.items() if flags & bit],
                    "bot":          d.get("bot", False),
                }
            if resp.status == 404:
                return {"error": "Discord kullanıcısı bulunamadı."}
            if resp.status in (401, 403):
                return await _discord_public_fallback(session, discord_id)
            return {"error": f"Discord API: HTTP {resp.status}"}
    except Exception as e:
        logger.debug(f"[Discord] {e}")
        return await _discord_public_fallback(session, discord_id)


async def _discord_public_fallback(session: aiohttp.ClientSession, discord_id: str) -> dict:
    """Token yoksa public lookup servislerini dene."""
    for url in [
        f"https://discord.id/api/fetch/?q={discord_id}&type=user",
        f"https://lookup.guru/api/lookup?id={discord_id}",
    ]:
        try:
            async with session.get(url, headers=H, timeout=T) as r:
                if r.status == 200:
                    d = await r.json(content_type=None)
                    if "user" in d:
                        d = d["user"]
                    uname = d.get("username") or d.get("tag", "").split("#")[0] or f"user_{discord_id}"
                    return {
                        "found":       True,
                        "id":          discord_id,
                        "username":    uname,
                        "global_name": d.get("global_name") or d.get("globalName") or uname,
                        "display":     uname,
                        "avatar_url":  (f"https://cdn.discordapp.com/avatars/{discord_id}/{d['avatar']}.png?size=1024"
                                        if d.get("avatar") else "https://cdn.discordapp.com/embed/avatars/0.png"),
                        "banner_url":  None,
                        "accent_color": None,
                        "created_at":  _snowflake_to_dt(discord_id),
                        "badges":      d.get("badges", []),
                        "bot":         False,
                    }
        except Exception:
            continue
    # Son fallback — sadece snowflake
    return {
        "found":       True,
        "id":          discord_id,
        "username":    f"user_{discord_id}",
        "global_name": "Bilinmiyor",
        "display":     f"user_{discord_id}",
        "avatar_url":  "https://cdn.discordapp.com/embed/avatars/0.png",
        "banner_url":  None,
        "accent_color": None,
        "created_at":  _snowflake_to_dt(discord_id),
        "badges":      [],
        "bot":         False,
        "_partial":    True,
    }


# ── 2. Discord Username History ────────────────────────────────────────────
async def discord_username_history(session: aiohttp.ClientSession, discord_id: str) -> list[dict]:
    """
    Remote API'de /service/discord-username-history endpoint'inin karşılığı.
    discord.id ve pomelo tracker üzerinden geçmiş kullanıcı adları.
    """
    results = []
    try:
        async with session.get(
            f"https://discord.id/api/fetch/?q={discord_id}&type=user",
            headers=H, timeout=T,
        ) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                history = data.get("history") or data.get("user", {}).get("history") or []
                if history:
                    names = [h.get("name") or h for h in history if h]
                    results.append({
                        "target":  discord_id,
                        "type":    "DISCORD_HISTORY",
                        "title":   f"Discord Kullanıcı Adı Geçmişi — {len(names)} kayıt",
                        "url":     f"https://discord.id/{discord_id}",
                        "source":  "Discord History",
                        "snippet": "📝 Geçmiş adlar: " + ", ".join(str(n) for n in names[:10]),
                    })
    except Exception as e:
        logger.debug(f"[DiscordHistory] {e}")
    return results


# ── 3. Discord → Roblox ────────────────────────────────────────────────────
async def discord_to_roblox(session: aiohttp.ClientSession, discord_id: str) -> dict | None:
    """
    Remote API'de /service/discord-to-roblox endpoint'inin karşılığı.
    Bloxlink public API.
    """
    api_key = _env("BLOXLINK_API_KEY")
    headers = {**H, "api-key": api_key} if api_key else H
    try:
        async with session.get(
            f"https://api.blox.link/v4/public/discord/{discord_id}",
            headers=headers, timeout=T,
        ) as resp:
            if resp.status == 200:
                d = await resp.json()
                rblx_id = d.get("robloxID") or d.get("primaryAccount")
                if rblx_id:
                    return {"discord_id": discord_id, "roblox_id": str(rblx_id)}
    except Exception as e:
        logger.debug(f"[DiscordToRoblox] {e}")
    return None


# ── 4. Roblox User Info ────────────────────────────────────────────────────
async def roblox_user_info(session: aiohttp.ClientSession, username: str | None = None, user_id: str | None = None) -> dict | None:
    """
    Remote API'de /service/roblox-userinfo endpoint'inin karşılığı.
    username VEYA user_id verilebilir.
    """
    try:
        if username and not user_id:
            async with session.post(
                "https://users.roblox.com/v1/usernames/users",
                json={"usernames": [username], "excludeBannedUsers": False},
                headers=H, timeout=T,
            ) as r:
                if r.status != 200:
                    return None
                items = (await r.json()).get("data", [])
                if not items:
                    return None
                user_id = str(items[0]["id"])
                username = items[0].get("name", username)

        if not user_id:
            return None

        # Profil detayı
        async with session.get(
            f"https://users.roblox.com/v1/users/{user_id}",
            headers=H, timeout=T,
        ) as r:
            profile = await r.json() if r.status == 200 else {}

        # Avatar
        av_url = ""
        async with session.get(
            f"https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds={user_id}&size=150x150&format=Png",
            headers=H, timeout=T,
        ) as ra:
            if ra.status == 200:
                imgs = (await ra.json()).get("data", [])
                av_url = imgs[0].get("imageUrl", "") if imgs else ""

        created  = profile.get("created", "?")[:10]
        banned   = profile.get("isBanned", False)
        desc     = (profile.get("description") or "")[:120]
        uname    = profile.get("name", username or "?")

        return {
            "target":     username or user_id,
            "type":       "ROBLOX",
            "title":      f"Roblox — {uname}",
            "url":        f"https://www.roblox.com/users/{user_id}/profile",
            "source":     "Roblox",
            "snippet":    f"🎮 ID: {user_id} | Kayıt: {created} | {'🚫 Banlı' if banned else '✅ Aktif'} | {desc}",
            "avatar_url": av_url,
            "roblox_id":  user_id,
        }
    except Exception as e:
        logger.debug(f"[Roblox] {e}")
    return None


# ── 5. Steam Profile ───────────────────────────────────────────────────────
async def steam_profile(session: aiohttp.ClientSession, identifier: str) -> dict | None:
    """
    Remote API'de /service/steam endpoint'inin karşılığı.
    identifier: SteamID64 veya vanity URL.
    """
    api_key = _env("STEAM_API_KEY")
    steam_id = identifier

    # Sayısal değilse vanity URL olarak çöz
    if api_key and not identifier.isdigit():
        try:
            async with session.get(
                "https://api.steampowered.com/ISteamUser/ResolveVanityURL/v0001/",
                params={"key": api_key, "vanityurl": identifier},
                headers=H, timeout=T,
            ) as r:
                if r.status == 200:
                    steam_id = (await r.json()).get("response", {}).get("steamid", identifier)
        except Exception:
            pass

    if not api_key:
        # Key yok — sadece profil URL'si döndür
        return {
            "target":  identifier,
            "type":    "STEAM",
            "title":   f"Steam — {identifier}",
            "url":     f"https://steamcommunity.com/id/{identifier}",
            "source":  "Steam",
            "snippet": f"🎮 Profil: steamcommunity.com/id/{identifier} (detay için STEAM_API_KEY gerekli)",
        }

    try:
        async with session.get(
            "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/",
            params={"key": api_key, "steamids": steam_id},
            headers=H, timeout=T,
        ) as r:
            if r.status == 200:
                players = (await r.json()).get("response", {}).get("players", [])
                if players:
                    p = players[0]
                    state_map = {0:"Offline",1:"Online",2:"Busy",3:"Away",4:"Snooze",6:"Playing"}
                    return {
                        "target":     identifier,
                        "type":       "STEAM",
                        "title":      f"Steam — {p.get('personaname', identifier)}",
                        "url":        p.get("profileurl", f"https://steamcommunity.com/id/{identifier}"),
                        "source":     "Steam",
                        "snippet":    f"🎮 SteamID64: {steam_id} | Durum: {state_map.get(p.get('personastate',0),'?')} | Ülke: {p.get('loccountrycode','?')}",
                        "avatar_url": p.get("avatarfull", ""),
                    }
    except Exception as e:
        logger.debug(f"[Steam] {e}")
    return None


# ── 6. Xbox Profile ────────────────────────────────────────────────────────
async def xbox_profile(session: aiohttp.ClientSession, gamertag: str) -> dict | None:
    """
    Remote API'de /service/xbox endpoint'inin karşılığı.
    OpenXBL free tier.
    """
    api_key = _env("OPENXBL_API_KEY")
    headers = {**H, "X-Authorization": api_key, "Accept-Language": "en-US"} if api_key else H
    try:
        async with session.get(
            f"https://xbl.io/api/v2/friends/search?gt={gamertag}",
            headers=headers, timeout=T,
        ) as r:
            if r.status == 200:
                data   = await r.json()
                people = data.get("profileUsers") or data.get("people", [])
                if people:
                    p    = people[0]
                    xuid = p.get("id", "?")
                    sett = p.get("settings", [])
                    gt   = next((s["value"] for s in sett if s.get("id") == "Gamertag"), gamertag)
                    gs   = next((s["value"] for s in sett if s.get("id") == "Gamerscore"), "?")
                    av   = next((s["value"] for s in sett if s.get("id") in ("GameDisplayPicRaw","PublicGamerpic")), "")
                    return {
                        "target":     gamertag,
                        "type":       "XBOX",
                        "title":      f"Xbox — {gt}",
                        "url":        f"https://xboxgamertag.com/search/{gamertag}",
                        "source":     "Xbox",
                        "snippet":    f"🎮 XUID: {xuid} | Gamertag: {gt} | Gamerscore: {gs}",
                        "avatar_url": av,
                    }
    except Exception as e:
        logger.debug(f"[Xbox] {e}")
    return None


# ── 7. Minecraft Username History ──────────────────────────────────────────
async def minecraft_history(session: aiohttp.ClientSession, username: str) -> dict | None:
    """
    Remote API'de /service/mc-history endpoint'inin karşılığı.
    Mojang API.
    """
    try:
        async with session.get(
            f"https://api.mojang.com/users/profiles/minecraft/{username}",
            headers=H, timeout=T,
        ) as r:
            if r.status == 200:
                d = await r.json()
                uid   = d.get("id", "")
                uname = d.get("name", username)
                return {
                    "target":  username,
                    "type":    "MINECRAFT",
                    "title":   f"Minecraft — {uname}",
                    "url":     f"https://namemc.com/profile/{uid}",
                    "source":  "Minecraft",
                    "snippet": f"⛏️ UUID: {uid} | Kullanıcı adı: {uname}",
                }
    except Exception as e:
        logger.debug(f"[Minecraft] {e}")
    return None


# ── 8. IP Geolocation ──────────────────────────────────────────────────────
async def ip_geolocation(session: aiohttp.ClientSession, ip: str) -> dict:
    """
    Remote API'de /service/ip-info endpoint'inin karşılığı.
    ip-api.com ücretsiz, 45 req/min.
    """
    try:
        fields = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,proxy,hosting,query"
        async with session.get(
            f"http://ip-api.com/json/{ip}?fields={fields}",
            timeout=T,
        ) as r:
            if r.status == 200:
                d = await r.json()
                if d.get("status") == "success":
                    return {
                        "target":  ip,
                        "type":    "IP_INFO",
                        "title":   f"IP: {ip} — {d.get('city','?')}, {d.get('country','?')}",
                        "url":     f"https://ipinfo.io/{ip}",
                        "source":  "IP Geolocation",
                        "snippet": (
                            f"🌍 {d.get('country','?')} ({d.get('countryCode','?')}) | "
                            f"Şehir: {d.get('city','?')} | "
                            f"ISP: {d.get('isp','?')} | "
                            f"Org: {d.get('org','?')} | "
                            f"Proxy: {'Evet' if d.get('proxy') else 'Hayır'} | "
                            f"Hosting: {'Evet' if d.get('hosting') else 'Hayır'} | "
                            f"Konum: {d.get('lat','?')},{d.get('lon','?')}"
                        ),
                        "extra": d,
                    }
    except Exception as e:
        logger.debug(f"[IPGeo] {e}")
    return {
        "target": ip, "type": "IP_INFO",
        "title": f"IP: {ip}", "url": f"https://ipinfo.io/{ip}",
        "source": "IP Geolocation", "snippet": "Bilgi alınamadı.",
    }


# ── 9. Email Account Check (Holehe) ───────────────────────────────────────
async def email_account_check(session: aiohttp.ClientSession, email: str) -> list[dict]:
    """
    Remote API'de /service/holehe endpoint'inin karşılığı.
    Holehe kütüphanesi varsa kullanır.
    """
    results = []
    try:
        import holehe.core as hc
        async for module in hc.checkMail(email):
            if module.get("exists"):
                name   = module.get("name", "?")
                domain = module.get("domain", "")
                results.append({
                    "target":  email,
                    "type":    "EMAIL_ACCOUNT",
                    "title":   f"Holehe — {name}",
                    "url":     f"https://{domain}" if domain else "",
                    "source":  "Holehe",
                    "snippet": f"📧 {email} → {name} platformunda kayıtlı hesap",
                })
        return results
    except ImportError:
        logger.debug("[Holehe] kütüphane bulunamadı")
    except Exception as e:
        logger.debug(f"[Holehe] {e}")

    # Holehe yoksa Gravatar fallback
    try:
        import hashlib
        h = hashlib.md5(email.lower().encode()).hexdigest()
        async with session.get(
            f"https://www.gravatar.com/{h}.json",
            headers=H, timeout=T,
        ) as r:
            if r.status == 200:
                d = await r.json()
                entry = (d.get("entry") or [{}])[0]
                results.append({
                    "target":  email,
                    "type":    "EMAIL_ACCOUNT",
                    "title":   f"Gravatar — {entry.get('displayName', email)}",
                    "url":     f"https://gravatar.com/{h}",
                    "source":  "Holehe",
                    "snippet": f"📧 {email} → Gravatar hesabı mevcut | Profil: {entry.get('profileUrl', '')}",
                })
    except Exception:
        pass

    return results


# ── 10. Subdomain Finder ───────────────────────────────────────────────────
async def subdomain_finder(session: aiohttp.ClientSession, domain: str) -> list[dict]:
    """
    Remote API'de /service/extract-subdomain endpoint'inin karşılığı.
    crt.sh + HackerTarget.
    """
    subdomains: set = set()

    # crt.sh
    try:
        async with session.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=aiohttp.ClientTimeout(total=15),
        ) as r:
            if r.status == 200:
                for cert in await r.json(content_type=None):
                    for n in cert.get("name_value", "").split("\n"):
                        n = n.strip().lstrip("*.")
                        if domain in n:
                            subdomains.add(n)
    except Exception as e:
        logger.debug(f"[crt.sh] {e}")

    # HackerTarget
    try:
        async with session.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=aiohttp.ClientTimeout(total=12),
        ) as r:
            if r.status == 200:
                for line in (await r.text()).splitlines():
                    if "," in line:
                        sub = line.split(",")[0].strip()
                        if domain in sub:
                            subdomains.add(sub)
    except Exception as e:
        logger.debug(f"[HackerTarget] {e}")

    if not subdomains:
        return []

    sub_list = sorted(subdomains)[:50]
    return [{
        "target":  domain,
        "type":    "SUBDOMAIN",
        "title":   f"Subdomain Bulucu — {len(sub_list)} subdomain",
        "url":     f"https://crt.sh/?q=%.{domain}",
        "source":  "SubdomainFinder",
        "snippet": (
            f"🔎 {domain} için {len(sub_list)} subdomain:\n"
            + "\n".join(f"  • {s}" for s in sub_list[:20])
            + (f"\n  ...ve {len(sub_list)-20} daha" if len(sub_list) > 20 else "")
        ),
    }]


# ── Ana sınıf ──────────────────────────────────────────────────────────────
class OsintLookups:
    """OSINT Lookups servislerinin tam karşılığı."""

    async def lookup_discord(self, discord_id: str) -> dict:
        from surface_scanner.discord_lookup import lookup_discord_user
        return await lookup_discord_user(discord_id)

    async def lookup_discord_full(self, discord_id: str) -> list[dict]:
        """Discord + geçmiş + Roblox bağlantısı."""
        results = []
        async with aiohttp.ClientSession() as s:
            # Username geçmişi
            history = await discord_username_history(s, discord_id)
            results.extend(history)
            # Roblox bağlantısı
            rblx = await discord_to_roblox(s, discord_id)
            if rblx:
                info = await roblox_user_info(s, user_id=rblx["roblox_id"])
                if info:
                    info["title"] = f"Roblox (Discord {discord_id} bağlantısı)"
                    results.append(info)
        return results

    async def lookup_ip(self, ip: str) -> dict:
        async with aiohttp.ClientSession() as s:
            return await ip_geolocation(s, ip)

    async def lookup_username(self, username: str) -> list[dict]:
        """Steam, Xbox, Roblox, Minecraft paralel."""
        results = []
        async with aiohttp.ClientSession() as s:
            tasks = [
                minecraft_history(s, username),
                roblox_user_info(s, username=username),
                steam_profile(s, username),
                xbox_profile(s, username),
            ]
            for r in await asyncio.gather(*tasks, return_exceptions=True):
                if isinstance(r, dict):
                    results.append(r)
        return results

    async def lookup_email(self, email: str) -> list[dict]:
        async with aiohttp.ClientSession() as s:
            return await email_account_check(s, email)

    async def lookup_domain(self, domain: str) -> list[dict]:
        async with aiohttp.ClientSession() as s:
            return await subdomain_finder(s, domain)
