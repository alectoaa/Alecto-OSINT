from typing import List, Dict
import re

_SECRET_VALUE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key)\b\s*[:=]\s*\S+"
)
_CREDENTIAL_PAIR = re.compile(
    r"(?i)(?:[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}|https?://\S+)\s*[:;|]\s*\S{4,}"
)

# Temel 6 alana ek olarak korunacak opsiyonel alanlar
_EXTRA_FIELDS = (
    "avatar_url",
    "banner_url",
    "accent_color",
    "badges",
    "bot",
    "roblox_id",
    "extra",
    "_discord",
    "_partial",
)


class DataProcessor:
    def process_raw_results(self, raw_data: List) -> List[Dict]:
        """Ham veriyi temizler, eksik alanlari varsayilanla doldurur.
        Temel alanlara ek olarak avatar_url, banner_url, _discord gibi
        opsiyonel zengin-icerik alanlari da korunur.
        """
        processed = []
        seen: set[tuple[str, str]] = set()
        # patterns to detect boilerplate / error pages (multi-lingual)
        ERROR_PHRASES = (
            "üzgünüz bu sayfa bulunamadı",
            "sayfa bulunamadı",
            "page not found",
            "404 not found",
            "not found",
            "sorry",
            "this page could not be found",
        )

        # dataset/name -> preferred type mapping
        DATASET_TYPE_MAP = {
            'Gaming Profiles': 'PLATFORM',
            'Website Signups': 'SIGNUP',
            'Security Breaches': 'BREACH',
            'Stolen Information': 'STEALER',
            'Paste/Leak': 'PASTE',
            'ProxyNova/COMB': 'BREACH',
            'External API': 'GENERIC',
            'Roblox': 'ROBLOX',
            'Minecraft': 'MINECRAFT',
            'Steam': 'STEAM',
            'Instagram': 'INSTAGRAM',
            'Twitter/X': 'TWITTER',
            'GitHub': 'GITHUB',
        }

        for item in raw_data:
            if isinstance(item, dict):
                url = str(item.get("url") or "").strip()
                # Prefer explicit 'line' (matched line) when present
                snippet = str(item.get("line") or item.get("snippet") or "").strip()
                if _SECRET_VALUE.search(snippet) or _CREDENTIAL_PAIR.search(snippet):
                    snippet = "Olası kimlik bilgisi içeriği güvenlik nedeniyle gösterilmedi."
                key = (url, snippet)
                if key in seen:
                    continue
                seen.add(key)

                row = {
                    "target":  str(item.get("target") or ""),
                    "type":    str(item.get("type") or "GENERIC"),
                    "title":   str(item.get("title") or ""),
                    "url":     url,
                    "dataset": str(item.get("dataset") or item.get("source") or "Unknown"),
                    "source":  str(item.get("source") or "Unknown"),
                    "snippet": snippet,
                    "line_number": item.get("line_number"),
                    "line": item.get("line", ""),
                }

                # infer type from dataset map or URL patterns
                ds = row.get('dataset') or ''
                if isinstance(ds, str) and ds in DATASET_TYPE_MAP:
                    row['type'] = DATASET_TYPE_MAP[ds]

                # URL-based heuristics
                lu = url.lower()
                if 'steamcommunity.com' in lu:
                    row['type'] = 'STEAM'
                elif 'roblox' in lu:
                    row['type'] = 'ROBLOX'
                elif 'namemc' in lu or 'mojang' in lu:
                    row['type'] = 'MINECRAFT'
                elif 'pastebin' in lu or '/paste' in lu or 'onionshare' in lu:
                    row['type'] = 'PASTE'
                elif row["source"].startswith("tor.") and row["type"] == "GENERIC":
                    row["type"] = "DARK_INDEX"

                # filter out common error/boilerplate pages
                s_low = row.get('snippet', '').lower()
                if any(p in s_low for p in ERROR_PHRASES):
                    continue

                if row["target"] and row["target"].lower() in row["snippet"].lower():
                    # For full-name matches, prefer word-boundary detection
                    try:
                        import re as _re
                        if _re.search(r"\b" + _re.escape(row["target"]) + r"\b", row["snippet"], _re.IGNORECASE):
                            row["confidence"] = "high"
                        else:
                            row["confidence"] = "medium"
                    except Exception:
                        row["confidence"] = "high"
                elif any(tok in row["snippet"].lower() for tok in ("password", "pwd", "token", ":", ";")):
                    row["confidence"] = "medium"
                else:
                    row["confidence"] = "low"

                # Opsiyonel alanlari varsa ekle
                for field in _EXTRA_FIELDS:
                    if field in item:
                        row[field] = item[field]
                for field in ("breach_date", "data_classes", "record_count", "affected_mailboxes"):
                    if field in item:
                        row[field] = item[field]
                processed.append(row)
            else:
                processed.append({
                    "target":  str(item),
                    "type":    "GENERIC",
                    "title":   "",
                    "url":     "",
                    "source":  "System",
                    "snippet": "",
                })
        return processed
