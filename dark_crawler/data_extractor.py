import re
from typing import Optional, Tuple

# E-posta:şifre / kullanıcı:hash / user:pass vb. sızıntı formatlarını arar.
LEAK_CONTENT_PATTERNS = [
    re.compile(
        r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\s*[:;|]\s*\S{4,64}',
        re.IGNORECASE,
    ),
    re.compile(
        r'\b[a-zA-Z0-9_.+-]{3,64}\s*[:;|\-]\s*\S{4,64}\b',
        re.IGNORECASE,
    ),
    re.compile(
        r'\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b.*\b(?:pass|password|pwd)\b',
        re.IGNORECASE,
    ),
    re.compile(
        r'\b(?:password|passwd|pwd|token|secret)\s*[:=]\s*\S{4,64}\b',
        re.IGNORECASE,
    ),
]

LEAK_METADATA_PATTERNS = [
    (
        "EMAIL_PASSWORD",
        re.compile(
            r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\s*[:;|]\s*\S{4,64}',
            re.IGNORECASE,
        ),
    ),
    (
        "API_KEY",
        re.compile(
            r'\b(?:AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|SG\.[A-Za-z0-9_-]{80}|[A-Za-z0-9_-]{32})\b',
            re.IGNORECASE,
        ),
    ),
    (
        "AWS_SECRET",
        re.compile(
            r'\b(?:aws_secret_access_key|aws_secret_key|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|A3T[A-Z0-9]{16}|AGPA[A-Z0-9]{16}|AIDA[A-Z0-9]{16})\b',
            re.IGNORECASE,
        ),
    ),
    (
        "PRIVATE_KEY",
        re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', re.IGNORECASE),
    ),
    (
        "PASSWORD_ASSIGNMENT",
        re.compile(r'\b(?:password|passwd|pwd|secret|token)\b\s*[:=]\s*\S{4,64}', re.IGNORECASE),
    ),
]

DIRECTORY_LISTING_PATTERN = re.compile(
    r'index of|directory listing|parent directory|directory listing for',
    re.IGNORECASE,
)


def is_leak_content(text: str) -> bool:
    """Metin, tipik sızıntı kalıplarını içeriyor mu?"""
    return any(pattern.search(text) for pattern in LEAK_CONTENT_PATTERNS)


def extract_leak_context(text: str, query: str) -> Optional[Tuple[str, int, str]]:
    """Sorguya en yakın sızıntı kalıbını döndürür.

    Eğer sorgu bir isimse, isim eşleşmelerinin etrafındaki bağlamı döndürür.
    Diğer durumlarda önce tipik leak kalıplarına bakılır.
    """
    q = query.strip()
    lower = text.lower()

    # If query looks like a name (contains space), try exact name matches first
    if " " in q:
        # word-boundary regex for the full name (case-insensitive)
        try:
            name_re = re.compile(r"\\b" + re.escape(q) + r"\\b", re.IGNORECASE)
        except re.error:
            name_re = None
        if name_re:
            m = name_re.search(text)
            if m:
                start = max(0, m.start() - 200)
                end = min(len(text), m.end() + 200)
                snippet = text[start:end].strip()
                # compute line number and line text
                line_no = text[:m.start()].count("\n") + 1
                lines = text.splitlines()
                line_text = lines[line_no - 1] if 0 <= line_no - 1 < len(lines) else snippet.splitlines()[0]
                return snippet, line_no, line_text.strip()

        # fallback: any occurrence of first or last name tokens
        parts = [p for p in re.split(r"\\s+", q) if p]
        for p in parts:
            if not p:
                continue
            try:
                tok_re = re.compile(r"\\b" + re.escape(p) + r"\\b", re.IGNORECASE)
            except re.error:
                continue
            m = tok_re.search(text)
            if m:
                start = max(0, m.start() - 120)
                end = min(len(text), m.end() + 120)
                snippet = text[start:end].strip()
                line_no = text[:m.start()].count("\n") + 1
                lines = text.splitlines()
                line_text = lines[line_no - 1] if 0 <= line_no - 1 < len(lines) else snippet.splitlines()[0]
                return snippet, line_no, line_text.strip()

    # Otherwise look for standard leak patterns
    if q.lower() not in lower and not is_leak_content(text):
        return None

    for pattern in LEAK_CONTENT_PATTERNS:
        match = pattern.search(text)
        if match:
            start = max(0, match.start() - 120)
            end = min(len(text), match.end() + 120)
            snippet = text[start:end].strip()
            line_no = text[:match.start()].count("\n") + 1
            lines = text.splitlines()
            line_text = lines[line_no - 1] if 0 <= line_no - 1 < len(lines) else snippet.splitlines()[0]
            return snippet, line_no, line_text.strip()

    return None


def extract_leak_metadata(text: str) -> dict:
    """Extract leak metadata and categories from a page text."""
    categories: list[str] = []
    matches: list[dict] = []

    for name, pattern in LEAK_METADATA_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0).strip()
            if name not in categories:
                categories.append(name)
            if len(matches) < 12:
                matches.append({"type": name, "match": value[:250]})

    return {
        "categories": categories,
        "matches": matches,
    }


def is_leak_content(text: str) -> bool:
    """Metin, tipik sızıntı kalıplarını içeriyor mu?"""
    if any(pattern.search(text) for pattern in LEAK_CONTENT_PATTERNS):
        return True
    if any(pattern.search(text) for _, pattern in LEAK_METADATA_PATTERNS):
        return True
    return False


def is_directory_listing(text: str) -> bool:
    """Sayfa tipik bir index/directory listesi mi?"""
    return bool(DIRECTORY_LISTING_PATTERN.search(text))
