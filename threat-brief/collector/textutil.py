"""Small text helpers shared by scoring, parsing, and matching."""

from __future__ import annotations

import html
import re

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def normalise(value: str | None) -> str:
    """Lowercase and turn punctuation into spaces so phrase checks are stable."""
    text = (value or "").lower().replace("_", " ")
    text = re.sub(r"[^a-z0-9]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def contains_phrase(haystack: str | None, phrase: str | None, min_length: int = 3) -> bool:
    """True when phrase is the whole haystack or a whole word/phrase inside it."""
    needle = normalise(phrase)
    hay = normalise(haystack)
    if len(needle) < min_length or not hay:
        return False
    if needle == hay:
        return True
    return f" {needle} " in f" {hay} "


def extract_cve_ids(text: str | None) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for match in CVE_RE.findall(text or ""):
        cve = match.upper()
        if cve not in seen:
            seen.add(cve)
            found.append(cve)
    return found


def strip_html(value: str | None) -> str:
    text = value or ""
    text = re.sub(r"(?is)<script\b.*?>.*?</script>", " ", text)
    text = re.sub(r"(?is)<style\b.*?>.*?</style>", " ", text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = html.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def clip(value: str | None, limit: int) -> str:
    text = (value or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"
