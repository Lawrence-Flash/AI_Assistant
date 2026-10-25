"""Plain-English summaries.

`get_summariser` is the plug for a later AI summary. This version registers
only the rule-based fallback. Asking for any other engine fails clearly
instead of calling a model.
"""

from __future__ import annotations

from typing import Protocol


class Summary:
    def __init__(self, text: str, what_to_do: str, engine: str):
        self.text = text
        self.what_to_do = what_to_do
        self.engine = engine


class Summariser(Protocol):
    name: str

    def summarise(self, item: dict) -> Summary:
        """Return a short summary and one 'what to do' line."""


class RuleBasedSummariser:
    """No model. The sentences are filled from the fields already on the item."""

    name = "rules-v1"

    def summarise(self, item: dict) -> Summary:
        if item.get("kind") == "news":
            return self._news(item)
        return self._cve(item)

    def _cve(self, item: dict) -> Summary:
        cve_id = item.get("cve_id") or "This CVE"
        subject = _product_label(item)
        severity = (item.get("severity") or "unspecified").lower()
        sentences = [f"{cve_id} is a {severity} vulnerability in {subject}."]
        description = _first_sentence(item.get("description") or "")
        if description and description.lower() not in sentences[0].lower():
            sentences.append(description)
        if item.get("in_kev"):
            sentences.append(
                "The US CISA catalog lists it as already exploited. "
                "That catalog is written for US federal agencies. It is still a strong sign the bug is being used in real attacks, including against smaller organisations."
            )
            if (item.get("ransomware") or "").lower() == "known":
                sentences.append("CISA also marks it as used in ransomware campaigns.")
        elif item.get("epss") is not None and float(item["epss"]) >= 0.1:
            sentences.append(
                f"FIRST's EPSS model puts the chance of exploitation activity in the next 30 days at about {float(item['epss']) * 100:.0f} percent. That is a forecast, not a promise."
            )
        matches = item.get("smb_matches") or []
        if matches:
            sentences.append(
                "It matches software this briefing watches for small businesses: " + ", ".join(matches) + "."
            )
        else:
            sentences.append(
                "It does not match the small-business software list, so a typical shop or office may not run it."
            )
        return Summary(" ".join(sentences), _what_to_do_cve(item, subject), self.name)

    def _news(self, item: dict) -> Summary:
        source = item.get("source") or "a news feed"
        title = item.get("title") or "A security headline"
        text = (
            f"Headline from {source}: {title}. "
            "This is a news item from a third party. It is not a finding on your network, and this project has not verified the article."
        )
        matches = item.get("smb_matches") or []
        if matches:
            action = (
                "If you use "
                + ", ".join(matches)
                + ", read the article and ask whoever looks after your IT whether you need to patch or change a setting."
            )
        else:
            action = "Read it only if it names software you use. It did not match the small-business list."
        return Summary(text, action, self.name)


def get_summariser(name: str | None = None) -> Summariser:
    """Return a summariser by name. Only `rules-v1` is shipped."""
    chosen = (name or "rules-v1").strip().lower()
    if chosen in {"rules-v1", "rules", "fallback"}:
        return RuleBasedSummariser()
    raise LookupError(
        f"Summariser {name!r} is not available. This version ships only the no-AI "
        "fallback 'rules-v1'. No language model is called."
    )


def _product_label(item: dict) -> str:
    vendor = (item.get("vendor") or "").strip()
    product = (item.get("product") or "").strip()
    if vendor and product:
        if product.lower().startswith(vendor.lower()):
            return product
        return f"{vendor} {product}"
    return product or vendor or "the affected software"


def _first_sentence(text: str) -> str:
    cleaned = " ".join(text.split())
    if not cleaned:
        return ""
    for mark in (". ", "? ", "! "):
        index = cleaned.find(mark)
        if 0 <= index <= 280:
            return cleaned[: index + 1]
    if len(cleaned) > 280:
        return cleaned[:279].rstrip() + "…"
    return cleaned


def _what_to_do_cve(item: dict, subject: str) -> str:
    matches = item.get("smb_matches") or []
    cvss = float(item["cvss"]) if item.get("cvss") is not None else 0.0
    if item.get("in_kev") and matches:
        return (
            f"If you use {subject}, install the vendor update this week. "
            "Until it is patched, keep it off the public internet if you can. "
            "Ask your IT person to confirm the version afterwards. "
            "If you do not use it, you can skip this item."
        )
    if item.get("in_kev"):
        return (
            f"If you use {subject}, apply the vendor update. "
            "CISA lists this as already exploited. If you do not use it, you can skip this item."
        )
    if matches and cvss >= 7:
        return (
            f"Check whether you run {subject}. If you do, install the vendor update and confirm the version. "
            "If you do not run it, no action is needed for this item."
        )
    if item.get("epss") is not None and float(item["epss"]) >= 0.1:
        return (
            f"Update {subject} when the vendor patch is available. "
            "Take a backup first if this system holds customer or payment data."
        )
    return f"No urgent action unless you actually use {subject}. Keep the vendor's automatic updates turned on."
