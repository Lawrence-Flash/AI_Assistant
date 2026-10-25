"""Turn recorded feed payloads into plain records. No network calls."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import datetime
from email.utils import parsedate_to_datetime

from collector.textutil import clip, extract_cve_ids, strip_html

CVSS_FIELDS = (
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)


def parse_kev(payload: dict) -> list[dict]:
    records = []
    for entry in payload.get("vulnerabilities") or []:
        cve_id = (entry.get("cveID") or "").upper()
        if not cve_id:
            continue
        records.append(
            {
                "cve_id": cve_id,
                "kind": "cve",
                "title": entry.get("vulnerabilityName") or cve_id,
                "vendor": entry.get("vendorProject") or "",
                "product": entry.get("product") or "",
                "description": entry.get("shortDescription") or "",
                "published": entry.get("dateAdded") or "",
                "kev_date_added": entry.get("dateAdded") or "",
                "in_kev": True,
                "ransomware": entry.get("knownRansomwareCampaignUse") or "Unknown",
                "kev_required_action": entry.get("requiredAction") or "",
                "cvss": None,
                "cvss_version": None,
                "severity": None,
                "version_ranges": [],
                "references": [],
                "aliases": [],
            }
        )
    return records


def parse_nvd(payload: dict, max_ranges: int = 40, description_limit: int = 500) -> list[dict]:
    records = []
    for wrapper in payload.get("vulnerabilities") or []:
        cve = wrapper.get("cve") or wrapper
        cve_id = (cve.get("id") or "").upper()
        if not cve_id:
            continue
        cvss, version, severity = _cvss(cve.get("metrics") or {})
        description = _english(cve.get("descriptions") or [])
        ranges, aliases = _configurations(cve.get("configurations") or [], max_ranges)
        vendor, product = _identity(aliases)
        kev_date = cve.get("cisaExploitAdd") or ""
        records.append(
            {
                "cve_id": cve_id,
                "kind": "cve",
                "title": clip(description, 140) or cve_id,
                "vendor": vendor,
                "product": product,
                "description": clip(description, description_limit),
                "published": cve.get("published") or "",
                "kev_date_added": kev_date,
                "in_kev": bool(kev_date),
                "ransomware": "Unknown",
                "kev_required_action": cve.get("cisaRequiredAction") or "",
                "cvss": cvss,
                "cvss_version": version,
                "severity": severity or _severity_from_score(cvss),
                "version_ranges": ranges,
                "references": _references(cve.get("references") or []),
                "aliases": aliases,
            }
        )
    return records


def parse_epss(payload: dict) -> dict[str, dict]:
    scores: dict[str, dict] = {}
    for row in payload.get("data") or []:
        cve_id = (row.get("cve") or "").upper()
        if not cve_id:
            continue
        try:
            probability = float(row.get("epss"))
        except (TypeError, ValueError):
            continue
        probability = min(max(probability, 0.0), 1.0)
        percentile = row.get("percentile")
        try:
            percentile_value = float(percentile) if percentile is not None else None
        except (TypeError, ValueError):
            percentile_value = None
        scores[cve_id] = {
            "epss": probability,
            "percentile": percentile_value,
            "date": row.get("date") or "",
        }
    return scores


def parse_rss(xml_bytes: bytes, source_name: str) -> list[dict]:
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return []
    items = []
    for node in _rss_items(root):
        title = strip_html(_child_text(node, "title"))
        link = _link(node)
        if not title or not link:
            continue
        description = strip_html(_child_text(node, "description") or _child_text(node, "summary"))
        published = _published(node)
        blob = f"{title} {description}"
        items.append(
            {
                "kind": "news",
                "title": title,
                "link": link,
                "source": source_name,
                "description": description,
                "published": published,
                "cve_ids": extract_cve_ids(blob),
            }
        )
    return items


def _cvss(metrics: dict) -> tuple[float | None, str | None, str | None]:
    for field, version in CVSS_FIELDS:
        entries = metrics.get(field) or []
        if not entries:
            continue
        chosen = _prefer_nvd(entries)
        data = chosen.get("cvssData") or {}
        score = data.get("baseScore")
        if score is None:
            continue
        try:
            value = float(score)
        except (TypeError, ValueError):
            continue
        severity = data.get("baseSeverity") or chosen.get("baseSeverity")
        return value, data.get("version") or version, (severity or "").upper() or None
    return None, None, None


def _prefer_nvd(entries: list[dict]) -> dict:
    for entry in entries:
        source = (entry.get("source") or "").lower()
        if source == "nvd@nist.gov" or entry.get("type") == "Primary":
            return entry
    return entries[0]


def _severity_from_score(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _english(descriptions: list[dict]) -> str:
    for item in descriptions:
        if (item.get("lang") or "").lower() == "en" and item.get("value"):
            return item["value"]
    for item in descriptions:
        if item.get("value"):
            return item["value"]
    return ""


def _configurations(configurations: list[dict], max_ranges: int) -> tuple[list[dict], list[dict]]:
    ranges: list[dict] = []
    aliases: list[dict] = []
    seen_alias: set[tuple[str, str]] = set()
    for configuration in configurations:
        for node in configuration.get("nodes") or []:
            if node.get("negate"):
                continue
            for match in node.get("cpeMatch") or []:
                if match.get("vulnerable") is False:
                    continue
                parsed = _cpe(match.get("criteria") or "")
                if parsed is None:
                    continue
                vendor, product, version = parsed
                key = (vendor, product)
                if key not in seen_alias and vendor and product:
                    seen_alias.add(key)
                    aliases.append({"vendor": vendor, "product": product})
                if len(ranges) >= max_ranges:
                    continue
                ranges.append(
                    {
                        "vendor": vendor,
                        "product": product,
                        "version": version,
                        "start_including": match.get("versionStartIncluding") or None,
                        "start_excluding": match.get("versionStartExcluding") or None,
                        "end_including": match.get("versionEndIncluding") or None,
                        "end_excluding": match.get("versionEndExcluding") or None,
                    }
                )
    return ranges, aliases


def _cpe(criteria: str) -> tuple[str, str, str] | None:
    parts = _split_cpe(criteria)
    # cpe:2.3:part:vendor:product:version:...
    if len(parts) < 6 or parts[0] != "cpe":
        return None
    return parts[3].replace("\\", ""), parts[4].replace("\\", ""), parts[5]


def _split_cpe(criteria: str) -> list[str]:
    parts: list[str] = []
    buffer: list[str] = []
    index = 0
    while index < len(criteria):
        char = criteria[index]
        if char == "\\" and index + 1 < len(criteria):
            buffer.append(criteria[index + 1])
            index += 2
            continue
        if char == ":":
            parts.append("".join(buffer))
            buffer = []
        else:
            buffer.append(char)
        index += 1
    parts.append("".join(buffer))
    return parts


def _identity(aliases: list[dict]) -> tuple[str, str]:
    if not aliases:
        return "", ""
    vendor = aliases[0]["vendor"].replace("_", " ")
    product = aliases[0]["product"].replace("_", " ")
    return vendor, product


def _references(references: list[dict]) -> list[dict]:
    output = []
    for item in references[:5]:
        url = item.get("url")
        if url:
            output.append({"label": item.get("source") or "Reference", "url": url})
    return output


def _rss_items(root: ET.Element) -> list[ET.Element]:
    channel = root.find("channel")
    if channel is not None:
        return list(channel.findall("item"))
    atom = "{http://www.w3.org/2005/Atom}"
    return list(root.findall(f"{atom}entry"))


def _child_text(node: ET.Element, name: str) -> str:
    child = node.find(name)
    if child is None:
        atom = "{http://www.w3.org/2005/Atom}"
        child = node.find(f"{atom}{name}")
    if child is None or child.text is None:
        return ""
    return child.text


def _link(node: ET.Element) -> str:
    direct = _child_text(node, "link")
    if direct:
        return direct.strip()
    atom = "{http://www.w3.org/2005/Atom}"
    for child in node.findall(f"{atom}link"):
        href = child.attrib.get("href")
        if href:
            return href.strip()
    return ""


def _published(node: ET.Element) -> str:
    raw = _child_text(node, "pubDate") or _child_text(node, "published") or _child_text(node, "updated")
    if not raw:
        dc = "{http://purl.org/dc/elements/1.1/}date"
        child = node.find(dc)
        raw = child.text if child is not None and child.text else ""
    if not raw:
        return ""
    try:
        parsed = parsedate_to_datetime(raw)
    except (TypeError, ValueError, IndexError):
        parsed = _from_iso(raw)
    if parsed is None:
        return ""
    return parsed.isoformat()


def _from_iso(raw: str) -> datetime | None:
    text = raw.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None
