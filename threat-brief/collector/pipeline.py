"""Build the brief and the catalog from feed payloads, then write the site files."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path

from collector.config import FIXTURES, SITE_DATA, load_profiles, load_settings
from collector.fetch import FetchError, fetch_bytes, fetch_json
from collector.parse import parse_epss, parse_kev, parse_nvd, parse_rss
from collector.score import score_cve, score_news
from collector.summarise import get_summariser
from collector.textutil import clip

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"

SOURCE_NOTES = [
    {"name": "CISA Known Exploited Vulnerabilities", "url": KEV_URL},
    {"name": "NVD CVE API 2.0", "url": "https://nvd.nist.gov/developers/vulnerabilities"},
    {"name": "FIRST EPSS", "url": "https://www.first.org/epss/"},
]


def build_documents(
    kev_payload: dict | None,
    nvd_payloads: list[dict],
    epss_payload: dict | None,
    news_feeds: list[tuple[str, bytes]],
    settings: dict,
    profiles: list[dict],
    now: datetime | None = None,
    warnings: list[str] | None = None,
    mode: str = "live",
) -> tuple[dict, dict]:
    """Merge, score, summarise, and split into a daily brief plus a match catalog."""
    now = now or datetime.now(timezone.utc)
    warnings = list(warnings or [])
    summariser = get_summariser(settings.get("summariser", "rules-v1"))
    max_ranges = int(settings.get("max_version_ranges", 40))
    description_limit = int(settings.get("max_description_chars", 500))

    kev_records = parse_kev(kev_payload or {})
    nvd_records: list[dict] = []
    for payload in nvd_payloads:
        nvd_records.extend(parse_nvd(payload, max_ranges=max_ranges, description_limit=description_limit))
    epss_map = parse_epss(epss_payload or {})
    news_items: list[dict] = []
    for source_name, xml_bytes in news_feeds:
        news_items.extend(parse_rss(xml_bytes, source_name))

    merged = _merge(kev_records, nvd_records)
    _attach_epss(merged, epss_map)

    cve_items = []
    for record in merged.values():
        scored = score_cve(record, profiles, settings.get("weights"))
        record.update(scored)
        summary = summariser.summarise(record)
        record["summary"] = summary.text
        record["what_to_do"] = summary.what_to_do
        record["summary_engine"] = summary.engine
        record["description"] = clip(record.get("description"), description_limit)
        cve_items.append(record)

    news_scored = []
    for item in news_items:
        if not _is_current(item.get("published"), int(settings.get("news_max_age_days", 7)), now):
            continue
        linked = [cve_id for cve_id in item.get("cve_ids") or [] if cve_id in merged]
        if linked:
            for cve_id in linked:
                merged[cve_id]["references"].append({"label": item.get("source") or "News", "url": item["link"]})
            continue
        scored = score_news(item, profiles, settings.get("news_weights"), settings.get("urgency_terms"))
        if scored["score"] <= 0:
            continue
        item.update(scored)
        item["id"] = "news-" + hashlib.sha256(item["link"].encode("utf-8")).hexdigest()[:12]
        summary = summariser.summarise(item)
        item["summary"] = summary.text
        item["what_to_do"] = summary.what_to_do
        item["summary_engine"] = summary.engine
        item["in_kev"] = False
        item["cvss"] = None
        news_scored.append(item)

    news_scored.sort(key=lambda item: (-item["score"], item["title"]))
    news_scored = news_scored[: int(settings.get("max_news_items", 8))]

    brief_cves = [item for item in cve_items if _in_brief_window(item, settings, now)]
    brief_cves.sort(key=lambda item: (-item["score"], item["cve_id"]))
    brief_cves = brief_cves[: int(settings.get("max_brief_items", 40))]

    items = _public_cve(brief_cves) + _public_news(news_scored)
    catalog_rows = _public_cve(sorted(cve_items, key=lambda item: (-item["score"], item["cve_id"])))

    generated_at = now.astimezone(timezone.utc).isoformat()
    formula = {
        "id": settings.get("formula_id", "smb-sa-v1"),
        "summary": settings.get("formula_summary", ""),
        "weights": settings.get("weights"),
        "news_formula_id": settings.get("news_formula_id"),
        "news_weights": settings.get("news_weights"),
    }
    counts = {
        "catalog_cves": len(catalog_rows),
        "brief_items": len(items),
        "brief_cves": len(brief_cves),
        "brief_news": len(news_scored),
        "kev": len(kev_records),
        "nvd": len(nvd_records),
        "epss": len(epss_map),
    }
    base = {
        "schema_version": 1,
        "generated_at": generated_at,
        "mode": mode,
        "formula": formula,
        "counts": counts,
        "warnings": warnings,
        "sources": SOURCE_NOTES + [{"name": feed["name"], "url": feed["url"]} for feed in settings.get("feeds", [])],
        "matching_note": (
            "Version matching is approximate. It compares dotted version numbers and a flattened, "
            "capped list of NVD CPE ranges. It does not evaluate NVD's AND/OR configuration trees, "
            "and many CISA KEV entries have no version range at all."
        ),
    }
    brief = {
        **base,
        "window": {"nvd_days": settings.get("nvd_days"), "kev_recent_days": settings.get("kev_recent_days")},
        "items": items,
    }
    catalog = {**base, "items": catalog_rows}
    return brief, catalog


def write_documents(brief: dict, catalog: dict, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    _atomic_json(output_dir / "brief.json", brief, pretty=True)
    _atomic_json(output_dir / "catalog.json", catalog, pretty=False)


def collect_live(settings: dict, profiles: list[dict], now: datetime | None = None) -> tuple[dict, dict]:
    now = now or datetime.now(timezone.utc)
    warnings: list[str] = []
    timeout = int(settings.get("request_timeout_seconds", 45))
    retries = int(settings.get("max_retries", 4))

    try:
        kev_payload = fetch_json(KEV_URL, timeout=timeout, max_retries=retries)
    except FetchError as error:
        warnings.append(f"CISA KEV feed failed: {error}")
        kev_payload = None

    nvd_payloads: list[dict] = []
    start, end = _nvd_window(now, int(settings.get("nvd_days", 7)))
    severities = list(settings.get("nvd_severities") or ["CRITICAL", "HIGH"])
    for index, severity in enumerate(severities):
        if index:
            time.sleep(float(settings.get("nvd_delay_seconds", 6)))
        try:
            nvd_payloads.extend(
                _fetch_nvd_pages(start, end, severity, settings, timeout, retries)
            )
        except FetchError as error:
            warnings.append(f"NVD {severity} feed failed: {error}. The brief continues without that slice.")

    kev_records = parse_kev(kev_payload or {})
    nvd_records: list[dict] = []
    for payload in nvd_payloads:
        nvd_records.extend(parse_nvd(payload))
    epss_ids = _epss_ids(kev_records, nvd_records, settings, now)
    epss_payload = {"data": []}
    if epss_ids:
        try:
            epss_payload = _fetch_epss(epss_ids, settings, timeout, retries)
        except FetchError as error:
            warnings.append(f"FIRST EPSS feed failed: {error}. Scores that need EPSS will show 0 for that part.")

    news_feeds: list[tuple[str, bytes]] = []
    for feed in settings.get("feeds") or []:
        try:
            body = fetch_bytes(feed["url"], timeout=timeout, max_retries=retries)
            news_feeds.append((feed.get("name") or feed["url"], body))
        except FetchError as error:
            warnings.append(f"RSS feed {feed.get('name') or feed.get('url')} failed: {error}")

    if not kev_records and not nvd_records:
        raise FetchError("No vulnerability data was collected. Existing site files were left unchanged.")

    return build_documents(
        kev_payload,
        nvd_payloads,
        epss_payload,
        news_feeds,
        settings,
        profiles,
        now=now,
        warnings=warnings,
        mode="live",
    )


def collect_fixtures(settings: dict, profiles: list[dict], fixtures: Path = FIXTURES) -> tuple[dict, dict]:
    kev = json.loads((fixtures / "kev_sample.json").read_text(encoding="utf-8"))
    nvd = json.loads((fixtures / "nvd_sample.json").read_text(encoding="utf-8"))
    epss = json.loads((fixtures / "epss_sample.json").read_text(encoding="utf-8"))
    rss = (fixtures / "rss_sample.xml").read_bytes()
    now = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
    return build_documents(
        kev,
        [nvd],
        epss,
        [("Example Security", rss)],
        settings,
        profiles,
        now=now,
        warnings=["Built from recorded fixtures. This is not a live feed."],
        mode="fixtures",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect the security threat brief. No API key and no paid service.")
    parser.add_argument("--fixtures", action="store_true", help="Build from the recorded sample fixtures. Does not use the network.")
    parser.add_argument("--days", type=int, default=None, help="Override how many days of NVD CVEs to request.")
    parser.add_argument("--output", type=Path, default=SITE_DATA, help="Directory for brief.json and catalog.json.")
    args = parser.parse_args(argv)

    settings = load_settings()
    profiles = load_profiles()
    if args.days is not None:
        settings["nvd_days"] = args.days

    try:
        if args.fixtures:
            brief, catalog = collect_fixtures(settings, profiles)
        else:
            brief, catalog = collect_live(settings, profiles)
    except FetchError as error:
        print(error, file=sys.stderr)
        return 1

    write_documents(brief, catalog, args.output)
    print(
        f"Wrote {args.output / 'brief.json'} and {args.output / 'catalog.json'} "
        f"({brief['counts']['brief_items']} brief items, {brief['counts']['catalog_cves']} catalog CVEs, mode={brief['mode']})."
    )
    for warning in brief["warnings"]:
        print(f"warning: {warning}")
    return 0


def _merge(kev_records: list[dict], nvd_records: list[dict]) -> dict[str, dict]:
    merged: dict[str, dict] = {}
    for record in kev_records:
        merged[record["cve_id"]] = record
    for record in nvd_records:
        current = merged.get(record["cve_id"])
        if current is None:
            merged[record["cve_id"]] = record
            continue
        if current.get("cvss") is None:
            current["cvss"] = record.get("cvss")
            current["cvss_version"] = record.get("cvss_version")
            current["severity"] = record.get("severity")
        if record.get("version_ranges"):
            current["version_ranges"] = record["version_ranges"]
        if record.get("aliases"):
            current["aliases"] = record["aliases"]
        if not current.get("published") or _looks_like_day(current.get("published")):
            if record.get("published"):
                current["published"] = record["published"]
        if not current.get("description"):
            current["description"] = record.get("description") or ""
        current["in_kev"] = True
        for reference in record.get("references") or []:
            current["references"].append(reference)
    return merged


def _attach_epss(merged: dict[str, dict], epss_map: dict[str, dict]) -> None:
    for cve_id, record in merged.items():
        score = epss_map.get(cve_id)
        if not score:
            record["epss"] = None
            record["epss_percentile"] = None
            continue
        record["epss"] = score["epss"]
        record["epss_percentile"] = score.get("percentile")


def _epss_ids(kev_records: list[dict], nvd_records: list[dict], settings: dict, now: datetime) -> list[str]:
    """Ask FIRST only about recent NVD CVEs and KEV entries added in the recent window."""
    ids = {record["cve_id"] for record in nvd_records}
    window = int(settings.get("kev_recent_days", 30))
    for record in kev_records:
        if _is_current(record.get("kev_date_added"), window, now):
            ids.add(record["cve_id"])
    return sorted(ids)


def _fetch_nvd_pages(start: str, end: str, severity: str, settings: dict, timeout: int, retries: int) -> list[dict]:
    page_size = int(settings.get("nvd_page_size", 2000))
    delay = float(settings.get("nvd_delay_seconds", 6))
    start_index = 0
    pages = []
    while True:
        params = {
            "pubStartDate": start,
            "pubEndDate": end,
            "resultsPerPage": page_size,
            "startIndex": start_index,
            "cvssV3Severity": severity,
        }
        url = NVD_URL + "?" + urllib.parse.urlencode(params)
        payload = fetch_json(url, timeout=timeout, max_retries=retries)
        pages.append(payload)
        total = int(payload.get("totalResults") or 0)
        returned = int(payload.get("resultsPerPage") or page_size)
        start_index += returned
        if start_index >= total or returned == 0:
            return pages
        time.sleep(delay)


def _fetch_epss(cve_ids: list[str], settings: dict, timeout: int, retries: int) -> dict:
    batch_size = int(settings.get("epss_batch_size", 100))
    delay = float(settings.get("epss_delay_seconds", 1))
    rows: list[dict] = []
    for index in range(0, len(cve_ids), batch_size):
        if index:
            time.sleep(delay)
        batch = cve_ids[index : index + batch_size]
        url = EPSS_URL + "?cve=" + ",".join(batch)
        payload = fetch_json(url, timeout=timeout, max_retries=retries)
        rows.extend(payload.get("data") or [])
    return {"data": rows}


def _nvd_window(now: datetime, days: int) -> tuple[str, str]:
    end = now.astimezone(timezone.utc).replace(microsecond=0)
    start = end - timedelta(days=days)
    return _nvd_stamp(start), _nvd_stamp(end)


def _nvd_stamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S.000")


def _in_brief_window(item: dict, settings: dict, now: datetime) -> bool:
    if _is_current(item.get("published"), int(settings.get("nvd_days", 7)), now):
        return True
    if item.get("in_kev") and _is_current(item.get("kev_date_added"), int(settings.get("kev_recent_days", 30)), now):
        return True
    return False


def _is_current(raw: str | None, days: int, now: datetime) -> bool:
    """True only when the timestamp parses and falls inside the window. Undated items are left out."""
    parsed = _parse_time(raw)
    if parsed is None:
        return False
    return parsed >= (now - timedelta(days=days))


def _parse_time(raw: str | None) -> datetime | None:
    if not raw:
        return None
    text = raw.strip()
    if len(text) == 10:
        text = text + "T00:00:00+00:00"
    text = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _looks_like_day(value: str | None) -> bool:
    return bool(value) and len(value) == 10


def _public_cve(items: list[dict]) -> list[dict]:
    public = []
    for item in items:
        public.append(
            {
                "id": item["cve_id"],
                "kind": "cve",
                "cve_id": item["cve_id"],
                "title": item.get("title") or item["cve_id"],
                "vendor": item.get("vendor") or "",
                "product": item.get("product") or "",
                "published": item.get("published") or "",
                "kev_date_added": item.get("kev_date_added") or "",
                "description": item.get("description") or "",
                "cvss": item.get("cvss"),
                "cvss_version": item.get("cvss_version"),
                "severity": item.get("severity"),
                "in_kev": bool(item.get("in_kev")),
                "ransomware": item.get("ransomware") or "Unknown",
                "epss": item.get("epss"),
                "epss_percentile": item.get("epss_percentile"),
                "smb_matches": item.get("smb_matches") or [],
                "formula_id": item.get("formula_id"),
                "score": item.get("score"),
                "score_components": item.get("score_components") or {},
                "reasons": item.get("reasons") or [],
                "summary": item.get("summary") or "",
                "what_to_do": item.get("what_to_do") or "",
                "summary_engine": item.get("summary_engine") or "",
                "references": _unique_refs(item.get("references") or []),
                "version_ranges": item.get("version_ranges") or [],
                "aliases": item.get("aliases") or [],
            }
        )
    return public


def _public_news(items: list[dict]) -> list[dict]:
    public = []
    for item in items:
        public.append(
            {
                "id": item["id"],
                "kind": "news",
                "cve_id": None,
                "title": item.get("title") or "",
                "vendor": "",
                "product": "",
                "published": item.get("published") or "",
                "description": item.get("description") or "",
                "source": item.get("source") or "",
                "cvss": None,
                "severity": None,
                "in_kev": False,
                "epss": None,
                "smb_matches": item.get("smb_matches") or [],
                "formula_id": item.get("formula_id"),
                "score": item.get("score"),
                "score_components": item.get("score_components") or {},
                "reasons": item.get("reasons") or [],
                "summary": item.get("summary") or "",
                "what_to_do": item.get("what_to_do") or "",
                "summary_engine": item.get("summary_engine") or "",
                "references": [{"label": item.get("source") or "Article", "url": item.get("link")}],
                "version_ranges": [],
                "aliases": [],
            }
        )
    return public


def _unique_refs(references: list[dict]) -> list[dict]:
    seen = set()
    output = []
    for item in references:
        url = item.get("url")
        if not url or url in seen:
            continue
        seen.add(url)
        output.append({"label": item.get("label") or "Reference", "url": url})
        if len(output) == 6:
            break
    return output


def _atomic_json(path: Path, payload: dict, pretty: bool) -> None:
    if pretty:
        text = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    else:
        text = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(path)
