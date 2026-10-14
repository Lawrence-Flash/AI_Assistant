"""Match a software inventory to catalog CVEs.

The same rules are reimplemented in site/js/match.js so the check can run
in the browser. Tests cover this module; the JS tests cover the port.

Version comparison is approximate: dotted numbers, missing parts treated as
0 (so 1.0 equals 1.0.0). NVD AND/OR configuration trees are not evaluated.
Ranges are a flattened, capped list of vulnerable CPE matches.
"""

from __future__ import annotations

import csv
import io
import re

from collector.textutil import contains_phrase, normalise

GENERIC_PRODUCTS = {"core", "firmware", "http server"}
GENERIC_PREFIX = "multiple"

HEADER_ALIASES = {
    "name": "name",
    "product": "name",
    "software": "name",
    "asset": "name",
    "application": "name",
    "vendor": "vendor",
    "publisher": "vendor",
    "manufacturer": "vendor",
    "supplier": "vendor",
    "version": "version",
    "ver": "version",
    "product_version": "version",
    "product version": "version",
}


def parse_inventory_csv(text: str) -> list[dict]:
    """Read a CSV with a name column and optional vendor and version columns."""
    sample = text.lstrip("\ufeff")
    if not sample.strip():
        raise ValueError("The inventory CSV is empty.")
    reader = csv.DictReader(io.StringIO(sample))
    if not reader.fieldnames:
        raise ValueError("The inventory CSV needs a header row with a name column.")
    mapping: dict[str, str] = {}
    for header in reader.fieldnames:
        key = normalise(header)
        if key in HEADER_ALIASES:
            mapping[header] = HEADER_ALIASES[key]
    if "name" not in mapping.values():
        raise ValueError("The inventory CSV needs a column named name, product, or software.")
    rows = []
    for index, raw in enumerate(reader, start=2):
        item = {"name": "", "vendor": "", "version": "", "line": index}
        for header, field in mapping.items():
            value = (raw.get(header) or "").strip()
            if value and not item[field]:
                item[field] = value
        if not item["name"] and not item["vendor"]:
            continue
        if not item["name"]:
            raise ValueError(f"Row {index} is missing a product name.")
        rows.append(item)
    if not rows:
        raise ValueError("The inventory CSV has headers but no data rows.")
    return rows


def match_inventory(rows: list[dict], catalog: list[dict]) -> dict:
    """Return a prioritised patch list and the rows whose version sat outside the ranges."""
    affected = []
    cleared = []
    for row in rows:
        for item in catalog:
            if item.get("kind") not in (None, "cve"):
                continue
            if not record_matches_row(row, item):
                continue
            confidence = _confidence(row, item)
            entry = {
                "inventory": {"name": row.get("name", ""), "vendor": row.get("vendor", ""), "version": row.get("version", "")},
                "cve_id": item.get("cve_id"),
                "title": item.get("title") or item.get("cve_id"),
                "vendor": item.get("vendor") or "",
                "product": item.get("product") or "",
                "score": item.get("score") or 0,
                "kev_date_added": item.get("kev_date_added") or "",
                "published": item.get("published") or "",
                "in_kev": bool(item.get("in_kev")),
                "cvss": item.get("cvss"),
                "smb_matches": item.get("smb_matches") or [],
                "what_to_do": item.get("what_to_do") or "",
                "summary": item.get("summary") or "",
                "reasons": item.get("reasons") or [],
                "confidence": confidence,
                "confidence_label": CONFIDENCE_LABELS.get(confidence, confidence),
            }
            if confidence == "version_outside":
                cleared.append(entry)
            else:
                affected.append(entry)
    affected.sort(key=lambda entry: (-float(entry["score"]), _older_first(entry), entry["cve_id"] or "", entry["inventory"]["name"]))
    cleared.sort(key=lambda entry: (entry["inventory"]["name"], entry["cve_id"] or ""))
    return {"affected": affected, "cleared": cleared}


CONFIDENCE_LABELS = {
    "version_in_range": "Version looks inside a published range. This check is approximate.",
    "version_exact": "Version matches a published CPE version. This check is approximate.",
    "name_only": "The name matches, but the feed has no usable version range. Confirm it yourself. This match is approximate.",
    "version_outside": "The version sits outside the published ranges we checked. This can be wrong.",
}


def record_matches_row(row: dict, item: dict) -> bool:
    if _vendors_contradict(row.get("vendor") or "", item):
        return False
    candidates = _product_candidates(item)
    inventory_name = row.get("name") or ""
    for candidate in candidates:
        if _products_compatible(inventory_name, candidate):
            return True
        if _is_generic(candidate) and _vendor_in_row(item.get("vendor") or "", row):
            return True
    for alias in item.get("aliases") or []:
        if _vendors_contradict(row.get("vendor") or "", {"vendor": alias.get("vendor") or "", "aliases": []}):
            continue
        product = (alias.get("product") or "").replace("_", " ")
        if _products_compatible(inventory_name, product):
            return True
        if _is_generic(product) and _vendor_in_row(alias.get("vendor") or item.get("vendor") or "", row):
            return True
    return False


def _older_first(entry: dict) -> str:
    """Turn an ISO date into a key that sorts newer dates first. Undated rows go last."""
    raw = entry.get("kev_date_added") or entry.get("published") or ""
    digits = "".join(char for char in raw if char.isdigit())
    if not digits:
        return "9"
    return "".join(str(9 - int(char)) for char in digits)


def cmp_version(left: str, right: str) -> int:
    """Return -1, 0, or 1. Missing numeric parts compare as 0."""
    a = _version_parts(left)
    b = _version_parts(right)
    length = max(len(a), len(b))
    for index in range(length):
        aa = a[index] if index < len(a) else 0
        bb = b[index] if index < len(b) else 0
        if type(aa) is not type(bb):
            aa, bb = str(aa), str(bb)
        if aa < bb:
            return -1
        if aa > bb:
            return 1
    return 0


def version_in_bounds(version: str, rng: dict) -> bool:
    if rng.get("start_including") and cmp_version(version, rng["start_including"]) < 0:
        return False
    if rng.get("start_excluding") and cmp_version(version, rng["start_excluding"]) <= 0:
        return False
    if rng.get("end_including") and cmp_version(version, rng["end_including"]) > 0:
        return False
    if rng.get("end_excluding") and cmp_version(version, rng["end_excluding"]) >= 0:
        return False
    return True


def _confidence(row: dict, item: dict) -> str:
    version = (row.get("version") or "").strip()
    relevant = _relevant_ranges(row, item)
    if not version or not relevant:
        return "name_only"
    outcomes = [_range_outcome(version, rng) for rng in relevant]
    if "in" in outcomes:
        return "version_in_range"
    if "exact" in outcomes:
        return "version_exact"
    if outcomes and all(outcome == "out" for outcome in outcomes):
        return "version_outside"
    return "name_only"


def _range_outcome(version: str, rng: dict) -> str:
    has_bounds = any(rng.get(key) for key in ("start_including", "start_excluding", "end_including", "end_excluding"))
    exact = rng.get("version") or ""
    if has_bounds:
        return "in" if version_in_bounds(version, rng) else "out"
    if exact and exact not in {"*", "-"}:
        return "exact" if cmp_version(version, exact) == 0 else "out"
    return "unknown"


def _relevant_ranges(row: dict, item: dict) -> list[dict]:
    ranges = []
    for rng in item.get("version_ranges") or []:
        product = (rng.get("product") or "").replace("_", " ")
        vendor = rng.get("vendor") or ""
        if _vendors_contradict(row.get("vendor") or "", {"vendor": vendor, "aliases": []}):
            continue
        if _products_compatible(row.get("name") or "", product):
            ranges.append(rng)
            continue
        if _is_generic(product) and _vendor_in_row(vendor, row):
            ranges.append(rng)
    return ranges


def _product_candidates(item: dict) -> list[str]:
    values = [item.get("product") or ""]
    return [value for value in values if normalise(value)]


def _products_compatible(inventory_name: str, product: str) -> bool:
    return contains_phrase(inventory_name, product) or contains_phrase(product, inventory_name)


def _is_generic(product: str) -> bool:
    text = normalise(product)
    return text in GENERIC_PRODUCTS or text.startswith(GENERIC_PREFIX + " ")


def _vendor_in_row(vendor: str, row: dict) -> bool:
    return contains_phrase(row.get("name") or "", vendor) or contains_phrase(row.get("vendor") or "", vendor)


def _vendors_contradict(inventory_vendor: str, item: dict) -> bool:
    if not normalise(inventory_vendor):
        return False
    vendors = [item.get("vendor") or ""]
    vendors.extend(alias.get("vendor") or "" for alias in item.get("aliases") or [])
    concrete = [vendor for vendor in vendors if normalise(vendor)]
    if not concrete:
        return False
    return not any(
        contains_phrase(inventory_vendor, vendor) or contains_phrase(vendor, inventory_vendor) for vendor in concrete
    )


def _version_parts(version: str) -> list:
    parts: list = []
    for chunk in re.split(r"[.\-_+/\s]+", (version or "").strip().lower()):
        if not chunk:
            continue
        for run in re.findall(r"\d+|[a-z]+", chunk):
            parts.append(int(run) if run.isdigit() else run)
    return parts
