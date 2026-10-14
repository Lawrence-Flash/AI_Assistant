"""Load the threat-brief settings and the small-business software list."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = ROOT / "config"
SITE_DATA = ROOT / "site" / "data"
FIXTURES = ROOT / "tests" / "fixtures"


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def load_settings(path: Path | None = None) -> dict:
    return load_json(path or (CONFIG_DIR / "settings.json"))


def load_profiles(path: Path | None = None) -> list[dict]:
    document = load_json(path or (CONFIG_DIR / "smb_software.json"))
    profiles = document.get("profiles") or []
    if not isinstance(profiles, list) or not profiles:
        raise ValueError(f"No software profiles in {path or CONFIG_DIR / 'smb_software.json'}")
    return profiles
