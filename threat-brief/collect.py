#!/usr/bin/env python3
"""Entry point for the threat brief collector.

    python3 threat-brief/collect.py
    python3 threat-brief/collect.py --fixtures

Uses the Python standard library only. It does not read API keys.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from collector.pipeline import main

if __name__ == "__main__":
    raise SystemExit(main())
