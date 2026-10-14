"""HTTP fetch with backoff. Used by the live collector, never by the tests."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable

USER_AGENT = "threat-brief/1.0 (small-business security awareness; no API key)"
RETRY_STATUS = {403, 429, 503}


class FetchError(RuntimeError):
    """A feed could not be fetched after the allowed retries."""


def fetch_bytes(
    url: str,
    timeout: int = 45,
    max_retries: int = 4,
    opener: Callable = urllib.request.urlopen,
    sleeper: Callable[[float], None] = time.sleep,
) -> bytes:
    """GET a URL. On 403, 429, or 503, wait 6s, 12s, 24s, then 48s and retry.

    NVD's keyless limit is 5 requests per rolling 30 seconds. Callers also
    pause between successful NVD pages. This retry path is for bursts and
    temporary blocks, and it gives up rather than hammering the host.
    """
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    delay = 6.0
    last_error: Exception | None = None
    for attempt in range(max_retries):
        try:
            with opener(request, timeout=timeout) as response:
                return response.read()
        except urllib.error.HTTPError as error:
            last_error = error
            if error.code not in RETRY_STATUS or attempt == max_retries - 1:
                raise FetchError(f"HTTP {error.code} from {url}") from error
            retry_after = _retry_after(error)
            sleeper(retry_after if retry_after is not None else delay)
            delay = min(delay * 2, 60.0)
        except urllib.error.URLError as error:
            last_error = error
            if attempt == max_retries - 1:
                raise FetchError(f"Could not reach {url}: {error.reason}") from error
            sleeper(delay)
            delay = min(delay * 2, 60.0)
    raise FetchError(f"Could not fetch {url}: {last_error}")


def fetch_json(url: str, **kwargs) -> dict:
    raw = fetch_bytes(url, **kwargs)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as error:
        raise FetchError(f"Response from {url} was not JSON") from error
    if not isinstance(payload, dict):
        raise FetchError(f"Response from {url} was not a JSON object")
    return payload


def _retry_after(error: urllib.error.HTTPError) -> float | None:
    header = error.headers.get("Retry-After") if error.headers else None
    if not header:
        return None
    try:
        seconds = float(header)
    except (TypeError, ValueError):
        return None
    if seconds < 0:
        return None
    return min(seconds, 60.0)
