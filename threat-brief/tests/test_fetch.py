"""Backoff tests with a fake opener. No network."""

from __future__ import annotations

import os
import sys
import unittest
import urllib.error
from email.message import Message

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from collector.fetch import FetchError, fetch_bytes


class Response:
    def __init__(self, payload: bytes):
        self.payload = payload

    def read(self):
        return self.payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FetchTests(unittest.TestCase):
    def test_retries_429_then_succeeds(self):
        calls = {"n": 0}
        sleeps = []

        def opener(request, timeout):
            calls["n"] += 1
            if calls["n"] < 3:
                headers = Message()
                headers["Retry-After"] = "0"
                raise urllib.error.HTTPError(request.full_url, 429, "slow down", headers, None)
            return Response(b"{}")

        payload = fetch_bytes("https://example.test/cves", opener=opener, sleeper=sleeps.append, max_retries=4)
        self.assertEqual(payload, b"{}")
        self.assertEqual(calls["n"], 3)
        self.assertEqual(sleeps, [0.0, 0.0])

    def test_backoff_without_retry_after(self):
        sleeps = []

        def opener(request, timeout):
            if len(sleeps) < 2:
                raise urllib.error.HTTPError(request.full_url, 503, "unavailable", Message(), None)
            return Response(b"ok")

        payload = fetch_bytes("https://example.test/kev", opener=opener, sleeper=sleeps.append, max_retries=4)
        self.assertEqual(payload, b"ok")
        self.assertEqual(sleeps, [6.0, 12.0])

    def test_other_http_errors_are_not_retried(self):
        calls = {"n": 0}

        def opener(request, timeout):
            calls["n"] += 1
            raise urllib.error.HTTPError(request.full_url, 404, "missing", Message(), None)

        with self.assertRaises(FetchError):
            fetch_bytes("https://example.test/missing", opener=opener, sleeper=lambda seconds: None, max_retries=4)
        self.assertEqual(calls["n"], 1)


if __name__ == "__main__":
    unittest.main()
