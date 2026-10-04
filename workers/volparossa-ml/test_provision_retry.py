#!/usr/bin/env python3
"""Small stdlib-only downloads; no Internet, models, installs or runtime imports."""
import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock
import urllib.error

SPEC = importlib.util.spec_from_file_location("provision_retry", Path(__file__).with_name("provision.py"))
PROVISION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROVISION)
BODY = b"public pinned fixture bytes"
URL = "https://files.pythonhosted.org/packages/fixture.whl"
ITEM = dict(url=URL, bytes=len(BODY), sha256=hashlib.sha256(BODY).hexdigest())


class Response(io.BytesIO):
    url = URL

    def __init__(self, partial_timeout=False):
        super().__init__(BODY)
        self.headers = {"Content-Length": str(len(BODY))}
        self.partial_timeout = partial_timeout
        self.reads = 0

    def read(self, size=-1):
        self.reads += 1
        if self.partial_timeout:
            if self.reads > 1:
                raise TimeoutError("synthetic network timeout")
            size = min(size, 4)
        return super().read(size)


class RetryTests(unittest.TestCase):
    def test_timeout_restarts_partial_file_and_verifies_complete_original_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "fixture.whl"
            partial = Response(partial_timeout=True)
            def second(*_args, **_kwargs):
                self.assertFalse(target.exists())
                return Response()
            opener = mock.Mock()
            # The third attempt observes that failed partial data was removed.
            calls = 0
            def attempt(*args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 1: return partial
                if calls == 2: raise urllib.error.URLError(TimeoutError("timeout"))
                return second(*args, **kwargs)
            opener.open.side_effect = attempt
            with mock.patch.object(PROVISION.time, "sleep") as sleep:
                PROVISION.download(ITEM, target, opener, time.monotonic() + 60)
            self.assertEqual(sleep.call_args_list, [mock.call(1), mock.call(2)])
            self.assertEqual(opener.open.call_count, 3)
            self.assertTrue(partial.closed)
            self.assertEqual(target.read_bytes(), BODY)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_repeated_timeout_is_bounded_and_deadline_is_not_extended(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "fixture.whl"
            for remaining, expected in [(60, 3), (.5, 1)]:
                opener = mock.Mock()
                opener.open.side_effect = TimeoutError("synthetic network timeout")
                with mock.patch.object(PROVISION.time, "sleep"), self.assertRaises(TimeoutError):
                    PROVISION.download(ITEM, target, opener, time.monotonic() + remaining)
                self.assertEqual(opener.open.call_count, expected)
                self.assertFalse(target.exists())
                self.assertTrue(all(0 < call.kwargs["timeout"] <= min(30, remaining)
                                    for call in opener.open.call_args_list))

    def test_invalid_bytes_refusals_and_existing_destinations_are_never_retried(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "fixture.whl"
            for error in [
                urllib.error.HTTPError(URL, 429, "rate limit", {}, None),
                urllib.error.HTTPError(URL, 403, "forbidden", {}, None),
                urllib.error.URLError("certificate or unsupported endpoint"),
            ]:
                opener = mock.Mock(); opener.open.side_effect = error
                with mock.patch.object(PROVISION.time, "sleep") as sleep, self.assertRaises(urllib.error.URLError):
                    PROVISION.download(ITEM, target, opener, time.monotonic() + 60)
                self.assertEqual(opener.open.call_count, 1); sleep.assert_not_called()
            opener = mock.Mock(); opener.open.side_effect = lambda *_a, **_k: Response()
            with mock.patch.object(PROVISION.time, "sleep") as sleep, self.assertRaises(PROVISION.ProvisionError):
                PROVISION.download(dict(ITEM, sha256="0" * 64), target, opener, time.monotonic() + 60)
            self.assertEqual(opener.open.call_count, 1); sleep.assert_not_called()
            self.assertFalse(target.exists())
            target.write_bytes(b"existing owner data")
            opener.open.reset_mock()
            with self.assertRaises(FileExistsError):
                PROVISION.download(ITEM, target, opener, time.monotonic() + 60)
            self.assertEqual(opener.open.call_count, 1)
            self.assertEqual(target.read_bytes(), b"existing owner data")


if __name__ == "__main__":
    unittest.main()
