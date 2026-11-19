#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Focused checks of recipient origin selection and native renderer evidence."""
import runpy
from pathlib import Path
import unittest
from unittest.mock import Mock
from urllib.parse import urlsplit


renderer = runpy.run_path(str(Path(__file__).with_name("studio-recipient-browser.py")))
HOST = "vp" + "1" * 32 + ".localhost"
ORIGIN = f"http://{HOST}:31301/"
ASSETS = {"assets": {"/studio-export.html": {}, "/assets/studio-topology.png": {}}}
CAPS = {"browserName": "firefox", "browserVersion": "140.16.0", "moz:profile": "/state/profile"}


class RecipientRendererTests(unittest.TestCase):
    def test_only_signed_assets_at_exact_ready_loopback_origin_can_be_navigated(self):
        self.assertEqual(renderer["page_url"](urlsplit(ORIGIN), ASSETS), ORIGIN + "studio-export.html")
        for candidate in (ORIGIN.replace("http:", "https:"), ORIGIN + "index.html", ORIGIN + "?a",
                          ORIGIN.replace(HOST, "localhost"), ORIGIN.replace(HOST, "user@" + HOST),
                          ORIGIN.replace(HOST, HOST + ".example"), ORIGIN.replace(":31301", "")):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                renderer["page_url"](urlsplit(candidate), ASSETS)
        with self.assertRaises(ValueError):
            renderer["page_url"](urlsplit(ORIGIN), {"assets": {"/index.html": {}}})

    def test_all_rendered_checks_must_pass_in_web_content_context(self):
        for result in (True, False, 1, None):
            driver = Mock()
            driver.command.side_effect = [{"capabilities": CAPS}, {}, {}, {}, {"value": result}]
            if result is True:
                renderer["observe_page"](driver, ORIGIN + "studio-export.html")
            else:
                with self.assertRaises(ValueError):
                    renderer["observe_page"](driver, ORIGIN + "studio-export.html")
            self.assertEqual(driver.command.call_args_list[1].args, ("Marionette:SetContext", {"value": "content"}))
            name, arguments = driver.command.call_args.args
            self.assertEqual(name, "WebDriver:ExecuteAsyncScript")
            self.assertNotIn("sandbox", arguments)
            self.assertEqual(arguments["args"], [ORIGIN + "studio-export.html", renderer["MARKER"], renderer["CHART"]])

    def test_rejects_other_runtime_and_profile_before_navigation(self):
        for change in ({"browserName": "chrome"}, {"browserVersion": "141"}, {"moz:profile": "/old/profile"}):
            driver = Mock()
            driver.command.return_value = {"capabilities": dict(CAPS, **change)}
            with self.subTest(change=change), self.assertRaises(ValueError):
                renderer["observe_page"](driver, ORIGIN + "studio-export.html")
            self.assertEqual(driver.command.call_count, 1)


if __name__ == "__main__":
    unittest.main()
