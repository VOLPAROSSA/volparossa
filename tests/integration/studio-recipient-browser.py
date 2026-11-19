# SPDX-License-Identifier: GPL-3.0-only
"""Inspect the republished Studio site with Firefox in the recipient's network namespace."""

import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time


RUNTIME = Path("/opt/volparossa-studio-browser")
PAGE = "/studio-export.html"
CHART = "/assets/studio-topology.png"
MARKER = "VOLPAROSSA Studio manual export 20261022"

# Execute in the ordinary web content context. Only fixed booleans cross the
# Marionette boundary; the page cannot supply a path, executable or command.
OBSERVE = """
const [pageUrl, marker, chartPath, done] = arguments;
(async () => {
  if (location.href !== pageUrl || document.readyState !== 'complete') return false;
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  const matches = [];
  for (let text; (text = walker.nextNode()); ) {
    if (text.textContent.trim() === marker) matches.push(text.parentElement);
  }
  const visible = el => {
    el.scrollIntoView({block:'center',inline:'center',behavior:'instant'});
    const box = el.getBoundingClientRect(), css = getComputedStyle(el);
    const x = (Math.max(0, box.left) + Math.min(innerWidth, box.right)) / 2;
    const y = (Math.max(0, box.top) + Math.min(innerHeight, box.bottom)) / 2;
    return box.width > 0 && box.height > 0 && css.visibility === 'visible' &&
      el.checkVisibility({opacityProperty:true, visibilityProperty:true}) &&
      el.contains(document.elementFromPoint(x, y));
  };
  if (matches.length !== 1 || !visible(matches[0]) ||
      getComputedStyle(matches[0]).fontSize !== '37px') return false;
  const url = new URL(chartPath, pageUrl).href;
  const images = [...document.images].filter(el => el.currentSrc === url);
  if (images.length !== 1) return false;
  const image = images[0];
  await image.decode();
  return image.complete && image.naturalWidth === 1024 && image.naturalHeight === 768 && visible(image);
})().then(done, () => done(false));
"""


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def page_url(url, expected):
    host = url.hostname or ""
    require(url.scheme == "http" and re.fullmatch(r"vp[0-9a-f]{32}\.localhost", host)
            and url.port is not None and 0 < url.port <= 65535 and url.netloc == f"{host}:{url.port}"
            and url.path == "/" and not url.query and not url.fragment, "unexpected renderer origin")
    require(PAGE in expected["assets"] and CHART in expected["assets"], "signed renderer assets absent")
    return f"http://{url.netloc}{PAGE}"


def launch(work):
    # The caller has already restricted the worker UID to loopback in this
    # guest namespace. Keep the shared network and give Firefox a private PID
    # namespace and private filesystem, without the agent's socket or cache.
    return subprocess.Popen([
        "/usr/bin/bwrap", "--unshare-user", "--uid", str(os.getuid()), "--gid", str(os.getgid()),
        "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--die-with-parent", "--new-session",
        "--cap-drop", "ALL", "--ro-bind", "/usr", "/usr", "--ro-bind", "/etc", "/etc",
        "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
        "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/run",
        "--ro-bind", str(RUNTIME / "build/firefox-esr"), "/firefox",
        "--bind", str(work), "/state", "--chdir", "/state", "--",
        "/firefox/firefox-esr", "--headless", "--no-remote", "--new-instance",
        "--profile", "/state/profile", "--marionette", "about:blank",
    ], env={"PATH": "/usr/bin:/bin", "HOME": "/state/home", "XDG_RUNTIME_DIR": "/state/runtime",
            "XDG_CONFIG_HOME": "/state/config", "XDG_CACHE_HOME": "/state/cache", "TMPDIR": "/tmp",
            "MOZ_NO_REMOTE": "1", "MOZ_HEADLESS": "1", "MOZ_CRASHREPORTER_DISABLE": "1"},
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def connect(browser, port, deadline):
    # Use the same bounded protocol implementation as the pinned KVM Browser fixture.
    sys.path.insert(0, str(RUNTIME / "scripts"))
    try:
        from smoke_privacy import Marionette
    finally:
        sys.path.pop(0)
    while time.monotonic() < deadline and browser.poll() is None:
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=0.5)
        except (ConnectionRefusedError, TimeoutError):
            time.sleep(0.1)
            continue
        try:
            sock.settimeout(4)
            return sock, Marionette(sock)
        except BaseException:
            sock.close()
            raise
    raise ValueError("studio_recipient_browser_start")


def observe_page(driver, target):
    caps = driver.command("WebDriver:NewSession", {"capabilities": {"alwaysMatch":
        {"browserName": "firefox", "acceptInsecureCerts": False}}})["capabilities"]
    require(caps["browserName"] == "firefox" and caps["browserVersion"] == "140.16.0"
            and caps["moz:profile"] == "/state/profile", "unexpected recipient browser")
    driver.command("Marionette:SetContext", {"value": "content"})
    driver.command("WebDriver:SetTimeouts", {"pageLoad": 9000, "script": 5500})
    driver.command("WebDriver:Navigate", {"url": target})
    observed = driver.command("WebDriver:ExecuteAsyncScript", {
        "script": OBSERVE, "args": [target, MARKER, CHART], "newSandbox": True,
    })
    require(observed.get("value") is True, "recipient render did not match signed Studio page")


def verify_browser(url, expected, directory):
    target = page_url(url, expected)
    directory = Path(directory)
    require(os.getuid() != 0 and directory.name == "site-viewer" and directory.resolve() == directory
            and directory.stat().st_uid == os.getuid() and stat.S_IMODE(directory.stat().st_mode) == 0o700,
            "private recipient directory required")
    with tempfile.TemporaryDirectory(prefix="studio-browser-", dir=directory) as temporary:
        work = Path(temporary)
        for child in ("profile", "home", "runtime", "config", "cache"):
            (work / child).mkdir(mode=0o700)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        preferences = {"marionette.port": port, "network.trr.mode": 5,
                       "network.proxy.type": 0, "browser.cache.disk.enable": False,
                       "datareporting.policy.dataSubmissionEnabled": False}
        (work / "profile/user.js").write_text("".join(
            f"user_pref({json.dumps(k)}, {json.dumps(v)});\n" for k, v in preferences.items()), encoding="ascii")
        browser = launch(work)
        try:
            sock, driver = connect(browser, port, time.monotonic() + 22)
            with sock:
                sock.settimeout(12)
                observe_page(driver, target)
                driver.command("Marionette:Quit", {"flags": ["eAttemptQuit"]})
            require(browser.wait(timeout=6) == 0, "recipient browser did not close cleanly")
        except (OSError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError):
            # The pinned client includes remote diagnostics in exceptions.
            raise ValueError("studio_recipient_browser_protocol") from None
        finally:
            # bwrap's PID namespace is destroyed when its leader exits, also on failure.
            if browser.poll() is None:
                browser.kill()
                browser.wait(timeout=4)
    require(not work.exists(), "recipient browser profile survived cleanup")
    return dict(engine="firefox-esr", version="140.16.0", edited_page=True, visible_marker=True,
                computed_37px=True, chart_decoded=True, chart_width=1024, chart_height=768,
                browser_closed=True, profile_removed=True)
