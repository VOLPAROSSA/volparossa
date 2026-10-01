#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Original Files UI against the real owner service inside the disposable guest.

The parent retains the real encrypted catalog/core adapter. This driver starts no
backend and receives its temporary bearer only on stdin. No page/error text leaves it.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time

SOURCE = Path('/opt/volparossa-cloud')
RUNTIME = SOURCE / 'build/firefox-esr'
STAGE = 'input'


def require(value):
    if not value:
        raise ValueError('Cloud UI operation failed')


def read_frame(stream):
    size = bytearray()
    while True:
        byte = stream.recv(1)
        require(bool(byte))
        if byte == b':':
            break
        require(byte.isdigit() and len(size) < 8)
        size.extend(byte)
    require(bool(size))
    length = int(size)
    require(0 < length <= 4 * 1024**2)
    data = bytearray()
    while len(data) < length:
        part = stream.recv(length - len(data))
        require(bool(part))
        data.extend(part)
    return json.loads(data)


def settings(value):
    require(type(value) is dict and set(value) == {'origin', 'bearerToken', 'expectedBytes', 'expectedSha256'})
    require(type(value['origin']) is str and re.fullmatch(r'http://127\.0\.0\.1:[1-9][0-9]{0,4}', value['origin']))
    require(1 <= int(value['origin'].rsplit(':', 1)[1]) <= 65535)
    require(type(value['bearerToken']) is str and re.fullmatch(r'[A-Za-z0-9_-]{43}', value['bearerToken']))
    require(type(value['expectedBytes']) is int and 0 < value['expectedBytes'] <= 2 * 1024**2)
    require(type(value['expectedSha256']) is str and re.fullmatch('[0-9a-f]{64}', value['expectedSha256']))
    return value


def command(work):
    args = ['bwrap', '--die-with-parent', '--new-session', '--unshare-user', '--unshare-pid',
            '--unshare-ipc', '--unshare-uts', '--cap-drop', 'ALL']
    for name in ('/usr', '/bin', '/sbin', '/lib', '/lib64'):
        if Path(name).exists():
            args += ['--ro-bind', name, name]
    args += ['--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--tmpfs', '/home',
             '--tmpfs', '/root', '--tmpfs', '/run', '--dir', '/etc']
    for name in ('/etc/fonts', '/etc/ld.so.cache'):
        if Path(name).exists():
            args += ['--ro-bind', name, name]
    # Only this fresh UI directory is writable/visible, not the parent's private
    # catalog, recovery keys, core enrollment or provider stores.
    return args + ['--ro-bind', str(RUNTIME), '/runtime', '--bind', str(work), '/state',
        '--clearenv', '--setenv', 'HOME', '/state/home', '--setenv', 'PATH', '/usr/bin:/bin',
        '--setenv', 'XDG_CACHE_HOME', '/state/cache', '--setenv', 'MOZ_HEADLESS', '1',
        '--setenv', 'MOZ_CRASHREPORTER_DISABLE', '1', '--setenv', 'MOZ_NO_REMOTE', '1',
        '/runtime/firefox-esr', '--headless', '--no-remote', '--new-instance',
        '--profile', '/state/profile', '--marionette']


def main(root):
    global STAGE
    require(socket.gethostname() == 'volparossa-alpha' and os.geteuid() != 0)
    info = root.lstat()
    require(root.is_absolute() and root.resolve() == root and stat.S_ISDIR(info.st_mode)
        and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700)
    value = settings(json.loads(sys.stdin.buffer.read(4097)))
    base = runpy.run_path(str(SOURCE / 'scripts/smoke_web_ui.py'))['Marionette']

    class Marionette(base):
        def read(self):
            return read_frame(self.sock)

        def wait(self, script, seconds=120):
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                result = self.script(script)
                if result:
                    return result
                time.sleep(.2)
            raise TimeoutError('Cloud UI condition timeout')

    completed = False
    with tempfile.TemporaryDirectory(prefix='cloud-ui-', dir=root) as temporary:
        work = Path(temporary)
        for name in ('profile', 'downloads', 'home', 'cache'):
            (work / name).mkdir(mode=0o700)
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        prefs = {'marionette.port': port, 'marionette.enabled': True,
            'browser.shell.checkDefaultBrowser': False, 'browser.startup.homepage': 'about:blank',
            'browser.startup.page': 0, 'browser.aboutwelcome.enabled': False,
            'datareporting.policy.dataSubmissionEnabled': False, 'toolkit.telemetry.enabled': False,
            'browser.safebrowsing.downloads.enabled': False, 'browser.safebrowsing.malware.enabled': False,
            'browser.safebrowsing.phishing.enabled': False, 'app.update.enabled': False,
            'extensions.update.enabled': False, 'extensions.getAddons.cache.enabled': False,
            'network.captive-portal-service.enabled': False, 'network.connectivity-service.enabled': False,
            'network.dns.disablePrefetch': True, 'network.prefetch-next': False, 'network.predictor.enabled': False,
            'network.proxy.type': 1, 'network.proxy.http': '127.0.0.1', 'network.proxy.http_port': 1,
            'network.proxy.ssl': '127.0.0.1', 'network.proxy.ssl_port': 1,
            'network.proxy.no_proxies_on': '127.0.0.1,localhost',
            'browser.download.folderList': 2, 'browser.download.dir': '/state/downloads',
            'browser.download.useDownloadDir': True, 'browser.download.alwaysOpenPanel': False,
            'browser.helperApps.neverAsk.saveToDisk': 'application/octet-stream', 'pdfjs.disabled': True}
        (work / 'profile/user.js').write_text(''.join('user_pref(' + json.dumps(k) + ', '
            + json.dumps(v) + ');\n' for k, v in prefs.items()))
        browser, client = None, None
        try:
            STAGE = 'browser_start'
            browser = subprocess.Popen(command(work), stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
                env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
            client = Marionette(port)
            caps = client.session.get('capabilities', {})
            require(caps.get('browserName') == 'firefox' and caps.get('browserVersion') == '140.16.0')
            STAGE = 'locked_ui'
            client.call('WebDriver:Navigate', {'url': value['origin'] + '/#/files/spaces/projects'})
            client.wait("return !!document.getElementById('volparossa-recovery-token')")
            STAGE = 'wrong_token'
            submit = "document.getElementById('volparossa-recovery-token').value=arguments[0];document.querySelector('#volparossa-owner-recovery form').requestSubmit();"
            client.script(submit, ['wrong-token-that-is-at-least-32-characters'])
            client.wait("return document.querySelector('#volparossa-owner-recovery [role=status]')?.textContent.includes('failed')")
            require(client.script("return !document.body.innerText.includes('private-file.bin')"))
            STAGE = 'unlock'
            client.script(submit, [value['bearerToken']])
            client.wait("return !document.getElementById('volparossa-owner-recovery') && document.body.innerText.includes('\\nsynthetic-owner\\n')")
            client.call('WebDriver:Navigate', {'url': value['origin'] + '/#/files/spaces/project/synthetic-owner'})
            client.wait("return !!document.querySelector('[data-test-resource-name=\"private-file.bin\"]')")
            require(client.script("return !document.querySelector('[id^=app-floating-action-button]')"))
            for number in (1, 2):
                STAGE = f'original_download_{number}'
                target = work / 'downloads/private-file.bin'
                require(not target.exists())
                client.script("document.querySelector('[data-test-resource-name=\"private-file.bin\"]').closest('a,button').click();")
                client.wait("return [...document.querySelectorAll('button')].some(e=>e.textContent.trim()==='Download')")
                client.click('.oc-modal-body-actions-confirm')
                deadline = time.monotonic() + 900
                while time.monotonic() < deadline:
                    if target.exists() and target.stat().st_size == value['expectedBytes']:
                        break
                    require(browser.poll() is None)
                    time.sleep(.2)
                info = target.lstat()
                require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                    and info.st_nlink == 1 and info.st_size == value['expectedBytes'])
                require(hashlib.sha256(target.read_bytes()).hexdigest() == value['expectedSha256'])
                target.unlink()
                require(not list((work / 'downloads').iterdir()))
            STAGE = 'logout'
            require(client.script("return !location.href.includes(arguments[0]) && !JSON.stringify(localStorage).includes(arguments[0]) && !JSON.stringify(sessionStorage).includes(arguments[0])", [value['bearerToken']]))
            client.script("document.getElementById('_userMenuButton').click();")
            client.wait("return !!document.getElementById('volparossa-recovery-close')")
            client.script("document.getElementById('volparossa-recovery-close').click();")
            client.wait("return !!document.getElementById('volparossa-recovery-token')")
            completed = True
        finally:
            if client is not None:
                try:
                    client.call('WebDriver:DeleteSession')
                except (OSError, RuntimeError, ValueError):
                    pass
                client.sock.close()
            if browser is not None:
                if browser.poll() is None:
                    os.killpg(browser.pid, signal.SIGTERM)
                try:
                    browser.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    os.killpg(browser.pid, signal.SIGKILL)
                    browser.wait(timeout=5)
                require(browser.poll() is not None)
    require(completed and not work.exists())
    return dict(version=1, kind='cloud-private-file-original-ui', success=True,
        original_files_ui=True, actual_owner_service=True, synthetic_backend=False,
        file_downloads_verified=2, download_bytes=value['expectedBytes'], download_sha256=value['expectedSha256'],
        wrong_token_denied=True, logout_relocks=True, token_absent_from_url_and_web_storage=True,
        private_profile_removed=True, browser_stopped_and_joined=True,
        browser_version='140.16.0', owner_secrets_exported=False)


if __name__ == '__main__':
    def interrupted(_signal, _frame):
        raise ValueError('Cloud UI interrupted')
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, interrupted)
    try:
        require(len(sys.argv) == 2)
        print(json.dumps(main(Path(sys.argv[1])), sort_keys=True))
    except (ValueError, TypeError, KeyError, OSError, RuntimeError, subprocess.SubprocessError):
        print(json.dumps(dict(success=False, kind='cloud-private-file-ui-failure', stage=STAGE)))
        sys.exit(1)
