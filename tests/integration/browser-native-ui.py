# SPDX-License-Identifier: GPL-3.0-only
"""Exercise the visible Firefox tab menu and GTK chooser on the fixture's private X display."""
import ctypes as ct
import json
import os
from pathlib import Path
import re
import subprocess
import time


def wait_for(check, description, seconds=12):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(.08)
    raise ValueError("native tab UI: " + description)


class Display:
    def __init__(self):
        if not re.fullmatch(r":[0-9]+(?:\.0)?", os.environ.get("DISPLAY", "")):
            raise ValueError("expected private local X display")
        self.x = ct.CDLL("libX11.so.6")
        self.test = ct.CDLL("libXtst.so.6")
        self.x.XOpenDisplay.argtypes = [ct.c_char_p]
        self.x.XOpenDisplay.restype = ct.c_void_p
        self.display = self.x.XOpenDisplay(None)
        if not self.display:
            raise ValueError("disposable display unavailable")
        self.x.XSetInputFocus.argtypes = [ct.c_void_p, ct.c_ulong, ct.c_int, ct.c_ulong]
        self.x.XCloseDisplay.argtypes = [ct.c_void_p]
        self.x.XSync.argtypes = [ct.c_void_p, ct.c_int]
        self.x.XStringToKeysym.argtypes = [ct.c_char_p]
        self.x.XStringToKeysym.restype = ct.c_ulong
        self.x.XKeysymToKeycode.argtypes = [ct.c_void_p, ct.c_ulong]
        self.x.XKeysymToKeycode.restype = ct.c_uint
        self.test.XTestFakeMotionEvent.argtypes = [ct.c_void_p, ct.c_int, ct.c_int, ct.c_int, ct.c_ulong]
        for event in (self.test.XTestFakeButtonEvent, self.test.XTestFakeKeyEvent):
            event.argtypes = [ct.c_void_p, ct.c_uint, ct.c_int, ct.c_ulong]

    def focus_browser(self, process_id):
        windows = subprocess.check_output(["xwininfo", "-root", "-tree"], text=True, timeout=3)
        # Unbranded Gecko builds append their update channel to WM_CLASS.
        # Select the browser window belonging to the connected parent process.
        candidates = re.findall(r'^\s*(0x[0-9a-f]+) [^\n]*: \("Navigator" "[^"\n]+"\)',
                                windows, re.MULTILINE)
        owned = []
        for window in candidates:
            props = subprocess.run(["xprop", "-id", window, "_NET_WM_PID", "WM_WINDOW_ROLE"],
                                   capture_output=True, text=True, timeout=3)
            if props.returncode == 0 and props.stdout.splitlines() == [
                    f"_NET_WM_PID(CARDINAL) = {process_id}", 'WM_WINDOW_ROLE(STRING) = "browser"']:
                owned.append(window)
        if len(owned) != 1:
            raise ValueError("expected one Firefox browser window on the private display")
        self.x.XSetInputFocus(self.display, int(owned[0], 16), 2, 0)
        self.x.XSync(self.display, 0)

    def close(self):
        self.x.XCloseDisplay(self.display)

    def point(self, xy, button=None):
        if len(xy) != 2 or not (0 <= xy[0] < 1280 and 0 <= xy[1] < 960):
            raise ValueError("native tab menu item outside virtual display")
        self.test.XTestFakeMotionEvent(self.display, -1, round(xy[0]), round(xy[1]), 0)
        if button:
            for pressed in (1, 0):
                self.test.XTestFakeButtonEvent(self.display, button, pressed, 0)
        self.x.XSync(self.display, 0)

    def press(self, name, pressed):
        symbol = self.x.XStringToKeysym(name.encode("ascii"))
        keycode = self.x.XKeysymToKeycode(self.display, symbol)
        if not keycode:
            raise ValueError("unmapped virtual keyboard key")
        self.test.XTestFakeKeyEvent(self.display, keycode, int(pressed), 0)
        self.x.XSync(self.display, 0)

    def key(self, name):
        self.press(name, True)
        self.press(name, False)

    def select_file(self, path):
        if not re.fullmatch(r"/[A-Za-z0-9/_.-]{1,511}", str(path)):
            raise ValueError("unsupported fixture path")
        def chooser():
            tree = subprocess.check_output(["xwininfo", "-root", "-tree"],
                                           text=True, stderr=subprocess.DEVNULL, timeout=3)
            for match in re.finditer(r'(0x[0-9a-f]+) "Choose a private VOLPAROSSA routing grant(?: - [^"]+)?"', tree):
                details = subprocess.run(["xwininfo", "-id", match[1]], capture_output=True,
                                         text=True, timeout=3)
                if details.returncode == 0 and "Map State: IsViewable" in details.stdout:
                    return match[1], details.stdout
        picker = wait_for(chooser, "file picker did not open")
        self.x.XSetInputFocus(self.display, int(picker[0], 16), 2, 0)
        self.x.XSync(self.display, 0)
        self.press("Control_L", True)
        self.key("l")
        self.press("Control_L", False)
        time.sleep(.15)
        for char in str(path):
            shifted = char.isupper() or char == "_"
            if shifted:
                self.press("Shift_L", True)
            self.key({"/": "slash", ".": "period", "-": "minus", "_": "minus"}.get(char, char.lower()))
            if shifted:
                self.press("Shift_L", False)
        # In the fixture's en-US GTK chooser the Open button occupies the
        # bottom right. Click it once, scoped to the measured picker window.
        geometry = [int(re.search(r"^\s*" + label + r":\s+(-?\d+)", picker[1], re.M)[1])
                    for label in ("Absolute upper-left X", "Absolute upper-left Y", "Width", "Height")]
        x, y, width, height = geometry
        time.sleep(.3)
        self.point([x + width - 50, y + height - 22], 1)
        wait_for(lambda: not chooser(), "file picker did not close")


RECT = """
const [index] = arguments;
const win = Services.wm.getMostRecentWindow("navigator:browser");
const elem = win.__volparossaTrialUI.tabs[index];
const bounds = elem.getBoundingClientRect();
if (bounds.width <= 1 || bounds.height <= 1) return null;
return [(win.mozInnerScreenX + bounds.x + bounds.width/2)*win.devicePixelRatio,
        (win.mozInnerScreenY + bounds.y + bounds.height/2)*win.devicePixelRatio];
"""

SETUP = """
const [directory, authorities] = arguments;
const win = Services.wm.getMostRecentWindow("navigator:browser");
const { VolparossaBrowserNetwork: Controller } = ChromeUtils.importESModule(
    "resource:///modules/VolparossaBrowserNetwork.sys.mjs");
const original = Controller.bind;
const principal = Services.scriptSecurityManager.getSystemPrincipal();
const tabs = authorities.map(() => win.gBrowser.addTab("about:blank",{triggeringPrincipal:principal}));
const owners = [null, null];
let confirmCount = 0, menuCount = 0;
const marker = async (name, value) => {
  const path = directory + "/ui-" + name;
  await IOUtils.writeJSON(path + ".tmp", value, {mode:"create"});
  await IOUtils.move(path + ".tmp", path, {noOverwrite:true});
};
const observePrompt = subject => {
  const bag = subject.arguments?.[0]?.QueryInterface(Ci.nsIPropertyBag2);
  if (!bag || bag.getPropertyAsAString("title") !== "Connect this tab?") return;
  const message = bag.getPropertyAsAString("text");
  const index = confirmCount === 2 ? 1 : 0;
  if (!message.includes(authorities[index])) return;
  marker("prompt-" + (++confirmCount), {matched: true});
};
const doc = win.document;
const contextMenu = doc.getElementById("tabContextMenu");
const menu = doc.getElementById("context_volparossaTabRoute");
const capture = async event => {
  const popup = event.target;
  if (popup !== contextMenu && popup !== menu.menupopup) return;
  const root = popup === contextMenu;
  const number = root ? ++menuCount : menuCount;
  if (win.TabContextMenu.contextTab !== tabs[[0, 0, 1, 0, 0, 1, 1][number - 1]]) return;
  if (number === 5 || number === 7) {
    if (root && doc.getElementById("volparossa-tab-route-status").getAttribute("data-l10n-id")
        === "volparossa-tab-route-ordinary" && doc.getElementById("volparossa-tab-route-release").disabled
        && !doc.getElementById("volparossa-tab-route-connect").disabled) {
      await marker("ordinary-" + number, true);
    }
    return;
  }
  const element = root ? menu : doc.getElementById("volparossa-tab-route-" +
      (number <= 3 ? "connect" : "release"));
  await doc.l10n.translateElements([element]);
  // Read the settled native menu geometry. Additional WebDriver commands
  // while a popup is open can refocus the parent Firefox window.
  await new Promise(resolve => win.setTimeout(resolve, 200));
  if (popup.state !== "open" || element.hidden || element.disabled) return;
  const bounds = element.getBoundingClientRect(), inner = popup.getBoundingClientRect();
  const outer = popup.getOuterScreenRect();
  const x = (outer.x + bounds.x-inner.x + bounds.width/2)*win.devicePixelRatio;
  const y = (outer.y + bounds.y-inner.y + bounds.height/2)*win.devicePixelRatio;
  await marker((root ? "menu-" : "item-") + number, [x,y]);
};
contextMenu.addEventListener("popupshown", capture);
Services.obs.addObserver(observePrompt, "common-dialog-loaded");
Controller.bind = function(browser, ...args) {
  const owner = original.call(this, browser, ...args);
  const i = tabs.findIndex(tab => tab.linkedBrowser === browser);
  if (i >= 0) owners[i] = owner;
  return owner;
};
win.__volparossaTrialUI = { tabs, owners, finish() {
  Controller.bind = original;
  contextMenu.removeEventListener("popupshown", capture);
  Services.obs.removeObserver(observePrompt, "common-dialog-loaded");
  delete win.__volparossaTrialUI;
}};
return owners.every(owner => owner === null);
"""


STATE = """
const win = Services.wm.getMostRecentWindow("navigator:browser");
return win.__volparossaTrialUI.owners.map(owner => owner?.status.state ?? null);
"""


def open_menu(client, display, index):
    xy = wait_for(lambda: client.script(RECT, [index]), "tab inaccessible")
    display.focus_browser(client.script("return Services.appinfo.processID;"))
    display.point(xy, 3)


def menu(client, display, index, sequence, work):
    def location(name):
        path = Path(work) / f"ui-{name}-{sequence}"
        wait_for(path.is_file, f"{name} did not appear")
        return json.loads(path.read_bytes())
    open_menu(client, display, index)
    display.point(location("menu"))
    display.point(location("item"), 1)


def connect_tabs(client, paths, authorities, work):
    if client.script(SETUP, [str(work), authorities]) is not True:
        raise ValueError("tab bound before visible user action")
    display = Display()
    try:
        for sequence, (index, approve) in enumerate(((0, False), (0, True), (1, True)), start=1):
            menu(client, display, index, sequence, work)
            display.select_file(paths[index])
            wait_for((Path(work) / ("ui-prompt-" + str(sequence))).is_file, "scoped confirmation missing")
            display.key("Return" if approve else "Escape")
            if approve:
                wait_for(lambda: client.script(STATE)[index] == "overlay_ready",
                         "selected tab did not receive an overlay route", 100)
            elif client.script(STATE) != [None, None]:
                raise ValueError("cancel consumed or attached a grant")
    finally:
        display.close()
    return {"physical_tab_menu": True, "native_file_picker": True, "verified_authority_confirmations": 3,
            "cancelled_without_binding": True, "owner_approved_tabs": 2}


def release_tabs(client, work):
    display = Display()
    try:
        for index, sequence in ((0, 4), (1, 6)):
            menu(client, display, index, sequence, work)
            open_menu(client, display, index)
            wait_for((Path(work) / f"ui-ordinary-{sequence + 1}").is_file,
                     "released tab's menu did not return to ordinary networking")
            display.key("Escape")
    finally:
        display.close()
    client.script('Services.wm.getMostRecentWindow("navigator:browser").__volparossaTrialUI.finish()')


SIDEBAR = 'const win = Services.wm.getMostRecentWindow("navigator:browser");'
PROVIDER_VIEW = SIDEBAR + """
const doc = win.SidebarController.browser.contentDocument;
const selector = doc.getElementById("provider"), menu = selector.getBoundingClientRect();
const choices = Array.from(selector.options).filter(option => !option.hidden && !option.disabled);
const byId = id => doc.getElementById(id);
const panel = byId("volparossa-cooperative-compute");
const view = doc.defaultView, scale = view.devicePixelRatio;
return {
  selected: selector.value,
  preference: Services.prefs.getStringPref("browser.ml.chat.provider"),
  eligible: choices.map(option => option.value).filter(value =>
    value === "volparossa:public" || value === "volparossa:private").length === 2,
  publicIndex: choices.findIndex(option => option.value === "volparossa:public"),
  privateIndex: choices.findIndex(option => option.value === "volparossa:private"),
  privatePanel: !!byId("volparossa-private-compute"),
  publicPanel: !!panel,
  visible: menu.width > 0 && menu.height > 0,
  open: selector.matches(":open"),
  center: [(view.mozInnerScreenX + menu.x + menu.width / 2) * scale,
           (view.mozInnerScreenY + menu.y + menu.height / 2) * scale],
  review: panel?.dataset.state === "review",
  consentPending: byId("volparossa-public-consent")?.checked === false &&
    byId("volparossa-public-rights")?.checked === false &&
    byId("volparossa-public-license")?.value === "" &&
    byId("volparossa-public-submit")?.disabled === true,
  prefilled: byId("volparossa-public-question")?.value === "Synthetic demo question" &&
    byId("volparossa-public-context")?.value === "Public fixture text"
};
"""


def exercise_provider_selector(client, report):
    """Move the built-in selector with physical input and follow Firefox's public Ask entry point."""
    def view():
        return client.script(PROVIDER_VIEW)

    def selected(state, name):
        return (state["visible"] and state["eligible"] and state["selected"] == state["preference"] == name
                and state["privatePanel"] == (name == "volparossa:private")
                and state["publicPanel"] == (name == "volparossa:public"))

    def pick(display, current, index, name):
        if not 0 <= index < 32:
            raise ValueError("unknown provider selector option")
        display.point(current["center"], 1)
        wait_for(lambda: view()["open"], "native provider menu did not open")
        display.key("Home")
        for _ in range(index):
            display.key("Down")
        display.key("Return")
        def observe():
            state = view()
            return state if selected(state, name) else None
        return wait_for(observe, "provider selection did not reach the requested panel")

    report["provider_selector_phase"] = "sidebar"
    client.script(SIDEBAR + """
      Services.prefs.setBoolPref("browser.ml.chat.enabled", true);
      Services.prefs.setStringPref("browser.ml.chat.provider", "volparossa:private");
      return (async () => {
        await win.SidebarController.promiseInitialized;
        await win.SidebarController.show("viewGenaiChatSidebar");
        const sidebar = win.SidebarController.browser.contentWindow;
        await sidebar.browserPromise;
        if (sidebar.document.documentURI !== "chrome://browser/content/genai/chat.html") {
          throw new Error("provider_sidebar_document");
        }
      })();
    """)
    display = Display()
    try:
        private = view()
        if not selected(private, "volparossa:private"):
            raise ValueError("private native sidebar missing")
        report["provider_selector_phase"] = "public-option"
        public = pick(display, private, private["publicIndex"], "volparossa:public")
        if not public["review"] or not public["consentPending"]:
            raise ValueError("public selector did not open an unapproved review")
        report["provider_selector_phase"] = "public-ask"
        client.script(SIDEBAR + """
          const {GenAI} = ChromeUtils.importESModule("resource:///modules/GenAI.sys.mjs");
          return GenAI.handleAskChat({label: "Synthetic demo question"},
            {window: win, selection: "Public fixture text"});
        """)
        review = view()
        if not (selected(review, "volparossa:public") and review["prefilled"] and
                review["consentPending"] and review["review"]):
            raise ValueError("public Ask did not retain review and consent")
        report["provider_selector_phase"] = "private-option"
        pick(display, review, review["privateIndex"], "volparossa:private")
    finally:
        display.close()
    report["provider_selector_phase"] = "sidebar-close"
    client.script(SIDEBAR + 'return win.SidebarController.hide();')
    wait_for(lambda: client.script(SIDEBAR + 'return !win.SidebarController.isOpen;'),
             "provider sidebar did not close")
    report["provider_selector"] = dict(physical_provider_changes=2, native_ask_prefill=True,
        public_rights_and_consent_clear=True, public_license_empty=True, public_submit_disabled=True,
        sidebar_closed=True)
    del report["provider_selector_phase"]
