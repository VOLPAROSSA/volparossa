#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Native Firefox ordinary tabs through the real core; runs only in the disposable guest.

The external topology retains ownership of WireGuard/MPTCP, origin gates and
packet observations. This driver neither creates routes nor disables global ECH.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import subprocess
import sys
import time

import browser_native_runtime as runtime
import smoke_network_core as core
from smoke_privacy import Marionette
from stage_firefox import ROOT, build_path, validate_isolated_browser_home

SCRIPT = r"""
const [grants, urls, expectedSha, expectedBytes, certificate, output, done] = arguments;
let phase="import";
const checkpoint = async (next, errorCode=null, attachment=null, request=null) => {
  phase=next;
  await IOUtils.writeJSON(output+"/driver-status.json", {version:1,
    kind:"real-gecko-core-gateway-driver-status", phase, error_code:errorCode,
    errno:null, child_exit_code:null, attachment, request}, {tmpPath:output+"/driver-status.json.tmp"});
};
const marker=async(name,value)=> {
  await IOUtils.writeJSON(output+"/"+name+".tmp",value,{mode:"create"});
  await IOUtils.move(output+"/"+name+".tmp",output+"/"+name,{noOverwrite:true});
};
(async()=>{
  const {setTimeout}=ChromeUtils.importESModule("resource://gre/modules/Timer.sys.mjs");
  const {VolparossaBrowserNetwork}=ChromeUtils.importESModule("resource:///modules/VolparossaBrowserNetwork.sys.mjs");
  const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
  const principal=Services.scriptSecurityManager.getSystemPrincipal();
  const channel=url=>Services.io.newChannelFromURI(Services.io.newURI(url),null,principal,null,
    Ci.nsILoadInfo.SEC_ALLOW_CROSS_ORIGIN_SEC_CONTEXT_IS_NULL,Ci.nsIContentPolicy.TYPE_OTHER);
  const fresh=channel(urls[0]).QueryInterface(Ci.nsIHttpChannelInternal);
  if (!("allowECH" in fresh) || fresh.allowECH !== true) throw new Error("native_abi_missing");
  Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB).addCertFromBase64(certificate,"C,,");
  const window=Services.wm.getMostRecentWindow("navigator:browser");
  const tabs=grants.map(()=>window.gBrowser.addTab("about:blank",{triggeringPrincipal:principal}));
  const owners=tabs.map(tab=>VolparossaBrowserNetwork.bind(tab.linkedBrowser));
  const attachment=owner=>[...owner._routes.values()][0]?.attachment;
  const result={native_ech_abi:true,builtin_modules:true,ordinary_tabs:true};
  // Observe original navigation bytes without replacing the native navigation:
  // one bounded buffer per onDataAvailable is immediately forwarded unchanged
  // to the original product/Gecko listener. There is no openChannel/asyncOpen.
  const navigate=(owner,browser,url)=>new Promise((resolve,reject)=>{
    let bytes=0, selected=false, streamDone=false, windowDone=false, failed=false, previous=null;
    const hash=Cc["@mozilla.org/security/hash;1"].createInstance(Ci.nsICryptoHash);
    hash.init(Ci.nsICryptoHash.SHA256);
    const original=owner._select;
    const cleanup=()=>{ owner._select=original; browser.removeProgressListener(progress); };
    const fail=()=>{ if(!failed){ failed=true; cleanup(); reject(new Error("ordinary_navigation_failed")); } };
    const finish=()=>{
      if(failed || !streamDone || !windowDone) return;
      const sha=Array.from(hash.finish(false),c=>c.charCodeAt(0).toString(16).padStart(2,"0")).join("");
      if(bytes !== expectedBytes || sha !== expectedSha || owner.status.state !== "overlay") { fail(); return; }
      cleanup();
      resolve({bytes,sha256_verified:true});
    };
    const observer={
      QueryInterface:ChromeUtils.generateQI(["nsIStreamListener","nsIRequestObserver"]),
      onStartRequest(request){ previous.onStartRequest(request); },
      onDataAvailable(request,input,offset,count){
        try {
          if(count>1048576 || bytes+count>expectedBytes) throw new Error("body_bound");
          const reader=Cc["@mozilla.org/binaryinputstream;1"].createInstance(Ci.nsIBinaryInputStream);
          reader.setInputStream(input);
          const body=reader.readByteArray(count); bytes+=count; hash.update(body,count);
          const copy=Cc["@mozilla.org/io/arraybuffer-input-stream;1"].createInstance(Ci.nsIArrayBufferInputStream);
          const array=Uint8Array.from(body); copy.setData(array.buffer,0,count);
          previous.onDataAvailable(request,copy,offset,count);
        } catch { request.cancel(Cr.NS_ERROR_ABORT); fail(); }
      },
      onStopRequest(request,status){
        try { previous.onStopRequest(request,status); }
        finally { if(!Components.isSuccessCode(status)) fail(); else {streamDone=true;finish();} }
      },
    };
    const progress={
      QueryInterface:ChromeUtils.generateQI(["nsIWebProgressListener","nsISupportsWeakReference"]),
      onStateChange(_progress,_request,flags,status){
        if((flags&Ci.nsIWebProgressListener.STATE_STOP)&&(flags&Ci.nsIWebProgressListener.STATE_IS_WINDOW)){
          if(!Components.isSuccessCode(status)||browser.currentURI.spec!==url) fail();
          else {windowDone=true;finish();}
        }
      },
      onLocationChange(){},onProgressChange(){},onStatusChange(){},onSecurityChange(){},onContentBlockingEvent(){},
    };
    owner._select=function(...args){
      const proxy=Reflect.apply(original,this,args);
      const request=args[0];
      if(!selected && request.URI.spec===url){
        selected=true;
        previous=request.QueryInterface(Ci.nsITraceableChannel).setNewListener(observer);
      }
      return proxy;
    };
    browser.addProgressListener(progress,Ci.nsIWebProgress.NOTIFY_STATE_WINDOW);
    browser.loadURI(Services.io.newURI(url),{triggeringPrincipal:principal});
  });
  try{
    await checkpoint("attach-a"); await owners[0].authorize(grants[0]);
    await checkpoint("attach-b"); await owners[1].authorize(grants[1]);
    const a=attachment(owners[0]),b=attachment(owners[1]);
    result.independent_attachments=a.active&&b.active&&a._isolation!==b._isolation;
    await checkpoint("wrong-scope");
    try{ a.openChannel(channel("https://outside-authority.invalid/denied"),{}); result.wrong_scope_blocked=false; }
    catch{ result.wrong_scope_blocked=true; }
    if(!result.wrong_scope_blocked) throw new Error("scope_failure");
    await checkpoint("request-a"); result.a=await navigate(owners[0],tabs[0].linkedBrowser,urls[0]);
    await marker("a-complete.json",{version:1,complete:true});
    await checkpoint("request-b");
    const pending=navigate(owners[1],tabs[1].linkedBrowser,urls[1]);
    let failure=null; pending.catch(error=>{failure=error;});
    const deadline=Date.now()+75000;
    while(!(await IOUtils.exists(output+"/detach-a"))){
      if(failure) throw failure;
      if(Date.now()>=deadline) throw new Error("detach_marker_unavailable");
      await sleep(50);
    }
    const command=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(await IOUtils.read(output+"/detach-a",{maxBytes:128})));
    if(Object.keys(command).sort().join(",")!=="detach,version"||command.version!==1||command.detach!==true)
      throw new Error("detach_marker_invalid");
    await checkpoint("detach-a"); owners[0].close();
    await marker("a-detached.json",{version:1,detached:true}); result.a_detached=!a.active;
    await checkpoint("finish-b"); result.b=await pending; result.b_survives_a_detach=b.active;
  }finally{ for(const owner of owners) owner.close(); }
  done(result);
})().catch(async error=>{
  const allowed=["invalid_contract","invalid_scope","scope_unavailable","invalid_channel",
    "unsupported_runtime","unavailable","request_failed","detached"];
  const code=allowed.includes(error?.code)?error.code:"SCRIPT_FAILED";
  const attachment=error?.diagnostic??null;
  try{await checkpoint(phase,code,attachment,null);}catch{}
  done({fatal:"native_network_core_driver_failed",phase,code,attachment});
});
"""


def check_result(value, count):
    require = runtime.require
    require(type(value) is dict and all(value.get(k) is True for k in
        ("native_ech_abi", "builtin_modules", "ordinary_tabs")))
    core.check_result({k: v for k, v in value.items() if k not in
                       ("native_ech_abi", "builtin_modules", "ordinary_tabs")}, count)


def inside(args, work, provision):
    require = runtime.require
    core.guest_guard(args)
    require(all(os.statvfs(p).f_flag & os.ST_RDONLY for p in (Path("/"), ROOT, args.stage)))
    validate_isolated_browser_home(work)
    grants = [core.grant_file(p) for p in (args.grant_a, args.grant_b)]
    require(grants[0]["capability"] != grants[1]["capability"])
    control = core.validate_control_namespace(args.control_directory, grants)
    access = core.probe_app_socket(work, grants)
    for url, grant in zip((args.url_a, args.url_b), grants):
        core.pinned_url(url, grant)
    require(args.test_ca.is_file() and not args.test_ca.is_symlink() and args.test_ca.stat().st_size <= 16384)
    certificate = base64.b64encode(ssl.PEM_cert_to_DER_cert(args.test_ca.read_text())).decode()
    for name in ("profile", "config", "cache", "runtime", "tmp", "upload"):
        (work / name).mkdir(mode=0o700)
    (work / "profile/prefs.js").write_text('user_pref("remote.prefs.recommended", false);\n')
    environment = dict(HOME=os.environ["HOME"], PATH="/usr/bin:/bin", LANG="C.UTF-8",
        MOZ_NO_REMOTE="1", MOZ_CRASHREPORTER_DISABLE="1", MOZ_UPLOAD_DIR=str(work / "upload"),
        XDG_CONFIG_HOME=str(work / "config"), XDG_CACHE_HOME=str(work / "cache"),
        XDG_RUNTIME_DIR=str(work / "runtime"), TMPDIR=str(work / "tmp"))
    report = dict(version=1, kind="native-firefox-core-ordinary-tabs", passed=False,
        core_revision=args.core_revision, browser_revision=provision["browser_revision"],
        runtime_version="157.0.1", runtime_source_stamp=runtime.FIREFOX_REVISION,
        native_bundle_sha256=runtime.digest(ROOT / "native-bundle.json"),
        original_build_receipt_sha256=runtime.BASE_RECEIPT_SHA,
        javascript_overlay=provision["javascript_overlay"], profile_ech_grease_disabled=False,
        native_ech_wire_proven=False, full_browser_killswitch=False,
        expected_bytes=args.expected_bytes, expected_sha256=args.expected_sha256,
        overlay_kernel_proof_external=True, namespace=os.readlink("/proc/self/ns/net"),
        socket_access=access, control_namespace=control)
    browser, client = None, None
    try:
        core.driver_status(work, "browser-start")
        browser = subprocess.Popen([str(args.stage / "firefox"), "--headless", "--no-remote", "--new-instance",
            "--profile", str(work / "profile"), "--marionette", "--remote-allow-system-access", "about:blank"],
            env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            require(browser.poll() is None)
            try:
                connection = socket.create_connection(("127.0.0.1", 2828), timeout=1)
                connection.settimeout(315)
                client = Marionette(connection)
                break
            except (ConnectionRefusedError, TimeoutError):
                time.sleep(.2)
        require(client is not None)
        client.command("WebDriver:NewSession", {"capabilities": {"alwaysMatch": {}}})
        initial_tabs = set(client.command("WebDriver:GetWindowHandles", {})["value"])
        require(len(initial_tabs) == 1)
        client.command("Marionette:SetContext", {"value": "chrome"})
        client.command("WebDriver:SetTimeouts", {"script": 300000})
        result = client.command("WebDriver:ExecuteAsyncScript", {"script": SCRIPT,
            "args": [grants, [args.url_a, args.url_b], args.expected_sha256, args.expected_bytes, certificate, str(work)],
            "newSandbox": True, "sandbox": "system"})["value"]
        report["result"] = result
        check_result(result, args.expected_bytes)
        client.command("Marionette:SetContext", {"value": "content"})
        handles = set(client.command("WebDriver:GetWindowHandles", {})["value"]) - initial_tabs
        require(len(handles) == 2)
        for handle in handles:
            client.command("WebDriver:SwitchToWindow", {"handle": handle})
            require(client.command("WebDriver:ExecuteScript", {"script":
                'return document.body.textContent.startsWith("volparossa-browser-network:");',
                "args": [], "newSandbox": True})["value"] is True)
        report["ordinary_tab_bodies_verified"] = 2
        client.command("Marionette:Quit", {"flags": ["eAttemptQuit"]})
        require(browser.wait(timeout=20) == 0)
        report["passed"] = True
    finally:
        if client is not None:
            client.socket.close()
        if browser is not None and browser.poll() is None:
            os.killpg(browser.pid, signal.SIGTERM)
            try:
                browser.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(browser.pid, signal.SIGKILL)
                browser.wait(timeout=5)
        report["cleanup"] = dict(browser_exited=browser is None or browser.poll() is not None,
                                 profile_removed=core.remove_profile(work))
        report["passed"] = report["passed"] and all(report["cleanup"].values())
        (work / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    require(report["passed"])


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("stage", "output", "grant-a", "grant-b", "test-ca", "control-directory"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("url-a", "url-b", "expected-sha256", "core-revision", "parent-netns"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--expected-bytes", type=int, required=True)
    parser.add_argument("--inside", action="store_true")
    args = parser.parse_args()
    core.guest_guard(args)
    runtime.require(ROOT == runtime.GUEST_ROOT and args.stage == ROOT / "build/firefox-native"
        and args.expected_bytes == 33554432 and re.fullmatch(r"[0-9a-f]{40}", args.core_revision)
        and re.fullmatch(r"[0-9a-f]{64}", args.expected_sha256))
    provision = runtime.validate(ROOT)
    work = build_path(args.output)
    if args.inside:
        core.private_directory(work)
        inside(args, work, provision)
        return
    runtime.require(not work.exists())
    work.mkdir(parents=True, mode=0o700)
    core.driver_status(work, "wrapper-start")
    # The guest application HOME is already private; mask it completely and keep
    # only a fresh .mozilla inode. Never clear HOME: Gecko expects a valid value.
    home = Path.home()
    runtime.require(home.resolve() == home and home != Path("/") and not home.is_relative_to(ROOT))
    (work / "appdata").mkdir(mode=0o700)
    for name in ("firefox", "firefox-esr"):
        (work / "appdata" / name).mkdir(mode=0o700)
    home_mounts = ["--tmpfs", str(home), "--dir", str(home / ".mozilla"), "--bind", str(work / "appdata"),
                   str(home / ".mozilla"), "--remount-ro", str(home)]
    try:
        subprocess.run(["/usr/bin/bwrap", "--die-with-parent", "--unshare-user", "--ro-bind", "/", "/",
            *core.isolated_runtime_parent(args.stage, work), *home_mounts,
            *core.control_namespace_mounts(args.control_directory), "--bind", str(work), str(work),
            "--tmpfs", "/tmp", "--proc", "/proc", "--dev", "/dev", "--chdir", str(work), "--",
            sys.executable, "-B", str(Path(__file__).resolve()), *sys.argv[1:], "--inside"],
            cwd=work, check=True, timeout=360)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError) as error:
        core.driver_status(work, "wrapper-launch", error)
        raise


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError):
        print("native core browser trial failed", file=sys.stderr)
        raise SystemExit(1) from None
