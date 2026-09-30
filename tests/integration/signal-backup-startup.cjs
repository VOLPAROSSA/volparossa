// SPDX-License-Identifier: GPL-3.0-only
// Observe only the pinned Bootstrap retry error; never export error text, argv or config.
'use strict';
const fs = require('node:fs');
const { createHash } = require('node:crypto');
const names = new Set(['Error', 'TypeError', 'RangeError', 'TimeoutError', 'SystemError']);
const codes = new Set(['EACCES', 'EPERM', 'ENOENT', 'EROFS', 'ENOSPC', 'ENOMEM', 'ECONNREFUSED',
  'ECONNRESET', 'EADDRINUSE', 'EADDRNOTAVAIL', 'ETIMEDOUT', 'ERR_MODULE_NOT_FOUND', 'MODULE_NOT_FOUND',
  'ERR_DLOPEN_FAILED', 'ERR_REQUIRE_ESM', 'ERR_UNKNOWN_FILE_EXTENSION', 'ERR_ASSERTION', 'ERR_MOCHA_TIMEOUT']);
const signals = new Set(['SIGABRT', 'SIGBUS', 'SIGFPE', 'SIGILL', 'SIGKILL', 'SIGSEGV', 'SIGSYS',
  'SIGTERM', 'SIGTRAP', 'SIGXCPU', 'SIGXFSZ']);
const patterns = {
  crashpad_database: /crashpad_handler: --database is required/i,
  chromium_namespace: /failed to (?:move to|enter) new namespace|failed to unshare|no usable sandbox/i,
  chromium_setuid_sandbox: /suid sandbox helper binary was found, but is not configured correctly|running as root without --no-sandbox/i,
  chromium_display: /missing x server or \$display|unable to open x display|the platform failed to initialize/i,
  native_library: /error while loading shared libraries|err_dlopen_failed|no native build was found|invalid elf header/i,
  cpu_instruction: /illegal instruction/i,
  user_data_directory: /failed to create (?:the )?(?:user data|profile) directory|cannot create user data directory/i,
  debugger_connect: /websocket error|websocket connection|connect econnrefused|connect etimedout/i,
  chromium_process_launch: /zygote could not fork|failed to launch (?:the )?(?:gpu|renderer) process/i,
  resource_limit: /out of memory|cannot allocate memory|no space left on device|file size limit exceeded/i,
};
// These are upstream source names, not runtime filesystem paths. Unknown names are
// hashed so an operator can match the exact pinned binary's source-string inventory
// without exporting an arbitrary filename, CHECK expression, value, or fatal text.
const sourceNames = new Set([
  'electron_main_delegate.cc', 'electron_browser_main_parts.cc', 'electron_browser_context.cc',
  'electron_api_app.cc', 'electron_api_crash_reporter.cc', 'node_bindings.cc', 'node_bindings_linux.cc',
  'javascript_environment.cc', 'browser_main_loop.cc', 'browser_main_runner_impl.cc',
  'content_main_runner_impl.cc', 'zygote_host_impl_linux.cc', 'zygote_linux.cc',
  'setuid_sandbox_host.cc', 'sandbox_linux.cc', 'thread_helpers.cc', 'platform_thread_posix.cc',
  'platform_thread_linux.cc', 'crashpad_client_linux.cc', 'process_singleton_posix.cc',
  'shared_memory_switch.cc', 'shared_memory_posix.cc', 'platform_shared_memory_region_posix.cc',
  'memory_mapped_file_posix.cc', 'file_util_posix.cc', 'v8_initializer.cc',
  'linux_ui_factory.cc', 'ozone_platform_x11.cc', 'ozone_platform_wayland.cc',
  'logging.cc', 'check.cc',
]);
function fatalLocations(raw) {
  // Both Chromium header forms and the V8 format embedded in pinned Electron
  // 44.1.0 ("# Fatal error in: %s, line %d"). This does not export its message.
  const header = /\b(?:FATAL|DFATAL):([^\]\[\r\n]{1,512}?)(?:\((\d{1,7})\)|:(\d{1,7}))\]|# Fatal error in:? ([^\r\n]{1,512}?), line (\d{1,7})/g;
  const locations = [];
  const seen = new Set();
  let omitted = false;
  for (const match of raw.matchAll(header)) {
    const source = (match[1] || match[4]).replace(/^(?:\.\.\/)+/, '');
    const line = Number(match[2] || match[3] || match[5]);
    if (!/^(?:[A-Za-z0-9_.+-]+\/)*[A-Za-z0-9_+-]+\.(?:cc|cpp|c|h)$/.test(source)
        || line < 1 || line > 1000000) continue;
    const sourceHash = createHash('sha256').update(source).digest('hex');
    const key = `${sourceHash}:${line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    if (locations.length === 4) { omitted = true; continue; }
    const basename = source.split('/').pop();
    const suffix = raw.slice(match.index + match[0].length, match.index + match[0].length + 4096);
    const after = suffix.split('\n', match[4] ? 3 : 1).join('\n');
    locations.push({ source: sourceNames.has(basename) ? basename : 'OTHER', source_sha256: sourceHash,
      line, category: /\bCheck failed:|\bCHECK failed:/i.test(after) ? 'check_failed'
        : /\bNOTREACHED hit\b/.test(after) ? 'notreached' : 'fatal_log' });
  }
  return { observed: /\b(?:FATAL|DFATAL):|# Fatal error in\b|\bFATAL ERROR:/.test(raw), locations, omitted };
}
function knownSignal(value) {
  return value == null || value === 'null' ? null : signals.has(value) ? value : 'OTHER';
}
function classify(error) {
  const original = typeof error?.message === 'string' ? error.message : '';
  const raw = original.slice(0, 65536);
  const ended = /<process did exit: exitCode=(null|-?\d{1,3}), signal=(null|SIG[A-Z0-9]{1,12})>/.exec(raw);
  // Playwright observes the .bin/Node launcher; Electron's CLI separately reports
  // a signalled native child. Never mislabel the launcher's code as Electron's code.
  const native = /\/electron exited with signal (SIG[A-Z0-9]{1,12})(?:\s|$)/.exec(raw);
  const processState = {
    launcher_started: /<launched> pid=\d{1,12}/.test(raw),
    spawn_failure_observed: /spawn(?:Sync)? [^\n]{1,4096} (?:ENOENT|EACCES|EPERM)(?:\s|$)/.test(raw),
    launcher_exit_observed: ended !== null,
    launcher_exit_code: ended && ended[1] !== 'null' ? Number(ended[1]) : null,
    launcher_exit_signal: knownSignal(ended?.[2]),
    electron_exit_signal: knownSignal(native?.[1]),
    node_endpoint_observed: /Debugger listening on ws:\/\//.test(raw),
    chromium_endpoint_observed: /DevTools listening on ws:\/\//.test(raw),
  };
  if (processState.launcher_exit_code !== null && Math.abs(processState.launcher_exit_code) > 255) {
    processState.launcher_exit_code = null;
  }
  const timeout = error?.name === 'TimeoutError' || /timeout \d+ms exceeded|timed out/i.test(raw);
  const causes = Object.fromEntries(Object.entries(patterns).map(([name, pattern]) => [name, pattern.test(raw)]));
  const failure = native ? 'electron_signal' : ended ? 'launcher_exit'
    : timeout && causes.debugger_connect ? 'debugger_connect_timeout'
    : timeout && processState.node_endpoint_observed && !processState.chromium_endpoint_observed ? 'chromium_endpoint_timeout'
    : timeout && processState.launcher_started && !processState.node_endpoint_observed ? 'node_endpoint_timeout'
    : !processState.launcher_started && processState.spawn_failure_observed ? 'spawn_error'
    : 'unknown';
  return {
    exception: { name: names.has(error?.name) ? error.name : 'OTHER',
      code: codes.has(error?.code) ? error.code : 'OTHER',
      errno: Number.isInteger(error?.errno) && Math.abs(error.errno) > 0 && Math.abs(error.errno) < 4096 ? error.errno : null },
    process: processState, failure_class: failure, causes,
    cause_unknown: !Object.values(causes).some(Boolean), message_truncated: original.length > 65536,
    fatal: fatalLocations(raw),
  };
}
function install(destination) {
  const original = console.error;
  console.error = function (...args) {
    const attempt = typeof args[0] === 'string' && /^Failed to start the app, attempt ([1-4]), retrying$/.exec(args[0]);
    if (attempt && args.length === 2) {
      try {
        const record = { version: 2, phase: 'bootstrap-startup-failed', attempt: Number(attempt[1]), ...classify(args[1]) };
        fs.writeFileSync(`${destination}.tmp`, JSON.stringify(record) + '\n', { flag: 'wx', mode: 0o600 });
        fs.renameSync(`${destination}.tmp`, destination);
      } catch {
        // Diagnostic failure cannot change the original application/test control flow.
      }
    }
    return original.apply(this, args);
  };
}
module.exports = { classify, install };
if (process.env.VOLPAROSSA_BACKUP_STARTUP) install(process.env.VOLPAROSSA_BACKUP_STARTUP);
