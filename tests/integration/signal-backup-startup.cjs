// SPDX-License-Identifier: GPL-3.0-only
// Observe only the pinned Bootstrap retry error; never export error text, argv or config.
'use strict';
const fs = require('node:fs');
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
  };
}
function install(destination) {
  const original = console.error;
  console.error = function (...args) {
    const attempt = typeof args[0] === 'string' && /^Failed to start the app, attempt ([1-4]), retrying$/.exec(args[0]);
    if (attempt && args.length === 2) {
      try {
        const record = { version: 1, phase: 'bootstrap-startup-failed', attempt: Number(attempt[1]), ...classify(args[1]) };
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
