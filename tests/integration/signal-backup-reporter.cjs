// SPDX-License-Identifier: GPL-3.0-only
// Never serialize Mocha errors, screenshots, messages, arguments or application logs.
'use strict';
const fs = require('node:fs');
const title = 'backups exports and imports a VOLPAROSSA replicated encrypted backup';
module.exports = class SignalBackupReporter {
  constructor(runner) {
    let tests = 0, passes = 0, failures = 0, pending = 0, exact = true;
    let lastFailure = null;
    const codes = new Set(['EACCES', 'EPERM', 'ENOENT', 'EROFS', 'ENOSPC', 'ENOMEM', 'ECONNREFUSED',
      'ETIMEDOUT', 'ERR_MODULE_NOT_FOUND', 'MODULE_NOT_FOUND', 'ERR_DLOPEN_FAILED', 'ERR_REQUIRE_ESM',
      'ERR_UNKNOWN_FILE_EXTENSION', 'ERR_ASSERTION', 'ERR_MOCHA_TIMEOUT']);
    const status = phase => {
      const path = process.env.VOLPAROSSA_BACKUP_STATUS;
      if (!path) return;
      fs.writeFileSync(`${path}.tmp`, JSON.stringify({ version: 1, phase, tests, passes, failures, pending,
        exact_test: exact, last_failure: lastFailure }) + '\n', { flag: 'wx', mode: 0o600 });
      fs.renameSync(`${path}.tmp`, path);
    };
    status('reporter-initialized');
    runner.once('start', () => status('run-start'));
    runner.on('hook', () => status('hook-start'));
    runner.on('hook end', () => status('hook-end'));
    runner.on('test', () => status('test-start'));
    runner.on('test end', test => { tests += 1; exact &&= test.fullTitle() === title; status('test-end'); });
    runner.on('pass', () => { passes += 1; status('test-pass'); });
    runner.on('fail', (test, error) => {
      failures += 1;
      const kind = test?.type === 'hook' ? 'hook' : test?.type === 'test' ? 'test' : 'unknown';
      const number = error?.errno;
      lastFailure = { kind, code: codes.has(error?.code) ? error.code : 'OTHER',
        errno: Number.isInteger(number) && Math.abs(number) > 0 && Math.abs(number) < 4096 ? number : null };
      status(`${kind}-fail`);
    });
    runner.on('pending', () => { pending += 1; status('pending'); });
    runner.once('end', () => {
      status('run-end');
      fs.writeFileSync(process.env.VOLPAROSSA_BACKUP_RESULT,
        JSON.stringify({ version: 1, tests, passes, failures, pending, exact_test: exact }) + '\n',
        { flag: 'wx', mode: 0o600 });
    });
  }
};
