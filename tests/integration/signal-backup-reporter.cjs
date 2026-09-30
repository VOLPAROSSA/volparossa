// SPDX-License-Identifier: GPL-3.0-only
// Never serialize Mocha errors, screenshots, messages, arguments or application logs.
'use strict';
const fs = require('node:fs');
const title = 'backups exports and imports a VOLPAROSSA replicated encrypted backup';
module.exports = class SignalBackupReporter {
  constructor(runner) {
    let tests = 0, passes = 0, failures = 0, pending = 0, exact = true;
    runner.on('test end', test => { tests += 1; exact &&= test.fullTitle() === title; });
    runner.on('pass', () => { passes += 1; });
    runner.on('fail', () => { failures += 1; });
    runner.on('pending', () => { pending += 1; });
    runner.once('end', () => {
      fs.writeFileSync(process.env.VOLPAROSSA_BACKUP_RESULT,
        JSON.stringify({ version: 1, tests, passes, failures, pending, exact_test: exact }) + '\n',
        { flag: 'wx', mode: 0o600 });
    });
  }
};
