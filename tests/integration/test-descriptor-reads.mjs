// SPDX-License-Identifier: GPL-3.0-only
// Isolated actual reader bodies with real files/descriptors, no guest/application execution.
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
const require = createRequire(import.meta.url);
const __dirname = fileURLToPath(new URL('.', import.meta.url));
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const vm = require('node:vm');
const ROOT = path.resolve(__dirname, '../..');
const readers = [
  {
    "source": "tests/integration/cloud-private-file-sdk.mjs",
    "name": "publicBytes",
    "sync": false,
    "args": "file",
    "rootOnly": true
  },
  {
    "source": "tests/integration/agent-private-task-code.cjs",
    "name": "readPrivateInput",
    "sync": true,
    "args": "file",
    "rootOnly": false
  }
];
function reader(config, afterStat = () => {}, beforeRead = () => {}) {
  const source = fs.readFileSync(path.join(ROOT, config.source), 'utf8');
  const start = source.indexOf((config.sync ? 'function ' : 'async function ') + config.name + '(');
  assert.ok(start >= 0);
  const end = source.indexOf('\n}', start) + 2;
  assert.ok(end > start);
  const handles = [], closed = [], capacities = [];
  const wrappedFS = {...fs, ...(!config.sync ? fsp : {})};
  if (config.sync) {
    wrappedFS.openSync = (...args) => { const fd = fs.openSync(...args); handles.push(fd); return fd; };
    wrappedFS.fstatSync = fd => { const info = fs.fstatSync(fd); afterStat(); return info; };
    wrappedFS.readSync = (fd, bytes, ...args) => {
      capacities.push(bytes.length); beforeRead(); return fs.readSync(fd, bytes, ...args);
    };
    wrappedFS.closeSync = fd => { closed.push(fd); return fs.closeSync(fd); };
  }
  async function open(...args) {
    const handle = await fsp.open(...args); handles.push(handle.fd);
    return {stat: async () => {const info = await handle.stat(); afterStat(); return info;},
      read: async (bytes, ...rest) => {capacities.push(bytes.length); beforeRead(); return handle.read(bytes, ...rest);},
      close: async () => {closed.push(handle.fd); await handle.close();}};
  }
  wrappedFS.open = open;
  const demand = value => assert.ok(value);
  const fn = vm.runInNewContext('(' + source.slice(start, end) + ')', {fs: wrappedFS, open,
    constants: fs.constants, realpath: fsp.realpath, realpathSync: fs.realpathSync,
    path, Buffer, process, assert, insist: demand, require: demand, demand, checkFixture: demand,
    MAX_BYTES: 2 * 1024 * 1024});
  const call = file => config.args === 'expected' ? fn(file, {bytes: 12})
    : config.args === 'project' ? fn(path.dirname(file), path.basename(file)) : fn(file);
  return {call, handles, closed, capacities};
}
function fixture(t, rootOnly = false) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'vp-descriptor-'));
  fs.chmodSync(directory, 0o700);
  const file = path.join(directory, 'fixture');
  fs.writeFileSync(file, 'trusted-data', {mode: rootOnly && process.getuid() === 0 ? 0o444 : 0o600});
  t.after(() => fs.rmSync(directory, {recursive: true, force: false}));
  return {directory, file};
}
for (const config of readers) {
  test(config.name + ': leaf symlink is rejected without reading its target', async t => {
    const f = fixture(t, config.rootOnly), linked = path.join(f.directory, 'link');
    fs.symlinkSync(f.file, linked);
    const r = reader(config);
    await assert.rejects(async () => r.call(linked));
    assert.equal(r.capacities.length, 0); assert.deepEqual(r.closed, r.handles);
  });
  if (config.rootOnly && process.getuid() !== 0) {
    test(config.name + ': unprivileged ownership fails closed and closes descriptor', async t => {
      const f = fixture(t, config.rootOnly), r = reader(config);
      await assert.rejects(async () => r.call(f.file));
      assert.equal(r.capacities.length, 0); assert.deepEqual(r.closed, r.handles);
    });
    continue; // No simulated root authority in an unprivileged local test.
  }
  test(config.name + ': pathname replacement after stat reads the checked descriptor', async t => {
    const f = fixture(t, config.rootOnly); let replaced = false;
    const r = reader(config, () => {
      if (replaced) return; replaced = true;
      fs.renameSync(f.file, path.join(f.directory, 'original'));
      fs.writeFileSync(f.file, 'untrusted!!!', {mode: 0o600});
    });
    assert.equal((await r.call(f.file)).toString(), 'trusted-data');
    assert.equal(replaced, true); assert.deepEqual(r.closed, r.handles);
  });
  test(config.name + ': concurrent growth is bounded and closes on rejection', async t => {
    const f = fixture(t, config.rootOnly); let changed = false;
    const r = reader(config, () => {}, () => {
      if (changed) return; changed = true; fs.appendFileSync(f.file, Buffer.alloc(1024 * 1024));
    });
    await assert.rejects(async () => r.call(f.file));
    assert.ok(r.capacities.length > 0); assert.ok(r.capacities.every(size => size === 13));
    assert.deepEqual(r.closed, r.handles);
  });
}
