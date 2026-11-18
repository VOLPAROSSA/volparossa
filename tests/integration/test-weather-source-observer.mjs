// SPDX-License-Identifier: GPL-3.0-only
// Inert fake-fetch/filesystem tests: no origin requests or downloaded executables.
import assert from 'node:assert/strict';
import { chmodSync, closeSync, constants, existsSync, fstatSync, mkdirSync, mkdtempSync, openSync, readFileSync, readdirSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { MAX_RECEIPT_BYTES, MAX_RETRY_SECONDS, observeFetch, parseRetryAfter, writeReceipt } from './weather-source-observer.mjs';

const NOW = Date.parse('2026-10-12T12:00:00.123Z');
const URL = 'https://data.ecmwf.int/forecasts/fixture.grib2';
const state = (name, until = null) => ({ retry_after_state: name, retry_not_before_ms: until });
const receipt = (product = 'weather') => ({ schema: 1, kind: 'weather-source-rate-limit', product,
  status: 429, observed_at_ms: NOW, ...parseRetryAfter('60', NOW) });
function response(header = '60', overrides = {}) {
  return { url: URL, redirected: false, status: 429,
    headers: { get(name) { assert.equal(name, 'retry-after'); return header; } },
    get body() { throw new Error('body must not be accessed'); },
    ...overrides };
}
function privateDirectory(t) {
  const directory = mkdtempSync(join(tmpdir(), 'weather-source-observer-'));
  chmodSync(directory, 0o700);
  t.after(() => rmSync(directory, { recursive: true, force: false }));
  return directory;
}
function readOpened(path) {
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try { return { info: fstatSync(descriptor), raw: readFileSync(descriptor) }; }
  finally { closeSync(descriptor); }
}

test('bounded integral seconds preserve exact delay including zero and leading zeros', () => {
  for (const [input, seconds] of [['0', 0], ['001', 1], ['60', 60], [String(MAX_RETRY_SECONDS), MAX_RETRY_SECONDS]]) {
    assert.deepEqual(parseRetryAfter(input, NOW), state('valid-seconds', NOW + seconds * 1000));
  }
});

test('missing, malformed, combined and excessive guidance never becomes a usable delay', () => {
  assert.deepEqual(parseRetryAfter(null, NOW), state('missing'));
  for (const input of ['', ' 60 ', '-1', '+1', '0.5', '1e3', '60, 120', '60\r\nSECRET', 'é', '1'.repeat(129), 60, undefined]) {
    assert.deepEqual(parseRetryAfter(input, NOW), state('malformed'));
  }
  for (const input of [String(MAX_RETRY_SECONDS + 1), '9007199254740993', '9'.repeat(128)]) {
    assert.deepEqual(parseRetryAfter(input, NOW), state('out-of-range'));
  }
});

test('canonical dates preserve future and past absolute guidance including signed epochs', () => {
  for (const input of ['Mon, 12 Oct 2026 12:01:00 GMT', 'Mon, 12 Oct 2026 11:59:00 GMT', 'Wed, 31 Dec 1969 23:59:59 GMT']) {
    assert.deepEqual(parseRetryAfter(input, NOW), state('valid-date', Date.parse(input)));
  }
  assert.deepEqual(parseRetryAfter('Tue, 20 Oct 2026 12:00:00 GMT', NOW), state('out-of-range'));
});

test('date roundtrip rejects incorrect weekday, impossible calendar and noncanonical forms', () => {
  for (const input of ['Tue, 12 Oct 2026 12:01:00 GMT', 'Mon, 31 Feb 2026 12:01:00 GMT',
    'Mon, 12 Oct 2026 24:00:00 GMT', 'Mon, 12 Oct 2026 12:00:60 GMT', 'Mon, 12 Oct 2026 12:01:00 UTC',
    '2026-10-12T12:01:00Z', 'Monday, 12-Oct-26 12:01:00 GMT',
    'Mon, 12 Oct 2026 12:01:00 GMT, Mon, 12 Oct 2026 12:02:00 GMT']) {
    assert.deepEqual(parseRetryAfter(input, NOW), state('malformed'));
  }
});

test('invalid observation clocks reject parsing without inventing an epoch', () => {
  for (const clock of [NaN, Infinity, -1, 1.5, Number.MAX_SAFE_INTEGER, '123']) {
    assert.throws(() => parseRetryAfter('60', clock), TypeError);
  }
  assert.deepEqual(parseRetryAfter('1', 8640000000000000), state('out-of-range'));
});

test('exactly one delegation keeps receiver, all arguments, signal and Response identity; no body access', async () => {
  const controller = new AbortController();
  const options = { method: 'GET', headers: { Range: 'bytes=1-3' }, signal: controller.signal, redirect: 'error' };
  const receiver = {}, original = response(), emitted = [];
  let calls = 0;
  const wrapped = observeFetch(function (...args) {
    calls++; assert.equal(this, receiver); assert.equal(args[0], URL); assert.equal(args[1], options);
    assert.equal(args.length, 2); assert.equal(args[1].signal, controller.signal); return Promise.resolve(original);
  }, { product: 'weather', now: () => NOW, emit: value => emitted.push(value) });
  assert.equal(await wrapped.call(receiver, URL, options), original);
  assert.equal(calls, 1); assert.deepEqual(emitted, [receipt()]); assert.equal(controller.signal.aborted, false);
  assert.deepEqual(options.headers, { Range: 'bytes=1-3' });
});

test('native AbortSignal and original fetch rejection retain exact identity', async () => {
  const controller = new AbortController(), error = new Error('private original transport failure');
  let calls = 0, emissions = 0;
  const wrapped = observeFetch((_url, options) => {
    calls++; assert.equal(options.signal, controller.signal);
    return new Promise((_resolve, reject) => options.signal.addEventListener('abort', () => reject(error), { once: true }));
  }, { product: 'weather', now() { throw new Error('broken clock'); }, emit() { emissions++; } });
  const pending = wrapped(URL, { signal: controller.signal }); controller.abort();
  await assert.rejects(pending, actual => actual === error);
  assert.equal(calls, 1); assert.equal(emissions, 0);
});

test('observer IO, header and clock failures preserve original Response without retries', async () => {
  for (const failure of ['clock', 'header', 'write', 'backward', 'invalid']) {
    let calls = 0, ticks = 0, emissions = 0;
    const original = response('60', failure === 'header' ? { headers: { get() { throw new Error('header failed'); } } } : {});
    const wrapped = observeFetch(() => { calls++; return original; }, { product: 'weather',
      now() { if (failure === 'clock') throw new Error('clock failed');
        return failure === 'invalid' ? NaN : failure === 'backward' ? NOW - ticks++ : NOW; },
      emit() { emissions++; throw new Error('write failed'); } });
    assert.equal(await wrapped(URL), original); assert.equal(calls, 1);
    assert.equal(emissions, failure === 'write' ? 1 : 0);
  }
});

test('forward wall clock is observation time, not an automatic retry or clamped date', async () => {
  let ticks = 0; const emitted = [];
  const later = NOW + 3600000;
  const original = response('Mon, 12 Oct 2026 12:01:00 GMT');
  const wrapped = observeFetch(() => original, { product: 'weather', now: () => ticks++ ? later : NOW,
    emit: value => emitted.push(value) });
  assert.equal(await wrapped(URL), original);
  assert.equal(emitted[0].observed_at_ms, later);
  assert.equal(emitted[0].retry_not_before_ms, Date.parse('Mon, 12 Oct 2026 12:01:00 GMT'));
});

test('only exact allowed original HTTPS origin, final URL and nonredirected429 are observed', async () => {
  for (const [url, overrides] of [[URL, { status: 200 }], [URL, { status: 503 }], [URL, { redirected: true }],
    [URL, { url: `${URL}?changed` }], ['http://data.ecmwf.int/fixture', {}],
    ['https://data.ecmwf.int:8443/fixture', {}], ['https://secret@data.ecmwf.int/fixture', {}],
    ['https://data.ecmwf.int.invalid/fixture', {}], ['https://noaa-gefs-pds.s3.amazonaws.com/fixture', {}]]) {
    let calls = 0, emissions = 0;
    const original = response('60', { url, ...overrides });
    const wrapped = observeFetch(() => { calls++; return original; }, { product: 'weather', now: () => NOW,
      emit() { emissions++; } });
    assert.equal(await wrapped(url), original); assert.equal(calls, 1); assert.equal(emissions, 0);
  }
  const url = 'https://noaa-gefs-pds.s3.amazonaws.com/fixture', original = response(null, { url }), emitted = [];
  await observeFetch(() => original, { product: 'air_quality', now: () => NOW, emit: value => emitted.push(value) })(url);
  assert.deepEqual(emitted, [{ ...receipt('air_quality'), ...state('missing') }]);
});

test('first matching429 alone writes metadata, including failed diagnostic IO', async () => {
  for (const fail of [false, true]) {
    let calls = 0, emissions = 0;
    const original = response();
    const wrapped = observeFetch(() => { calls++; return original; }, { product: 'weather', now: () => NOW,
      emit() { emissions++; if (fail) throw new Error('occupied'); } });
    assert.equal(await wrapped(URL), original); assert.equal(await wrapped(URL), original);
    assert.equal(calls, 2); assert.equal(emissions, 1);
  }
});

test('fixed sidecars are exclusive private bounded regular files and preserve existing evidence', t => {
  const directory = privateDirectory(t);
  for (const [product, name] of [['weather', 'weather-origin-http.json'], ['air_quality', 'air-quality-origin-http.json']]) {
    writeReceipt(receipt(product), directory);
    const file = join(directory, name), { info, raw: before } = readOpened(file);
    assert.ok(info.isFile()); assert.equal(info.nlink, 1); assert.equal(info.mode & 0o777, 0o600);
    assert.equal(info.uid, process.getuid()); assert.ok(info.size <= MAX_RECEIPT_BYTES);
    assert.deepEqual(JSON.parse(before), receipt(product));
    assert.throws(() => writeReceipt(receipt(product), directory), { code: 'EEXIST' });
    assert.deepEqual(readOpened(file).raw, before);
    for (const secret of [URL, 'Range', 'headers', 'body']) assert.equal(before.includes(secret), false);
  }
});

test('sidecar symlinks, unsafe directory and unknown receipt fields cannot write', t => {
  const directory = privateDirectory(t), target = join(directory, 'must-not-create');
  symlinkSync(target, join(directory, 'weather-origin-http.json'));
  assert.throws(() => writeReceipt(receipt(), directory)); assert.equal(existsSync(target), false);
  const unsafe = join(directory, 'unsafe'); mkdirSync(unsafe, { mode: 0o755 });
  assert.throws(() => writeReceipt(receipt(), unsafe)); assert.deepEqual(readdirSync(unsafe), []);
  for (const changes of [{ raw_header: 'PRIVATE' }, { product: '../outside' }, { retry_after_state: 'missing', retry_not_before_ms: NOW },
    { retry_not_before_ms: NOW + 604801000 }, { retry_not_before_ms: NOW + 1 }, { observed_at_ms: NaN }]) {
    assert.throws(() => writeReceipt({ ...receipt('air_quality'), ...changes }, directory), TypeError);
  }
  assert.equal(existsSync(join(directory, 'air-quality-origin-http.json')), false);
});

test('ordinary import is inert; explicit product query wraps only fetch without starting it', t => {
  const directory = privateDirectory(t), module = new globalThis.URL('./weather-source-observer.mjs', import.meta.url).href;
  const program = `import assert from 'node:assert/strict';
    const original = globalThis.fetch; await import(${JSON.stringify(module)});
    assert.equal(globalThis.fetch, original);
    await import(${JSON.stringify(`${module}?product=weather`)});
    assert.notEqual(globalThis.fetch, original);`;
  const result = spawnSync(process.execPath, ['--input-type=module', '--eval', program],
    { cwd: directory, encoding: 'utf8', timeout: 5000 });
  assert.equal(result.status, 0, result.stderr); assert.deepEqual(readdirSync(directory), []);
  assert.deepEqual(readdirSync(directory), []);
});

test('malformed bootstrap selectors fail before application with zero fetch calls or sidecars', t => {
  const directory = privateDirectory(t), module = new globalThis.URL('./weather-source-observer.mjs', import.meta.url).href;
  const guard = `let calls = 0;
    globalThis.fetch = () => { calls++; throw Error('unexpected fake fetch'); };
    process.on('exit', () => process.stdout.write(JSON.stringify({ calls })));`;
  for (const query of ['?product=other', '?product=weather&path=outside', '?product=weather&product=air_quality',
    '?product=%77eather', '?product=weather#fragment', '#fragment']) {
    const invalid = spawnSync(process.execPath, ['--import', `data:text/javascript,${encodeURIComponent(guard)}`,
      '--import', `${module}${query}`, '--eval', 'process.exit(99)'],
      { cwd: directory, encoding: 'utf8', timeout: 5000, maxBuffer: 4096,
        env: { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8' } });
    assert.equal(invalid.status, 1, invalid.stderr);
    assert.deepEqual(JSON.parse(invalid.stdout), { calls: 0 });
    assert.deepEqual(readdirSync(directory), []);
  }
});

test('actual explicit --import captures one fake429 without rewriting script arguments', t => {
  const directory = privateDirectory(t), module = new globalThis.URL('./weather-source-observer.mjs', import.meta.url).href;
  const bootstrap = `globalThis.calls = 0; globalThis.original = {
    url: ${JSON.stringify(URL)}, status: 429, redirected: false,
    headers: { get(name) { if (name !== 'retry-after') throw Error('unexpected header access'); return '60'; } },
    get body() { throw Error('body access'); }
  }; globalThis.fetch = async (...args) => { globalThis.calls++; globalThis.forwarded = args; return globalThis.original; };`;
  const program = `import assert from 'node:assert/strict';
    const options = { signal: new AbortController().signal };
    const value = await fetch(${JSON.stringify(URL)}, options);
    assert.equal(value, globalThis.original); assert.equal(globalThis.calls, 1);
    assert.equal(globalThis.forwarded[1], options);
    assert.deepEqual(process.argv.slice(1), ['origin', '--unchanged']);`;
  const result = spawnSync(process.execPath, ['--import', `data:text/javascript,${encodeURIComponent(bootstrap)}`,
    '--import', `${module}?product=weather`, '--input-type=module', '--eval', program, 'origin', '--unchanged'],
    { cwd: directory, encoding: 'utf8', timeout: 5000, maxBuffer: 4096,
      env: { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8' } });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(readdirSync(directory), ['weather-origin-http.json']);
  const value = JSON.parse(readOpened(join(directory, 'weather-origin-http.json')).raw);
  assert.equal(value.product, 'weather'); assert.equal(value.retry_after_state, 'valid-seconds');
  assert.equal(value.retry_not_before_ms - value.observed_at_ms, 60000);
  assert.equal(value.status, 429);
});
