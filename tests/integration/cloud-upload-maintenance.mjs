#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
// Separate disposable-guest continuation. Production Cloud creates authority;
// this observer neither enrolls archives nor schedules repairs or releases credit.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, readdir, readlink, realpath, unlink } from 'node:fs/promises';
import http from 'node:http';
import { hostname } from 'node:os';
import { dirname, join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const PHASES = Object.freeze(['prepare', 'upload', 'exercise', 'finish']);
export const F = 262144, MAX_CIPHER = 1048576, PLAIN_BYTES = 786433;
const CLOUD = '/opt/volparossa-cloud-upload', IMAGE = '/opt/volparossa-image-upload';
const PROVISION = '/opt/volparossa-cloud-upload-proof/provision.json';
const NODE = '/opt/volparossa-node/bin/node';
const REVISIONS = { cloud: 'cea181f1f80d57c9d8047093ed543f40ec43138d', image: 'eb9758453d094df5ea3ba045e993bd3d2dd47881' };
const STREAM_REVISIONS = { cloud: '7d10c4943062c5a0ae46fc57e293dc3e33db3ed2', image: '949f208dbb48fcb734d4dfd33eb1933b69830a01' };
const CHALLENGE_REVISIONS = { cloud: 'e0db1cacf7bec2df3925ee454ec6216587b8ddef', image: '43029ea8b780de2376a3b7325d24a8e1c657f08e' };
const APPEND_REVISIONS = { cloud: 'dda7a21818ece774445cf63d6e9a01fe0f2803b2', image: '10c46b9d6424929748e324fdd188a2f5ca77851a' };
const FLOW_REVISIONS = { cloud: '47b0f03b84913761570c3de7037ba5509b848c23', image: '9694a2b9dcb40aceefd78dbc0ab34303071a0ffd' };
const HASH = /^[0-9a-f]{64}$/u, A_FRAGMENTS = [0, 2, 3];
const COPY_FIELDS = ['provider_key', 'owner_key', 'grant_hex', 'archive_id', 'ciphertext_bytes', 'sha256'];
const CODES = new Set(['phase_deadline', 'authority_expired', 'authority_changed', 'private_file', 'private_directory',
  'input_changed', 'configuration', 'catalog_creation', 'cipher_identity', 'fragment_geometry', 'object_set',
  'enrollment', 'ready', 'owner_session', 'owner_join', 'http_status', 'http_body', 'storage_result',
  'baseline', 'custody', 'replacement_identity', 'journal_identity', 'plaintext_cleanup', 'previous_phase', 'cli_failed']);
const check = (value, code) => { if (!value) throw Object.assign(new Error(code), { code }); };
const sha = value => createHash('sha256').update(value).digest('hex');
const integer = (v, low, high) => Number.isSafeInteger(v) && v >= low && v <= high;
const hex = value => Array.isArray(value) && value.length === 32 && value.every(v => integer(v, 0, 255)) ? Buffer.from(value).toString('hex') : '';
const sameFile = (a, b) => ['dev', 'ino', 'mode', 'uid', 'nlink', 'size', 'mtimeNs', 'ctimeNs'].every(k => a[k] === b[k]);
export function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(k => [k, canonical(value[k])]));
  return value;
}
const equal = (a, b) => JSON.stringify(canonical(a)) === JSON.stringify(canonical(b));
const identity = value => sha(JSON.stringify(canonical(value)));
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const fragmentPath = (object, i) => join(object, 'journal', `fragment-${String(i).padStart(4, '0')}`);

export function sourceProfile(version = 1) {
  check(version === 1 || version === 2 || version === 3 || version === 4 || version === 5, 'arguments');
  if (version === 5) return { pinsFile: './cloud-upload-maintenance-pins-v5.json', revisions: { ...FLOW_REVISIONS }, previousVersion: [9] };
  if (version === 4) return { pinsFile: './cloud-upload-maintenance-pins-v4.json', revisions: { ...APPEND_REVISIONS }, previousVersion: [8] };
  if (version === 3) return { pinsFile: './cloud-upload-maintenance-pins-v3.json', revisions: { ...CHALLENGE_REVISIONS }, previousVersion: [7] };
  return version === 2
    ? { pinsFile: './cloud-upload-maintenance-pins-v2.json', revisions: { ...STREAM_REVISIONS }, previousVersion: [6] }
    : { pinsFile: './cloud-upload-maintenance-pins.json', revisions: { ...REVISIONS }, previousVersion: [1, 2, 3, 4, 5] };
}

export function fixtureBytes() {
  const result = Buffer.alloc(PLAIN_BYTES);
  for (let offset = 0; offset < result.length; offset += 32) {
    createHash('sha256').update(`VOLPAROSSA cloud upload ${offset}`).digest().copy(result, offset);
  }
  return result;
}
export function lengths(bytes) {
  check(integer(bytes, 3 * F + 1, MAX_CIPHER), 'fragment_geometry');
  return [F, F, F, bytes - 3 * F];
}
async function directory(path) {
  const st = await lstat(path, { bigint: true });
  check(st.isDirectory() && st.uid === BigInt(process.getuid()) && (st.mode & 0o7777n) === 0o700n
    && await realpath(path) === path, 'private_directory');
}
export async function boundedFile(path, maximum, publicFile = false) {
  const fd = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await fd.stat({ bigint: true });
    check(before.isFile() && before.nlink === 1n && before.size > 0n && before.size <= BigInt(maximum)
      && (publicFile ? before.uid === 0n && (before.mode & 0o6022n) === 0n
        : before.uid === BigInt(process.getuid()) && (before.mode & 0o7777n) === 0o600n), 'private_file');
    const bytes = Buffer.alloc(Number(before.size) + 1); let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await fd.read(bytes, offset, bytes.length - offset, offset);
      if (!bytesRead) break;
      offset += bytesRead;
    }
    check(offset === Number(before.size) && sameFile(before, await fd.stat({ bigint: true }))
      && sameFile(before, await lstat(path, { bigint: true })), 'input_changed');
    return bytes.subarray(0, offset);
  } finally { await fd.close(); }
}
async function json(path, maximum = 65536, publicFile = false) {
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(await boundedFile(path, maximum, publicFile)));
}
async function write(path, bytes) {
  await directory(dirname(path));
  const fd = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { await fd.writeFile(bytes); await fd.sync(); } finally { await fd.close(); }
}
async function writeJSON(path, value) {
  const bytes = Buffer.from(JSON.stringify(value) + '\n');
  check(bytes.length <= 16384, 'output_bound'); await write(path, bytes);
}
async function exists(path) { try { await lstat(path); return true; } catch (e) { if (e.code === 'ENOENT') return false; throw e; } }
async function fresh(path) { await directory(dirname(path)); await mkdir(path, { mode: 0o700 }); await directory(path); }
async function until(ctx, predicate) {
  while (!ctx.signal.aborted && performance.now() < ctx.deadline) {
    try { const value = await predicate(); if (value) return value; }
    catch (e) { if (e.code !== 'input_changed') throw e; }
    await sleep(25);
  }
  check(false, 'phase_deadline');
}

async function verifyPublic(path, record) {
  check(integer(record?.bytes, 1, 128 * MAX_CIPHER) && HASH.test(record.sha256), 'provision');
  const fd = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await fd.stat({ bigint: true });
    check(before.isFile() && before.uid === 0n && before.nlink === 1n && (before.mode & 0o6022n) === 0n
      && before.size === BigInt(record.bytes), 'provision');
    const hash = createHash('sha256'), chunk = Buffer.alloc(65536); let offset = 0;
    while (offset < record.bytes) {
      const { bytesRead } = await fd.read(chunk, 0, Math.min(chunk.length, record.bytes - offset), offset);
      check(bytesRead > 0, 'input_changed'); offset += bytesRead; hash.update(chunk.subarray(0, bytesRead));
    }
    check(hash.digest('hex') === record.sha256 && sameFile(before, await fd.stat({ bigint: true }))
      && sameFile(before, await lstat(path, { bigint: true })), 'provision');
  } finally { await fd.close(); }
}
async function guard(root, profileVersion = 1) {
  const profile = sourceProfile(profileVersion);
  check(process.platform === 'linux' && process.getuid() !== 0 && hostname() === 'volparossa-alpha'
    && process.execPath === NODE && /^\/opt\/va\.[a-f0-9]{32}\.[A-Za-z0-9]{6}\/u\/a$/u.test(root), 'guest_only');
  await directory(root);
  const raw = await boundedFile(PROVISION, 65536, true), p = JSON.parse(raw);
  const pinRaw = await boundedFile(fileURLToPath(new URL(profile.pinsFile, import.meta.url)), 65536, true);
  const pins = JSON.parse(pinRaw);
  check(p.version === profileVersion && pins.version === profileVersion
    && p.kind === 'cloud-upload-maintenance-runtime-provision' && p.success === true
    && p.guest_only === true && p.source_files_verified === true && p.runtime_files_verified === true
    && p.shared_adapter_verified === true && p.runtime_reused_without_modification === true
    && equal(p.pins, pins) && p.pins_sha256 === sha(pinRaw)
    && equal(Object.keys(pins.sources).sort(), ['cloud', 'image']), 'provision');
  const previousRaw = await boundedFile('/opt/volparossa-storage-consumers/provision.json', 65536, true);
  const previous = JSON.parse(previousRaw);
  check(sha(previousRaw) === p.previous_consumer_provision_sha256
    && profile.previousVersion.includes(previous.version), 'provision');
  for (const [name, source] of Object.entries(pins.sources)) {
    check(source.revision === profile.revisions[name], 'provision');
    for (const [file, record] of Object.entries(source.files)) {
      check(/^[A-Za-z0-9_./-]+$/u.test(file) && !file.startsWith('/') && !file.split('/').includes('..'), 'provision');
      await verifyPublic(join(name === 'cloud' ? CLOUD : IMAGE, file), record);
    }
  }
  await verifyPublic(NODE, pins.runtime.files['bin/node']);
  return sha(raw);
}
async function modules() {
  return Object.assign({}, ...await Promise.all([`${CLOUD}/scripts/cloud-serve.mjs`, `${IMAGE}/src/core-storage.mjs`]
    .map(path => import(pathToFileURL(path)))));
}
async function cli(args, signal) {
  check(!signal.aborted, 'phase_deadline');
  return new Promise((resolve, reject) => {
    const child = spawn(NODE, [join(CLOUD, 'scripts/cloud-catalog.mjs'), ...args], { detached: true, shell: false,
      env: { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8' }, stdio: ['ignore', 'pipe', 'ignore'] });
    let stopped = false, size = 0, chunks = [], escalation;
    const stop = () => {
      if (stopped) return; stopped = true;
      const kill = s => { try { if (child.pid > 1) process.kill(-child.pid, s); } catch {} };
      kill('SIGTERM'); escalation = setTimeout(() => kill('SIGKILL'), 15000);
    };
    signal.addEventListener('abort', stop, { once: true }); if (signal.aborted) stop();
    const timer = setTimeout(stop, 120000);
    child.stdout.on('data', part => { size += part.length; if (size > 65536) stop(); else chunks.push(part); });
    child.on('error', stop);
    child.on('close', (code, termination) => {
      clearTimeout(timer); clearTimeout(escalation); signal.removeEventListener('abort', stop);
      if (stopped || code !== 0 || termination !== null) { reject(Object.assign(new Error('cli_failed'), { code: 'cli_failed' })); return; }
      try { resolve(JSON.parse(Buffer.concat(chunks))); } catch { reject(Object.assign(new Error('cli_failed'), { code: 'cli_failed' })); }
      chunks = [];
    });
  });
}

export async function request(origin, token, method, body, ctx) {
  const base = new URL(origin);
  check(base.protocol === 'http:' && base.hostname === '127.0.0.1' && !base.username && !base.password
    && base.pathname === '/' && !base.search && !base.hash, 'configuration');
  check(body === undefined || Buffer.isBuffer(body) && body.length <= MAX_CIPHER, 'http_body');
  return new Promise((resolve, reject) => {
    const remaining = Math.floor(ctx.deadline - performance.now());
    if (ctx.signal.aborted || remaining <= 0) { reject(Object.assign(new Error('phase_deadline'), { code: 'phase_deadline' })); return; }
    const req = http.request(new URL('/dav/spaces/Uploads/synthetic.bin', base), { method, agent: false,
      signal: ctx.signal, maxHeaderSize: 8192, headers: { Authorization: `Bearer ${token}`, 'Accept-Encoding': 'identity',
        ...(body ? { 'Content-Length': body.length, 'Content-Type': 'application/octet-stream', 'If-None-Match': '*' } : {}) } }, res => {
      const chunks = []; let size = 0;
      res.on('data', part => { size += part.length; if (size > MAX_CIPHER) res.destroy(new Error('http_body')); else chunks.push(part); });
      res.on('error', reject);
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
    });
    const timer = setTimeout(() => req.destroy(Object.assign(new Error('phase_deadline'), { code: 'phase_deadline' })), remaining);
    req.on('close', () => clearTimeout(timer)); req.on('error', reject); req.end(body);
  });
}
export async function configuration(root, profileVersion = 1) {
  sourceProfile(profileVersion);
  const service = await json(join(root, 'service.json')), template = await json(join(root, 'storage-template.json'));
  const p = service.storageMaintenance;
  check(service.version === 1 && service.catalog === join(root, 'catalog') && service.workDirectory === join(root, 'work')
    && equal(service.ownerUploads, { directory: join(root, 'uploads'), space: 'Uploads', storageConfig: join(root, 'storage-template.json') })
    && !service.webDist && (service.port ?? 0) === 0 && Array.isArray(service.allowedOrigins ?? [])
    && (service.allowedOrigins ?? []).length === 0 && service.maxOpenBytes === MAX_CIPHER
    && service.requestTimeoutMs === 1800000 && p?.version === 2 && integer(p.expiresAt, 1, Number.MAX_SAFE_INTEGER)
    && p.maxSessions === 1 && p.maxChargedBytes === 3 * MAX_CIPHER && p.perArchiveMaxChargedBytes === 3 * MAX_CIPHER
    && p.lifetimeSeconds === 3600 && p.renewBeforeSeconds === 7200 && p.maximumTurnBytes === 8388608 && p.existing?.length === 0
    && template.version === 1 && !Object.hasOwn(template, 'stateDirectory') && !Object.hasOwn(template, 'copies')
    && template.fragmentBytes === F && template.lifetimeSeconds === 1800 && template.deadlineMs === 1800000
    && template.providers?.length === 3 && new Set(template.providers.map(p => p.key)).size === 3
    && template.providers.every(p => HASH.test(p.key)) && p.fromProviderKey === template.providers[0].key, 'configuration');
  if (profileVersion === 4) check(template.appendDiagnosticsV7 === true, 'configuration');
  if (profileVersion === 5) check(template.flowAcquireDiagnosticsV8 === true
    && !Object.hasOwn(template, 'appendDiagnosticsV7'), 'configuration');
  return { service, template };
}
async function objectRoot(root) {
  const names = await readdir(join(root, 'uploads'));
  check(names.length <= 2 && names.includes('LOCK'), 'object_set');
  const objects = names.filter(n => /^object-[0-9a-f]{32}$/u.test(n));
  check(objects.length === 1 && names.every(n => n === 'LOCK' || n === objects[0]), 'object_set');
  const object = join(root, 'uploads', objects[0]); await directory(object); return object;
}
function copyIdentity(journal) {
  check([...COPY_FIELDS, 'lease'].every(k => Object.hasOwn(journal, k)) && typeof journal.lease === 'string'
    && journal.lease.length <= 128 && journal.lease.length > 0, 'journal_identity');
  return identity(Object.fromEntries([...COPY_FIELDS, 'lease'].map(k => [k, journal[k]])));
}
export async function binding(root, object, config) {
  const intentRaw = await boundedFile(join(object, 'MAINTENANCE.json'), 32768), intent = JSON.parse(intentRaw);
  const enrollmentRaw = await boundedFile(join(object, 'maintenance/enrollment.json'), 32768), signed = JSON.parse(enrollmentRaw);
  const e = signed.enrollment, rootRaw = await boundedFile(join(object, 'journal/fragments.json'), 65536), m = JSON.parse(rootRaw).manifest;
  const cRaw = await boundedFile(join(object, 'core.json'), 65536), c = JSON.parse(cRaw);
  const receipt = await json(join(object, 'bundle/receipt.json'), 4096), p = config.service.storageMaintenance;
  const sizes = lengths(receipt.cipher_bytes);
  check(receipt.version === 2 && receipt.kind === 'volparossa-cloud-private-file' && receipt.cipher_file === 'file.pgp'
    && receipt.encryption === 'OpenPGP-AES256' && receipt.source_consistency === 'owner-upload-snapshot'
    && HASH.test(receipt.cipher_sha256), 'cipher_identity');
  check(equal(c, { ...config.template, stateDirectory: join(object, 'journal') })
    && intent.kind === 'cloud-upload-maintenance-intent' && intent.version === 1 && intent.expiresAt === p.expiresAt
    && intent.maximumChargedBytes === p.perArchiveMaxChargedBytes && intent.configSha256 === sha(cRaw)
    && intent.cipherSha256 === receipt.cipher_sha256 && intent.cipherBytes === receipt.cipher_bytes
    && intent.catalogSha256 === (await json(join(object, 'catalog/receipt.json'), 4096)).cipher_sha256
    && intent.fromProviderKey === p.fromProviderKey && intent.lifetimeSeconds === p.lifetimeSeconds
    && intent.renewBeforeSeconds === p.renewBeforeSeconds && intent.maximumTurnBytes === p.maximumTurnBytes
    && intent.providers?.length === 3, 'enrollment');
  for (let i = 0; i < 3; i++) check(equal(intent.providers[i], { ...c.providers[i],
    sha256: sha(await boundedFile(c.providers[i].grant, 2048)) }), 'enrollment');
  check(e?.version === 1 && e.archive === c.stateDirectory && e.expires === p.expiresAt
    && e.maximum_charged === p.perArchiveMaxChargedBytes && e.lifetime === p.lifetimeSeconds
    && e.renew_before === p.renewBeforeSeconds && e.maximum_turn === p.maximumTurnBytes
    && hex(e.source) === c.providers[0].key && equal(e.providers?.map(hex), c.providers.slice(1).map(p => p.key))
    && Array.isArray(e.grants) && e.grants.length === 2 && typeof signed.signature === 'string'
    && /^[0-9a-f]{128}$/u.test(signed.signature), 'enrollment');
  for (let i = 0; i < 2; i++) check(/^(?:[0-9a-f]{2}){1,2048}$/u.test(e.grants[i])
    && sha(Buffer.from(e.grants[i], 'hex')) === intent.providers[i + 1].sha256, 'enrollment');
  check(m?.version === 1 && m.ciphertext_bytes === receipt.cipher_bytes && hex(m.sha256) === receipt.cipher_sha256
    && m.fragment_bytes === F && m.copies_per_fragment === 2 && m.providers?.length === 3
    && m.providers.every((p, i) => hex(p.key) === c.providers[i].key && hex(p.grant_sha256) === intent.providers[i].sha256)
    && m.fragments?.length === 4 && m.fragments.every((f, i) => f.length === sizes[i] && f.offset === i * F
      && f.copies?.length === 2 && f.copies.every((c, j) => c.provider === (i + j) % 3)), 'fragment_geometry');
  const journals = [];
  for (let i = 0; i < 4; i++) for (let j = 0; j < 2; j++) journals.push(copyIdentity(await json(join(fragmentPath(object, i), `copy-${j}/archive.json`), 16384)));
  const ready = await json(join(object, 'READY.json'), 4096);
  check(equal(ready, { version: 1, catalogSha256: intent.catalogSha256 }), 'ready');
  return { object: object.split('/').at(-1), service_sha256: sha(await boundedFile(join(root, 'service.json'), 65536)),
    template_sha256: sha(await boundedFile(join(root, 'storage-template.json'), 65536)),
    cipher_bytes: receipt.cipher_bytes, cipher_sha256: receipt.cipher_sha256, journal_identities: journals,
    authority: { expires_at: e.expires, maximum_charged_bytes: e.maximum_charged, intent_sha256: sha(intentRaw),
      enrollment_sha256: sha(enrollmentRaw), config_sha256: sha(cRaw), root_sha256: sha(rootRaw) } };
}

export function validateBaseline(baseline, bytes) {
  lengths(bytes);
  const r = baseline?.retired_original_a;
  check(baseline?.version === 1 && Array.isArray(r) && r.length <= 2 && equal(r, [...new Set(r)].sort())
    && r.every(i => A_FRAGMENTS.includes(i)) && baseline.physical_payload_charge === 2 * bytes
    && baseline.pending_retirements === 0 && baseline.retained_copy_records === 8 + r.length, 'baseline');
  validateProjections(baseline.replacement_identities, r); return r;
}
function validateProjections(value, indexes) {
  check(Array.isArray(value) && value.length === indexes.length && value.every((v, i) =>
    equal(Object.keys(v).sort(), ['authorization_sha256', 'copy_identity_sha256', 'fragment'])
    && v.fragment === indexes[i] && HASH.test(v.authorization_sha256) && HASH.test(v.copy_identity_sha256)), 'replacement_identity');
}
export function validateStorage(result, bytes, baseline, phase) {
  const retired = baseline ? validateBaseline(baseline, bytes) : [], s = result?.storage;
  const repaired = phase === 'exercise' || phase === 'finish', replacements = repaired ? 3 : retired.length;
  const uncertain = phase === 'exercise' ? A_FRAGMENTS.filter(i => !retired.includes(i)).reduce((n, i) => n + lengths(bytes)[i], 0) : 0;
  check(['upload', 'exercise', 'finish'].includes(phase) && result?.status === 'complete' && result.local_process_joined === true
    && s?.operation_complete === true && s.logical_ciphertext_bytes === bytes && s.fragment_count === 4
    && s.copies_per_fragment === 2 && s.distinct_provider_identities === 3 && s.owner_signature_verified === true
    && s.reserved_payload_bytes === 0 && s.committed_payload_bytes === (phase === 'finish' ? 0 : 2 * bytes)
    && s.uncertain_payload_bytes === uncertain && s.physical_payload_charge_upper_bound === (phase === 'finish' ? 0 : 2 * bytes + uncertain), 'storage_result');
  if (phase !== 'finish') check(s.fully_redundant_from_retained_receipts === true && s.fragments_with_confirmed_unexpired_copy === 4, 'storage_result');
  if (replacements) check(s.report_version === 2 && s.placement_authorizations === replacements
    && s.retained_copy_records === 8 + replacements && s.pending_retirements === (repaired ? 3 - retired.length : 0)
    && s.desired_copies_per_fragment === 2 && s.replacement_overhead_included === true, 'storage_result');
  else check(!Object.hasOwn(s, 'report_version'), 'storage_result');
  return { logical_ciphertext_bytes: bytes, committed_payload_bytes: s.committed_payload_bytes,
    uncertain_payload_bytes: uncertain, physical_payload_charge_upper_bound: s.physical_payload_charge_upper_bound,
    fragment_count: 4, copies_per_fragment: 2, retained_copy_records: 8 + replacements,
    pending_retirements: repaired ? 3 - retired.length : 0 };
}

// Core status verifies signed placements; this bounded projection binds their
// exact original bytes/identities across the service restart and withdrawal.
export function projectCustody(records, placements, keys, bytes, retired, withdrawn, now) {
  const sizes = lengths(bytes), projections = [], originals = [];
  const expected = withdrawn ? A_FRAGMENTS : retired;
  check(records.length === 4 && placements.length === expected.length
    && equal(placements.map(e => e.fragment).sort(), expected), 'custody');
  for (let i = 0; i < 4; i++) {
    const { replica, journals } = records[i], replaced = expected.includes(i);
    check(replica.copies?.length === (replaced ? 3 : 2) && journals.length === replica.copies.length, 'custody');
    for (let j = 0; j < journals.length; j++) {
      const journal = journals[j], provider = j < 2 ? (i + j) % 3 : i === 2 ? 1 : 2;
      const charge = provider === 0 ? (retired.includes(i) ? 'deleted' : withdrawn ? 'uncertain' : 'committed') : 'committed';
      check(hex(replica.copies[j].provider_key) === keys[provider] && replica.copies[j].charge === charge
        && hex(journal.provider_key) === keys[provider] && journal.ciphertext_bytes === sizes[i]
        && journal.last_state === (charge === 'deleted' ? 4 : 3)
        && journal.last_stored_bytes === (charge === 'deleted' ? 0 : sizes[i])
        && (charge === 'deleted' ? journal.last_expiry === 0 : journal.last_expiry > now), 'custody');
      if (j < 2) originals.push(copyIdentity(journal));
    }
    if (replaced) {
      const entry = placements.find(e => e.fragment === i), intent = entry.handoff, journal = journals[2];
      check(intent?.phase === 'copying' && intent.from === (i === 2 ? 1 : 0) && intent.to === 2
        && equal(replica.handoff, { ...intent, phase: retired.includes(i) ? 'complete' : 'delete_pending' })
        && COPY_FIELDS.every(k => equal(journal[k], intent.initial_journal[k])), 'replacement_identity');
      projections.push({ fragment: i, authorization_sha256: identity(entry), copy_identity_sha256: copyIdentity(journal) });
    }
  }
  return { projections, originals };
}
async function records(object) {
  const result = [];
  for (let i = 0; i < 4; i++) {
    const path = fragmentPath(object, i), replica = await json(join(path, 'replicas.json'), 32768);
    check(Array.isArray(replica.copies) && integer(replica.copies.length, 2, 3), 'custody');
    const journals = [];
    for (let j = 0; j < replica.copies.length; j++) journals.push(await json(join(path, `copy-${j}/archive.json`), 16384));
    result.push({ replica, journals });
  }
  const path = join(object, 'journal/placement-authorizations.json');
  const placements = await exists(path) ? (await json(path, MAX_CIPHER)).authority.placements : [];
  return { records: result, placements };
}
async function custody(object, template, bound, baseline, withdrawn) {
  const raw = await records(object);
  const retired = baseline?.retired_original_a ?? raw.records.flatMap(({ replica }, i) =>
    replica.copies.some(c => hex(c.provider_key) === template.providers[0].key && c.charge === 'deleted') ? [i] : []);
  check(retired.length <= 2 && retired.every(i => A_FRAGMENTS.includes(i)), 'baseline');
  const projected = projectCustody(raw.records, raw.placements, template.providers.map(p => p.key),
    bound.cipher_bytes, retired, withdrawn, Math.floor(Date.now() / 1000));
  check(equal(projected.originals, bound.journal_identities), 'authority_changed');
  if (!withdrawn) return { version: 1, retired_original_a: retired, replacement_identities: projected.projections,
    physical_payload_charge: 2 * bound.cipher_bytes, pending_retirements: 0, retained_copy_records: 8 + retired.length };
  check(baseline.replacement_identities.every(old => equal(old, projected.projections.find(v => v.fragment === old.fragment))), 'replacement_identity');
  return projected.projections;
}
async function procText(path, maximum) {
  const fd = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try { const bytes = Buffer.alloc(maximum + 1), result = await fd.read(bytes, 0, bytes.length, 0);
    check(result.bytesRead <= maximum, 'owner_session'); return bytes.subarray(0, result.bytesRead).toString();
  } finally { await fd.close(); }
}
async function owners(config, object) {
  const tasks = await readdir('/proc/self/task'), pids = new Set(), result = [];
  check(tasks.length <= 64 && tasks.every(n => /^[0-9]+$/u.test(n)), 'owner_session');
  for (const task of tasks) {
    let raw; try { raw = await procText(`/proc/self/task/${task}/children`, 4096); } catch (e) { if (e.code === 'ENOENT') continue; throw e; }
    check(/^[0-9 ]*$/u.test(raw), 'owner_session'); for (const pid of raw.trim().split(' ').filter(Boolean)) pids.add(pid);
  }
  check(pids.size <= 32, 'owner_session');
  for (const pid of pids) try {
    const path = `/proc/${pid}`;
    if (await readlink(`${path}/exe`) !== config.coreBinary) continue;
    const start = raw => raw.slice(raw.lastIndexOf(')') + 2).trim().split(/\s+/u)[19];
    const before = start(await procText(`${path}/stat`, 8192));
    const args = (await procText(`${path}/cmdline`, 16384)).split('\0'); args.pop();
    check(equal(args, [config.coreBinary, '--control-socket', config.controlSocket, 'storage', 'fragments', 'maintenance', 'serve',
      '--enrollment', join(object, 'maintenance'), '--identity', config.identity, '--passphrase-file', config.passphraseFile]), 'owner_session');
    check((await procText(`${path}/status`, 16384)).match(/^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/mu)?.slice(1)
      .every(v => Number(v) === process.getuid()) && /^[0-9]+$/u.test(before), 'owner_session');
    if (before === start(await procText(`${path}/stat`, 8192))) result.push(`${pid}:${before}`);
  } catch (e) { if (!['ENOENT', 'ESRCH'].includes(e.code)) throw e; }
  check(result.length <= 1, 'owner_session'); return result;
}
async function ownSession(ctx, service, object, config, expires) {
  await until(ctx, async () => {
    const status = await service.maintenanceStatus();
    check(status?.version === 2 && status.automatic_enrollment === true && status.automatic_grant_refresh === false
      && status.configured_sessions === 1 && status.reserved_archive_ceiling_bytes === 3 * MAX_CIPHER
      && status.new_authorization_allowed === false && status.expires_at === expires, 'owner_session');
    const s = status.sessions?.[0];
    check(s?.expires_at === expires && s.reserved_ceiling_bytes === 3 * MAX_CIPHER
      && s.authority_uncertain === false, 'owner_session');
    return s.state === 'active' && s.owned_session === true && (await owners(config, object)).length === 1;
  });
}
async function withCore(m, object, operation, signal) {
  const core = await m.CoreStorage.open(join(object, 'core.json'));
  try { return await core[operation]({ signal }); } finally { await core.close(); }
}
async function closeService(service, ctx, object, template) {
  await service.close(); check((await owners(template, object)).length === 0, 'owner_join');
  check((await readdir(join(ctx.root, 'work'))).length === 0, 'plaintext_cleanup');
}
function constrainAuthority(ctx, expires) {
  check(expires * 1000 > Date.now(), 'authority_expired');
  const remaining = Math.min(ctx.deadline - performance.now(), expires * 1000 - Date.now());
  ctx.deadline = Math.min(ctx.deadline, performance.now() + remaining);
  return setTimeout(() => ctx.cancel.abort(), Math.max(1, remaining));
}
const publicBinding = bound => ({ cipher_bytes: bound.cipher_bytes, cipher_sha256: bound.cipher_sha256,
  plaintext_bytes: PLAIN_BYTES, plaintext_sha256: sha(fixtureBytes()), fragment_bytes: F, authority: bound.authority });

async function prepare(ctx) {
  ctx.stage = 'prepare_catalog';
  await fresh(join(ctx.root, 'work')); await fresh(join(ctx.root, 'uploads'));
  await writeJSON(join(ctx.root, 'selection.json'), { version: 1, files: [] });
  await write(join(ctx.root, 'plaintext.bin'), fixtureBytes());
  const result = await cli(['create', '--selection', join(ctx.root, 'selection.json'), '--catalog', join(ctx.root, 'catalog'),
    '--work-directory', join(ctx.root, 'work'), '--max-total-bytes', String(MAX_CIPHER)], ctx.signal);
  check(result.files === 0 && result.encrypted === true && result.sourceFallback === false, 'catalog_creation');
  check((await readdir(join(ctx.root, 'work'))).length === 0, 'plaintext_cleanup');
  return { plaintext_bytes: PLAIN_BYTES, plaintext_sha256: sha(fixtureBytes()), catalog_files: 0, catalog_encrypted: true };
}
async function upload(ctx, m) {
  ctx.stage = 'upload_start';
  const config = await configuration(ctx.root, ctx.profileVersion), expiry = config.service.storageMaintenance.expiresAt;
  const timer = constrainAuthority(ctx, expiry); let service, object;
  try {
    const plain = await boundedFile(join(ctx.root, 'plaintext.bin'), MAX_CIPHER);
    check(plain.equals(fixtureBytes()), 'cipher_identity');
    service = await m.startCloudService(config.service, { signal: ctx.signal });
    check((await request(service.origin, 'invalid', 'PUT', plain, ctx)).status === 401, 'http_status');
    check((await readdir(join(ctx.root, 'uploads'))).every(n => n === 'LOCK'), 'object_set');
    ctx.stage = 'upload_put';
    const reply = await request(service.origin, config.service.bearerToken, 'PUT', plain, ctx);
    check(reply.status === 201 && reply.body.length === 0, 'http_status');
    object = await objectRoot(ctx.root);
    const bound = await binding(ctx.root, object, config);
    const cipher = await boundedFile(join(object, 'bundle/file.pgp'), MAX_CIPHER);
    check(cipher.length === bound.cipher_bytes && sha(cipher) === bound.cipher_sha256, 'cipher_identity');
    await ownSession(ctx, service, object, config.template, expiry);
    ctx.stage = 'upload_close'; await closeService(service, ctx, object, config.template);
    // Explicit progress reconciles existing leases after cancelling background
    // work. It creates no new archive, lease identity, enrollment or deadline.
    ctx.stage = 'upload_baseline';
    check((await withCore(m, object, 'progress', ctx.signal)).status === 'complete', 'storage_result');
    const baseline = await custody(object, config.template, bound, null, false);
    const accounting = validateStorage(await withCore(m, object, 'status', ctx.signal), bound.cipher_bytes, baseline, 'upload');
    check(equal(await binding(ctx.root, object, config), bound), 'authority_changed');
    await writeJSON(join(ctx.root, 'cloud-upload-binding.json'), { version: 1, provision_sha256: ctx.provision, bound, baseline });
    return { ...publicBinding(bound), baseline, accounting, http_put_status: 201, wrong_token_status: 401,
      automatic_enrollment: true, ready_observed: true, owned_session_observed: true,
      ordering_source_enforced: true, io_ordering_measured: false, owner_joined: true };
  } finally { try { await service?.close(); } finally { clearTimeout(timer); } }
}
async function retained(ctx) {
  const value = await json(join(ctx.root, 'cloud-upload-binding.json'), 16384), config = await configuration(ctx.root, ctx.profileVersion);
  check(value.version === 1 && value.provision_sha256 === ctx.provision, 'previous_phase');
  const object = await objectRoot(ctx.root);
  check(equal(await binding(ctx.root, object, config), value.bound), 'authority_changed');
  validateBaseline(value.baseline, value.bound.cipher_bytes);
  return { ...value, object, config };
}
async function coldCache(object, bound) {
  const path = join(object, 'bundle/file.pgp');
  if (await exists(path)) {
    const bytes = await boundedFile(path, MAX_CIPHER);
    check(bytes.length === bound.cipher_bytes && sha(bytes) === bound.cipher_sha256, 'cipher_identity');
    await unlink(path); // Only this exact newly created, hash-verified cache.
  }
  check(!await exists(path), 'cipher_identity');
}
async function exercise(ctx, m) {
  ctx.stage = 'exercise_binding';
  const { object, config, bound, baseline } = await retained(ctx), reads = [];
  const timer = constrainAuthority(ctx, bound.authority.expires_at); let projections, accounting;
  try {
    for (let round = 0; round < 2; round++) {
      ctx.stage = round ? 'exercise_restart' : 'exercise_repair';
      await coldCache(object, bound);
      const service = await m.startCloudService(config.service, { signal: ctx.signal });
      try {
        await ownSession(ctx, service, object, config.template, bound.authority.expires_at);
        // A partial current turn is readiness-not-yet, not proof. The joined
        // core status below still independently validates actual signed state.
        await until(ctx, async () => {
          try { return await custody(object, config.template, bound, baseline, true); }
          catch (e) { if (['custody', 'replacement_identity', 'input_changed', 'ENOENT'].includes(e.code)) return null; throw e; }
        });
        ctx.stage = round ? 'exercise_second_get' : 'exercise_first_get';
        check((await request(service.origin, 'invalid', 'GET', undefined, ctx)).status === 401, 'http_status');
        const reply = await request(service.origin, config.service.bearerToken, 'GET', undefined, ctx);
        check(reply.status === 200 && reply.body.equals(fixtureBytes()), 'http_body');
        await closeService(service, ctx, object, config.template);
        const progress = await withCore(m, object, 'progress', ctx.signal);
        // Unavailable A is still charged. Its Progress request can honestly be
        // incomplete; require joined execution and the exact retained state,
        // not a false acknowledgement from the withdrawn provider.
        check(['complete', 'incomplete'].includes(progress.status) && progress.local_process_joined === true, 'storage_result');
        accounting = validateStorage(await withCore(m, object, 'status', ctx.signal), bound.cipher_bytes, baseline, 'exercise');
        const current = await custody(object, config.template, bound, baseline, true);
        check(!projections || equal(projections, current), 'replacement_identity'); projections = current;
        check(equal(await binding(ctx.root, object, config), bound), 'authority_changed');
        reads.push({ authenticated_get_body_verified: true, cipher_cache_absent_before_read: true,
          plaintext_bytes: PLAIN_BYTES, plaintext_sha256: sha(reply.body), wrong_token_status: 401,
          owned_session_observed: true, owner_joined: true });
      } finally { await service.close(); }
    }
    return { ...publicBinding(bound), baseline, repair_replacement_identities: projections,
      new_replacements_after_withdrawal: 3 - baseline.retired_original_a.length, accounting, reads,
      service_restarted_between_reads: true, original_authority_and_journals_retained: true };
  } finally { clearTimeout(timer); }
}
async function finish(ctx, m) {
  ctx.stage = 'finish_delete';
  const { object, config, bound, baseline } = await retained(ctx);
  check((await owners(config.template, object)).length === 0, 'owner_join');
  const accounting = validateStorage(await withCore(m, object, 'delete', ctx.signal), bound.cipher_bytes, baseline, 'finish');
  check(equal(await binding(ctx.root, object, config), bound), 'authority_changed');
  check((await owners(config.template, object)).length === 0, 'owner_join');
  return { ...publicBinding(bound), accounting, all_retained_copies_delete_acknowledged: true,
    owner_joined: true, private_fixture_removed: false };
}

export async function main(argv) {
  let profileVersion = 1;
  if (argv.length === 4 && argv[2] === '--profile-version') {
    check(argv[3] === '2' || argv[3] === '3' || argv[3] === '4' || argv[3] === '5', 'arguments'); profileVersion = Number(argv[3]); argv = argv.slice(0, 2);
  }
  check(argv.length === 2 && PHASES.includes(argv[0]), 'arguments'); process.umask(0o077);
  const [phase, root] = argv, provision = await guard(root, profileVersion), cancel = new AbortController();
  const abort = () => cancel.abort(); for (const name of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.on(name, abort);
  const timer = setTimeout(abort, 1800000);
  const ctx = { root, provision, profileVersion, cancel, signal: cancel.signal, deadline: performance.now() + 1800000, stage: 'phase_start' };
  try {
    check(!await exists(join(root, `cloud-upload-${phase}.json`)), 'previous_phase');
    if (phase !== 'prepare') {
      const previous = await json(join(root, `cloud-upload-${PHASES[PHASES.indexOf(phase) - 1]}.json`), 16384);
      check(previous.version === 1 && previous.kind === 'cloud-upload-maintenance' && previous.passed === true
        && previous.provision_sha256 === provision, 'previous_phase');
    }
    const evidence = await ({ prepare, upload, exercise, finish })[phase](ctx, await modules());
    check(!ctx.signal.aborted && performance.now() < ctx.deadline, 'phase_deadline');
    const report = { version: 1, kind: 'cloud-upload-maintenance', phase, passed: true, provision_sha256: provision,
      ...evidence, scope: { synthetic_inputs: true, protected_routes_independently_proven: false,
        provider_cleanup_independently_proven: false, automatic_grant_refresh: false, private_keys_exported: false,
        opencloud_account_server_proven: false, io_ordering_measured: false } };
    await writeJSON(join(root, `cloud-upload-${phase}.json`), report); return report;
  } catch (error) {
    const report = { version: 1, kind: 'cloud-upload-maintenance', phase, passed: false, provision_sha256: provision,
      stage: ctx.stage, code: ctx.signal.aborted ? 'phase_deadline' : CODES.has(error.code) ? error.code : 'application_failed', cleanup_confirmed: false };
    try { await writeJSON(join(root, `cloud-upload-${phase}.json`), report); } catch { /* Never replace the original failure. */ }
    return report;
  } finally {
    clearTimeout(timer); for (const name of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.off(name, abort);
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { const report = await main(process.argv.slice(2)); process.stdout.write(JSON.stringify(report) + '\n'); process.exitCode = report.passed ? 0 : 1; }
  catch { process.stderr.write('{"version":1,"kind":"cloud-upload-maintenance","passed":false,"code":"phase_failed"}\n'); process.exitCode = 1; }
}
