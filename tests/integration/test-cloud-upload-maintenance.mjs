// SPDX-License-Identifier: GPL-3.0-only
// Inert filesystem/HTTP observers. No core, GPG, Android, SDK or overlay proof.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import test from 'node:test';
import { binding, boundedFile, canonical, configuration, F, fixtureBytes, lengths, MAX_CIPHER, PHASES,
  PLAIN_BYTES, projectCustody, request, sourceProfile, main, validateBaseline, validateStorage } from './cloud-upload-maintenance.mjs';

const sha = x => createHash('sha256').update(x).digest('hex');
const keys = [1, 2, 3].map(n => Buffer.alloc(32, n).toString('hex'));
const array = h => [...Buffer.from(h, 'hex')];
const size = 786600;
const write = (path, value) => writeFile(path, JSON.stringify(value) + '\n', { mode: 0o600 });

test('source generations bind exact separate pins and predecessor versions without changing runtime', async () => {
  const old = sourceProfile(), stream = sourceProfile(2), challenge = sourceProfile(3), append = sourceProfile(4), flow = sourceProfile(5), close = sourceProfile(6);
  assert.deepEqual(old.previousVersion, [1, 2, 3, 4, 5]); assert.deepEqual(stream.previousVersion, [6]);
  assert.deepEqual(challenge.previousVersion, [7]);
  assert.deepEqual(append.previousVersion, [8]);
  assert.deepEqual(flow.previousVersion, [9]);
  assert.deepEqual(close.previousVersion, [10]);
  assert.deepEqual(close.revisions, { image: '1e812ec6424a539a336d230b99ae1c11a494ca29',
    cloud: '35598609d3fedb5d1241a479c1930c8a6b831661' });
  assert.deepEqual(flow.revisions, { cloud: '47b0f03b84913761570c3de7037ba5509b848c23',
    image: '9694a2b9dcb40aceefd78dbc0ab34303071a0ffd' });
  assert.deepEqual(stream.revisions, { cloud: '7d10c4943062c5a0ae46fc57e293dc3e33db3ed2',
    image: '949f208dbb48fcb734d4dfd33eb1933b69830a01' });
  assert.deepEqual(challenge.revisions, { cloud: 'e0db1cacf7bec2df3925ee454ec6216587b8ddef',
    image: '43029ea8b780de2376a3b7325d24a8e1c657f08e' });
  assert.deepEqual(append.revisions, { cloud: 'dda7a21818ece774445cf63d6e9a01fe0f2803b2',
    image: '10c46b9d6424929748e324fdd188a2f5ca77851a' });
  const pins = await Promise.all([old, stream, challenge, append, flow, close].map(async p => JSON.parse(await readFile(new URL(p.pinsFile, import.meta.url)))));
  assert.deepEqual(pins[0].runtime, pins[1].runtime);
  assert.deepEqual(pins[0].runtime, pins[2].runtime);
  assert.deepEqual(pins[0].runtime, pins[3].runtime);
  assert.deepEqual(pins[0].runtime, pins[4].runtime);
  assert.deepEqual(pins[0].runtime, pins[5].runtime);
  for (const [i, profile] of [old, stream, challenge, append, flow, close].entries()) {
    assert.equal(pins[i].version, i + 1);
    for (const name of ['cloud', 'image']) assert.equal(pins[i].sources[name].revision, profile.revisions[name]);
  }
  for (const bad of [true, '2', 0, 7, null]) assert.throws(() => sourceProfile(bad), /arguments/u);
});

test('explicit source selector rejects unknown or malformed arguments before any guest I/O', async () => {
  for (const tail of [['--profile-version', '1'], ['--profile-version', '7'], ['--profile-version', 'true'],
    ['--profile-version'], ['--other', '2'], ['--profile-version', '2', 'extra'],
    ['--profile-version', '5', '--profile-version', '6'], ['--profile-version', '6', '--profile-version', '5']]) {
    await assert.rejects(main(['upload', '/inert', ...tail]), /arguments/u);
  }
  for (const suffix of [[], ['--profile-version', '2'], ['--profile-version', '3'], ['--profile-version', '4'],
    ['--profile-version', '5'], ['--profile-version', '6']]) await assert.rejects(main(['upload', '/inert', ...suffix]), /guest_only/u);
});
function state(retired = [], withdrawn = false) {
  const replacements = withdrawn ? [0, 2, 3] : retired;
  const placements = [], records = lengths(size).map((bytes, i) => {
    const providers = [(i + 0) % 3, (i + 1) % 3, ...(replacements.includes(i) ? [i === 2 ? 1 : 2] : [])];
    const journals = providers.map((p, j) => ({ version: 1, provider_key: array(keys[p]), owner_key: array(sha('owner')),
      grant_hex: '616263', archive_id: array(sha(`${i}-${j}`)), ciphertext_bytes: bytes, sha256: array(sha(`fragment${i}`)),
      lease: `lease-${i}-${j}`, last_state: p === 0 && retired.includes(i) ? 4 : 3,
      last_stored_bytes: p === 0 && retired.includes(i) ? 0 : bytes,
      last_expiry: p === 0 && retired.includes(i) ? 0 : 5000 }));
    const replica = { copies: providers.map(p => ({ provider_key: array(keys[p]),
      charge: p === 0 ? (retired.includes(i) ? 'deleted' : withdrawn ? 'uncertain' : 'committed') : 'committed' })) };
    if (replacements.includes(i)) {
      const handoff = { phase: 'copying', from: i === 2 ? 1 : 0, to: 2,
        initial_journal: { ...journals[2], lease: null, last_state: null, last_stored_bytes: 0, last_expiry: 0 } };
      placements.push({ fragment: i, handoff });
      replica.handoff = { ...handoff, phase: retired.includes(i) ? 'complete' : 'delete_pending' };
    }
    return { replica, journals };
  });
  return { records, placements };
}
function baseline(retired = []) {
  const v = state(retired), p = projectCustody(v.records, v.placements, keys, size, retired, false, 1000);
  return { version: 1, retired_original_a: retired, replacement_identities: p.projections,
    physical_payload_charge: 2 * size, pending_retirements: 0, retained_copy_records: 8 + retired.length };
}
function storage(phase, retired = []) {
  const replacements = phase === 'upload' ? retired.length : 3;
  const uncertain = phase === 'exercise' ? [0, 2, 3].filter(i => !retired.includes(i)).reduce((n, i) => n + lengths(size)[i], 0) : 0;
  return { status: 'complete', local_process_joined: true, storage: { operation_complete: true,
    logical_ciphertext_bytes: size, fragment_count: 4, copies_per_fragment: 2, distinct_provider_identities: 3,
    owner_signature_verified: true, reserved_payload_bytes: 0, committed_payload_bytes: phase === 'finish' ? 0 : 2 * size,
    uncertain_payload_bytes: uncertain, physical_payload_charge_upper_bound: phase === 'finish' ? 0 : 2 * size + uncertain,
    fully_redundant_from_retained_receipts: phase !== 'finish', fragments_with_confirmed_unexpired_copy: phase === 'finish' ? 0 : 4,
    ...(replacements ? { report_version: 2, placement_authorizations: replacements, retained_copy_records: 8 + replacements,
      pending_retirements: phase === 'upload' ? 0 : 3 - retired.length,
      desired_copies_per_fragment: 2, replacement_overhead_included: true } : {}) } };
}

test('separate four phases, fixed real HTTP ciphertext geometry and deterministic incompressible input', () => {
  assert.deepEqual(PHASES, ['prepare', 'upload', 'exercise', 'finish']);
  assert.equal(F, 262144); assert.equal(MAX_CIPHER, 1048576);
  assert.equal(fixtureBytes().length, PLAIN_BYTES);
  assert.deepEqual(fixtureBytes(), fixtureBytes());
  assert.notDeepEqual(fixtureBytes().subarray(0, 32), fixtureBytes().subarray(32, 64));
  assert.deepEqual(lengths(3 * F + 1), [F, F, F, 1]);
  assert.deepEqual(lengths(MAX_CIPHER), [F, F, F, F]);
  for (const invalid of [0, 3 * F, MAX_CIPHER + 1, 3 * F + 0.5]) assert.throws(() => lengths(invalid));
});

test('private same-fd reads enforce actual size/mode and no symlink', async t => {
  const root = await mkdtemp(join(tmpdir(), 'cloud-upload-observer-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const path = join(root, 'record'); await writeFile(path, 'four', { mode: 0o600 });
  assert.equal((await boundedFile(path, 4)).toString(), 'four');
  await assert.rejects(boundedFile(path, 3), /private_file/u);
  await chmod(path, 0o644); await assert.rejects(boundedFile(path, 4));
  await chmod(path, 0o600); await symlink(path, join(root, 'link'));
  await assert.rejects(boundedFile(join(root, 'link'), 4));
});

test('canonical projections are key-order independent but not value/order independent', () => {
  assert.deepEqual(canonical({ z: [1, { b: 2, a: 1 }], a: true }), { a: true, z: [1, { a: 1, b: 2 }] });
  assert.notDeepEqual(canonical([0, 2]), canonical([2, 0]));
});

test('service fixture accepts only the exact production ephemeral-port and empty-origin defaults', async t => {
  const root = await mkdtemp(join(tmpdir(), 'cloud-upload-configuration-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const template = { version: 1, providers: keys.map((key, i) => ({ key, grant: join(root, `grant-${i}`) })),
    fragmentBytes: F, lifetimeSeconds: 1800, deadlineMs: 1800000 };
  const service = { version: 1, catalog: join(root, 'catalog'), workDirectory: join(root, 'work'),
    ownerUploads: { directory: join(root, 'uploads'), space: 'Uploads', storageConfig: join(root, 'storage-template.json') },
    storageMaintenance: { version: 2, expiresAt: 6000, maxSessions: 1, maxChargedBytes: 3 * MAX_CIPHER,
      perArchiveMaxChargedBytes: 3 * MAX_CIPHER, fromProviderKey: keys[0], lifetimeSeconds: 3600,
      renewBeforeSeconds: 7200, maximumTurnBytes: 8388608, existing: [] },
    maxOpenBytes: MAX_CIPHER, requestTimeoutMs: 1800000, maxConcurrent: 2 };
  await write(join(root, 'storage-template.json'), template);
  await write(join(root, 'service.json'), service);
  assert.deepEqual((await configuration(root)).service, service);
  for (const profile of [1, 2, 3]) assert.deepEqual((await configuration(root, profile)).template, template);
  await assert.rejects(configuration(root, 4), /configuration/u);
  for (const invalid of [false, 1, 'true', null]) {
    await write(join(root, 'storage-template.json'), { ...template, appendDiagnosticsV7: invalid });
    await assert.rejects(configuration(root, 4), /configuration/u);
  }
  await write(join(root, 'storage-template.json'), { ...template, appendDiagnosticsV7: true });
  assert.deepEqual(await configuration(root, 4), { template: { ...template, appendDiagnosticsV7: true }, service });
  await assert.rejects(configuration(root, 5), /configuration/u);
  for (const invalid of [false, 1, 'true', null]) {
    await write(join(root, 'storage-template.json'), { ...template, flowAcquireDiagnosticsV8: invalid });
    await assert.rejects(configuration(root, 5), /configuration/u);
  }
  for (const append of [true, false, null]) {
    await write(join(root, 'storage-template.json'), { ...template, flowAcquireDiagnosticsV8: true, appendDiagnosticsV7: append });
    await assert.rejects(configuration(root, 5), /configuration/u);
  }
  await write(join(root, 'storage-template.json'), { ...template, flowAcquireDiagnosticsV8: true });
  assert.deepEqual(await configuration(root, 5), { template: { ...template, flowAcquireDiagnosticsV8: true }, service });
  await assert.rejects(configuration(root, 4), /configuration/u);
  await assert.rejects(configuration(root, 6), /configuration/u);
  for (const invalid of [false, 1, 'true', null]) {
    await write(join(root, 'storage-template.json'), { ...template, tlsCloseDiagnosticsV9: invalid });
    await assert.rejects(configuration(root, 6), /configuration/u);
  }
  for (const flag of ['appendDiagnosticsV7', 'flowAcquireDiagnosticsV8']) {
    for (const value of [true, false, null]) {
      await write(join(root, 'storage-template.json'), { ...template, tlsCloseDiagnosticsV9: true, [flag]: value });
      await assert.rejects(configuration(root, 6), /configuration/u);
    }
  }
  await write(join(root, 'storage-template.json'), { ...template, tlsCloseDiagnosticsV9: true });
  assert.deepEqual(await configuration(root, 6), { template: { ...template, tlsCloseDiagnosticsV9: true }, service });
  for (const profile of [4, 5]) await assert.rejects(configuration(root, profile), /configuration/u);
  for (const profile of [1, 2, 3, 4, 5]) {
    const flags = profile === 4 ? { appendDiagnosticsV7: true } : profile === 5 ? { flowAcquireDiagnosticsV8: true } : {};
    for (const value of [true, false, null, 1, 'true']) {
      await write(join(root, 'storage-template.json'), { ...template, ...flags, tlsCloseDiagnosticsV9: value });
      await assert.rejects(configuration(root, profile), /configuration/u);
    }
  }
  await write(join(root, 'storage-template.json'), template);
  await write(join(root, 'service.json'), { ...service, port: 0, allowedOrigins: [] });
  await configuration(root);
  for (const extra of [{ port: 80 }, { allowedOrigins: ['https://example.invalid'] }, { allowedOrigins: '' }]) {
    await write(join(root, 'service.json'), { ...service, ...extra });
    await assert.rejects(configuration(root), /configuration/u);
  }
});

test('baseline admits zero to two actual early replacements, never an exhausted withdrawal case', () => {
  for (const retired of [[], [0], [2], [3], [0, 2], [0, 3], [2, 3]]) {
    assert.deepEqual(validateBaseline(baseline(retired), size), retired);
    assert.equal(validateStorage(storage('upload', retired), size, baseline(retired), 'upload').physical_payload_charge_upper_bound, 2 * size);
  }
  for (const r of [[0, 2, 3], [1], [0, 0], [3, 0]]) {
    assert.throws(() => validateBaseline({ ...baseline(), retired_original_a: r }, size));
  }
  const bad = baseline([0]); bad.replacement_identities[0].copy_identity_sha256 = 'bad';
  assert.throws(() => validateBaseline(bad, size));
});

test('post-withdrawal charge retains only the not-previously-retired original A copies', () => {
  for (const retired of [[], [0], [2, 3]]) {
    const result = validateStorage(storage('exercise', retired), size, baseline(retired), 'exercise');
    assert.equal(result.retained_copy_records, 11);
    assert.equal(result.pending_retirements, 3 - retired.length);
    assert.equal(result.uncertain_payload_bytes, [0, 2, 3].filter(i => !retired.includes(i)).reduce((n, i) => n + lengths(size)[i], 0));
    const bad = storage('exercise', retired); bad.storage.uncertain_payload_bytes = 0;
    assert.throws(() => validateStorage(bad, size, baseline(retired), 'exercise'));
  }
});

test('a dropped or substituted signed replacement/journal cannot satisfy custody projection', () => {
  const original = state([0], true), prior = state([0]);
  const projected = projectCustody(original.records, original.placements, keys, size, [0], true, 1000);
  assert.equal(projected.projections.length, 3);
  assert.deepEqual(projected.projections[0], projectCustody(prior.records, prior.placements, keys, size, [0], false, 1000).projections[0]);
  for (const mutate of [v => v.placements.pop(), v => { v.records[0].replica.handoff.phase = 'delete_pending'; },
    v => { v.records[2].journals[2].archive_id = array(sha('replacement')); },
    v => { v.records[2].journals[0].last_expiry = 1000; },
    v => { v.records[3].replica.copies[0].charge = 'deleted'; },
    v => { v.records[0].journals[0].last_stored_bytes = F; },
    v => { v.records[2].journals[2].last_stored_bytes--; }]) {
    const changed = structuredClone(original); mutate(changed);
    assert.throws(() => projectCustody(changed.records, changed.placements, keys, size, [0], true, 1000));
  }
});

test('original lease identity survives retirement, replacement and service restart', () => {
  const original = state(), advanced = state([0], true);
  const before = projectCustody(original.records, original.placements, keys, size, [], false, 1000);
  const after = projectCustody(advanced.records, advanced.placements, keys, size, [0], true, 1000);
  assert.deepEqual(before.originals, after.originals);
  advanced.records[0].journals[0].lease = 'new-lease';
  assert.notDeepEqual(before.originals, projectCustody(advanced.records, advanced.placements, keys, size, [0], true, 1000).originals);
});

test('all-copy deletion needs all eleven retained records, real completion and zero charge', () => {
  for (const retired of [[], [0], [0, 3]]) {
    const result = validateStorage(storage('finish', retired), size, baseline(retired), 'finish');
    assert.equal(result.physical_payload_charge_upper_bound, 0);
    for (const change of [v => { v.status = 'incomplete'; }, v => { v.local_process_joined = false; },
      v => { v.storage.retained_copy_records = 8; }, v => { v.storage.committed_payload_bytes = 1; },
      v => { v.storage.pending_retirements = 0; }]) {
      const bad = storage('finish', retired); change(bad);
      assert.throws(() => validateStorage(bad, size, baseline(retired), 'finish'));
    }
  }
});

test('real inert HTTP observer sends a full authenticated body and verifies complete GET bytes', async t => {
  const plain = fixtureBytes(), seen = [];
  const server = createServer(async (req, res) => {
    const chunks = []; for await (const part of req) chunks.push(part);
    seen.push({ method: req.method, path: req.url, token: req.headers.authorization, body: Buffer.concat(chunks) });
    if (req.headers.authorization !== 'Bearer fixture') { res.writeHead(401); res.end(); return; }
    res.writeHead(req.method === 'PUT' ? 201 : 200); res.end(req.method === 'PUT' ? undefined : plain);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`, cancel = new AbortController();
  const ctx = { signal: cancel.signal, deadline: performance.now() + 3000 };
  assert.equal((await request(origin, 'invalid', 'PUT', plain, ctx)).status, 401);
  assert.equal((await request(origin, 'fixture', 'PUT', plain, ctx)).status, 201);
  assert.deepEqual((await request(origin, 'fixture', 'GET', undefined, ctx)).body, plain);
  assert.deepEqual(seen[1].body, plain); assert.equal(seen[1].path, '/dav/spaces/Uploads/synthetic.bin');
  assert.equal(seen[1].token, 'Bearer fixture');
  cancel.abort(); await assert.rejects(request(origin, 'fixture', 'GET', undefined, ctx));
  await assert.rejects(request('http://example.invalid', 'fixture', 'GET', undefined, ctx), /configuration/u);
});

test('HTTP observer rejects oversize response without forwarding it to public evidence', async t => {
  const server = createServer((_req, res) => res.end(Buffer.alloc(MAX_CIPHER + 1)));
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  await assert.rejects(request(`http://127.0.0.1:${server.address().port}`, 'fixture', 'GET', undefined,
    { signal: new AbortController().signal, deadline: performance.now() + 3000 }), /http_body/u);
});

async function bindingFixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'cloud-upload-binding-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const object = join(root, 'object-' + 'a'.repeat(32));
  for (const path of [object, join(object, 'maintenance'), join(object, 'journal'), join(object, 'bundle'), join(object, 'catalog')]) {
    await mkdir(path, { mode: 0o700 });
  }
  const providers = keys.map((key, i) => ({ key, grant: join(root, `grant-${i}`) }));
  for (const p of providers) await writeFile(p.grant, 'fixture-grant', { mode: 0o600 });
  const p = { expiresAt: 4000, perArchiveMaxChargedBytes: 3 * MAX_CIPHER, fromProviderKey: keys[0],
    lifetimeSeconds: 3600, renewBeforeSeconds: 7200, maximumTurnBytes: 8388608 };
  const config = { service: { storageMaintenance: p }, template: { version: 1, providers } };
  await write(join(root, 'service.json'), config.service); await write(join(root, 'storage-template.json'), config.template);
  await write(join(object, 'core.json'), { ...config.template, stateDirectory: join(object, 'journal') });
  const intent = { version: 1, kind: 'cloud-upload-maintenance-intent', expiresAt: p.expiresAt,
    maximumChargedBytes: p.perArchiveMaxChargedBytes, configSha256: sha(await readFile(join(object, 'core.json'))),
    cipherBytes: size, cipherSha256: sha('cipher'), catalogSha256: sha('catalog'), fromProviderKey: keys[0],
    lifetimeSeconds: p.lifetimeSeconds, renewBeforeSeconds: p.renewBeforeSeconds, maximumTurnBytes: p.maximumTurnBytes,
    providers: providers.map(v => ({ ...v, sha256: sha('fixture-grant') })) };
  await write(join(object, 'MAINTENANCE.json'), intent);
  const enrollment = { version: 1, archive: join(object, 'journal'), expires: p.expiresAt,
    maximum_charged: p.perArchiveMaxChargedBytes, lifetime: p.lifetimeSeconds, renew_before: p.renewBeforeSeconds,
    maximum_turn: p.maximumTurnBytes, source: array(keys[0]), providers: keys.slice(1).map(array),
    grants: [Buffer.from('fixture-grant').toString('hex'), Buffer.from('fixture-grant').toString('hex')] };
  await write(join(object, 'maintenance/enrollment.json'), { enrollment, signature: '0'.repeat(128) });
  await write(join(object, 'bundle/receipt.json'), { version: 2, kind: 'volparossa-cloud-private-file', cipher_file: 'file.pgp',
    encryption: 'OpenPGP-AES256', source_consistency: 'owner-upload-snapshot', cipher_bytes: size, cipher_sha256: sha('cipher') });
  await write(join(object, 'catalog/receipt.json'), { cipher_sha256: sha('catalog') });
  await write(join(object, 'READY.json'), { version: 1, catalogSha256: sha('catalog') });
  await write(join(object, 'journal/fragments.json'), { manifest: { version: 1, ciphertext_bytes: size, sha256: array(sha('cipher')),
    fragment_bytes: F, copies_per_fragment: 2, providers: keys.map(key => ({ key: array(key), grant_sha256: array(sha('fixture-grant')) })),
    fragments: lengths(size).map((length, i) => ({ length, offset: i * F, copies: [0, 1].map(j => ({ provider: (i + j) % 3 })) })) } });
  const original = state();
  for (let i = 0; i < 4; i++) for (let j = 0; j < 2; j++) {
    const path = join(object, 'journal', `fragment-${String(i).padStart(4, '0')}`, `copy-${j}`);
    await mkdir(path, { recursive: true, mode: 0o700 }); await write(join(path, 'archive.json'), original.records[i].journals[j]);
  }
  return { root, object, config, enrollment };
}

test('retained production-envelope observer binds exact expiry, config, grants, root and original eight leases', async t => {
  const f = await bindingFixture(t), result = await binding(f.root, f.object, f.config);
  assert.equal(result.authority.expires_at, 4000); assert.equal(result.journal_identities.length, 8);
  assert.equal(result.authority.config_sha256, sha(await readFile(join(f.object, 'core.json'))));
  assert.equal(result.authority.root_sha256, sha(await readFile(join(f.object, 'journal/fragments.json'))));
  for (const change of [e => { e.expires++; }, e => { e.providers.reverse(); }, e => { e.maximum_charged++; },
    e => { e.grants[0] = '616263'; }, e => { e.source = array(keys[2]); }]) {
    const altered = structuredClone(f.enrollment); change(altered);
    await write(join(f.object, 'maintenance/enrollment.json'), { enrollment: altered, signature: '0'.repeat(128) });
    await assert.rejects(binding(f.root, f.object, f.config), /enrollment/u);
  }
});

test('driver calls only actual default Cloud service, never fixture enrollment, and preserves separate old proof', async () => {
  const source = await readFile(new URL('./cloud-upload-maintenance.mjs', import.meta.url), 'utf8');
  assert.match(source, /m\.startCloudService\(config\.service, \{ signal: ctx\.signal \}\)/u);
  assert.match(source, /scripts\/cloud-catalog\.mjs/u);
  assert.match(source, /for \(let round = 0; round < 2; round\+\+\)/u);
  assert.match(source, /request\(service\.origin, config\.service\.bearerToken, 'PUT'/u);
  assert.match(source, /request\(service\.origin, config\.service\.bearerToken, 'GET'/u);
  assert.doesNotMatch(source, /enrollMaintenance|\.deposit\(|spawnProcess|openMaintenance:|storageFactory:|sdk|npm|sudo/u);
  assert.match(source, /protected_routes_independently_proven: false/u);
  assert.match(source, /io_ordering_measured: false/u);
  assert.match(source, /previous_consumer_provision_sha256/u);
});
