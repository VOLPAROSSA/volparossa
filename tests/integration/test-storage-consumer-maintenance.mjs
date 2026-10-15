// SPDX-License-Identifier: GPL-3.0-only
// Inert contracts only. These do not execute GPG, a core, or application code.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, chmod, symlink, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { boundedFile, fixtureBytes, ForegroundObservation, MAX_CIPHER, PHASES, PLAIN_BYTES,
  consumerFailureReport, depositDiagnostic, parseProcStat, replacementReady, requirePublishComplete, retainedSnapshot,
  retentionAdvanced, validateAppendProfile, validateCheckpoint, validateStorage,
  createPublishCatalog, publish, withPublishCore } from './storage-consumer-maintenance.mjs';

const hash = value => createHash('sha256').update(value).digest('hex');
const keys = [1, 2, 3].map(v => Buffer.alloc(32, v).toString('hex'));
const copy = (key, charge = 'committed') => ({ provider_key: [...Buffer.from(key, 'hex')], charge });
const repaired = () => [0, 1, 2, 3].map(i => ({ copies: i === 1 ? [copy(keys[1]), copy(keys[2])]
  : [copy(keys[0], 'uncertain'), copy(keys[1]), copy(keys[2])], ...(i === 1 ? {} : { handoff: { phase: 'delete_pending' } }) }));
function storage(kind = 'repaired') {
  return { status: 'complete', local_process_joined: true, storage: {
    operation_complete: true, logical_ciphertext_bytes: 100, fragment_count: 4, copies_per_fragment: 2,
    distinct_provider_identities: 3, owner_signature_verified: true, reserved_payload_bytes: 0,
    report_version: 2, placement_authorizations: 3, retained_copy_records: 11, pending_retirements: 3,
    replacement_overhead_included: true, desired_copies_per_fragment: 2,
    committed_payload_bytes: kind === 'deleted' ? 0 : 200,
    uncertain_payload_bytes: kind === 'repaired' ? 75 : 0,
    physical_payload_charge_upper_bound: kind === 'deleted' ? 0 : kind === 'repaired' ? 275 : 200,
    fragments_with_confirmed_unexpired_copy: 4, fully_redundant_from_retained_receipts: true,
  } };
}

function publishFailure(value, app = 'cloud', operation = 'deposit', aborted = false, profileVersion = 1) {
  try { requirePublishComplete(value, app, operation, profileVersion); assert.fail('expected rejection'); }
  catch (error) {
    assert.equal(error.code, 'publish_operation');
    return consumerFailureReport({ provision: 'a'.repeat(64), stage: `${app}_publish`, signal: { aborted } }, 'publish', error);
  }
}

const transferFailure = () => ({ fragment_index: 2, copy_index: 1, operation: 'reserve',
  stage: 'agent_terminal', category: 'io', agent_code: null });
const diagnostics = (failures = [transferFailure()]) => ({ version: 1, failures, omitted_failures: 0 });
const detailedFailure = (stage = 'route_connect', deadline_scope = 'none') => ({
  ...transferFailure(), stage: 'agent_ready', category: 'agent_rejected', agent_code: 'CONTENT_UNAVAILABLE',
  agent_detail: { stage, deadline_scope } });
const detailedDiagnostics = (failures = [detailedFailure()]) => ({ version: 2, failures, omitted_failures: 0 });
const tlsDiagnostics = (tls_failure = 'authentication') => ({ version: 3, omitted_failures: 0,
  failures: [{ ...detailedFailure('tls_handshake'), agent_detail: {
    stage: 'tls_handshake', deadline_scope: 'none', tls_failure } }] });
const outcomeDiagnostics = () => ({ version: 4, omitted_failures: 0, failures: [{
  ...transferFailure(), operation: 'finalize', stage: 'wire_receipt', agent_detail: null,
  agent_outcome: { status: 'observed', detail: { phase: 'remote_receipt_read', category: 'timeout', deadline_scope: 'remote_wire' } },
}] });

const streamDiagnostics = (stream_failure = 'flow_acquire') => ({ version: 5, omitted_failures: 0,
  failures: [{ ...detailedFailure('stream_open'), agent_detail: { stage: 'stream_open',
    deadline_scope: 'none', tls_failure: null, stream_failure }, agent_outcome: null }] });

const challengeDiagnostics = () => ({ version: 6, omitted_failures: 0,
  failures: [{ ...detailedFailure('challenge', 'operation'), agent_detail: { stage: 'challenge',
    deadline_scope: 'operation', tls_failure: null, stream_failure: null,
    challenge: { phase: 'challenge_read_verify', before_challenge: '90_to_120s', in_challenge: '1_to_5s' } },
  agent_outcome: null }] });

const appendDiagnostics = () => ({ version: 7, omitted_failures: 0, failures: [{
  ...transferFailure(), operation: 'append', stage: 'wire_receipt', category: 'timeout', agent_detail: null,
  agent_outcome: { status: 'observed', detail: { phase: 'remote_receipt_read', category: 'timeout', deadline_scope: 'operation' },
    append_timing: { before_payload: '90_to_120s', in_payload_write_flush: 'under_1s', in_receipt_read: '5_to_15s' } },
}] });

const flowDiagnostics = () => ({ version: 8, omitted_failures: 0, failures: [{
  ...detailedFailure('stream_open'), agent_outcome: null,
  agent_detail: { stage: 'stream_open', deadline_scope: 'none', tls_failure: null,
    stream_failure: 'flow_acquire', challenge: null, flow_acquire: { rounds: 1,
      first: { stage: 'helper_acquire', reason: 'helper_io' }, last: { stage: 'helper_acquire', reason: 'helper_io' } } },
}] });

test('profile9 alone selects flow diagnostics and never combines opt-ins', () => {
  assert.doesNotThrow(() => validateAppendProfile({ flowAcquireDiagnosticsV8: true }, 9));
  for (const value of [false, null, 1, 'true', {}, []]) {
    assert.throws(() => validateAppendProfile({ flowAcquireDiagnosticsV8: value }, 9), /configuration/u);
  }
  assert.throws(() => validateAppendProfile({}, 9), /configuration/u);
  assert.throws(() => validateAppendProfile({ flowAcquireDiagnosticsV8: true, appendDiagnosticsV7: true }, 9), /configuration/u);
  for (let profile = 1; profile <= 8; profile++) {
    for (const value of [true, false, null]) assert.throws(() => validateAppendProfile({
      ...(profile === 8 ? { appendDiagnosticsV7: true } : {}), flowAcquireDiagnosticsV8: value }, profile), /configuration/u);
  }
});

test('flow diagnostic accepts exactly35 stage/reason pairs with bounded original loop rounds', () => {
  const helper = ['helper_kernel', 'helper_capacity', 'helper_unavailable', 'helper_not_found',
    'helper_cleanup_incomplete', 'helper_other_rejection', 'helper_timeout', 'helper_io',
    'helper_validation', 'helper_authority', 'helper_correlation', 'helper_runtime_changed'];
  const expected = { source_port: ['entropy'],
    retirement_drain: ['unconfirmed', 'io', ...helper.filter(r => r !== 'helper_not_found')],
    material: ['metadata', 'topology'], slot_reservation: ['unconfirmed', 'local_capacity', 'local_unavailable'],
    helper_acquire: helper, descriptor_clone: ['io'], descriptor_adoption: ['metadata', 'io'], flow_metadata: ['metadata'] };
  assert.equal(Object.values(expected).flat().length, 35);
  const reasons = new Set([...Object.values(expected).flat(), 'unobserved', 'PRIVATE']);
  for (const stage of [...Object.keys(expected), 'unobserved', 'PRIVATE']) for (const reason of reasons) {
    for (const rounds of [1, 2, 8]) {
      const d = flowDiagnostics();
      d.failures[0].agent_detail.flow_acquire = { rounds, first: { stage, reason }, last: { stage, reason } };
      if (expected[stage]?.includes(reason)) assert.deepEqual(depositDiagnostic(d, 8), d);
      else assert.throws(() => depositDiagnostic(d, 8), /deposit_diagnostics/u);
    }
  }
  const d = flowDiagnostics(), flow = d.failures[0].agent_detail.flow_acquire;
  flow.last = { stage: 'source_port', reason: 'entropy' };
  assert.throws(() => depositDiagnostic(d, 8), /deposit_diagnostics/u);
  for (let rounds = 2; rounds <= 8; rounds++) {
    flow.rounds = rounds; assert.deepEqual(depositDiagnostic(d, 8), d);
  }
});

test('flow diagnostic rejects missing nullable keys, raw data, scope errors and version relabeling', () => {
  const mutations = [f => { delete f.agent_detail.flow_acquire; },
    f => { f.agent_detail.flow_acquire.raw = '/private/canary'; },
    ...[0, 9, true, null, '1'].map(v => f => { f.agent_detail.flow_acquire.rounds = v; }),
    ...['rounds', 'first', 'last'].map(k => f => { delete f.agent_detail.flow_acquire[k]; }),
    ...['first', 'last'].map(k => f => { f.agent_detail.flow_acquire[k] = null; }),
    ...['stage', 'reason'].flatMap(k => [f => { delete f.agent_detail.flow_acquire.first[k]; },
      ...[null, true, 1, [], {}, 'PRIVATE'].map(v => f => { f.agent_detail.flow_acquire.first[k] = v; })]),
    ...['route_connect', 'challenge', 'tls_handshake'].map(v => f => { f.agent_detail.stage = v; }),
    ...['operation', 'exchange'].map(v => f => { f.agent_detail.deadline_scope = v; }),
    ...[null, 'policy', 'route_material'].map(v => f => { f.agent_detail.stream_failure = v; }),
    ...['CONTENT_INVALID', 'CONTENT_POLICY', 'CONTENT_BUSY', 'unknown'].map(v => f => { f.agent_code = v; }),
    f => { f.agent_detail.tls_failure = 'io'; }, f => { f.agent_detail.challenge = challengeDiagnostics().failures[0].agent_detail.challenge; },
    f => { f.stage = 'wire_receipt'; }, f => { f.category = 'io'; f.agent_code = null; }];
  for (const mutate of mutations) {
    const d = flowDiagnostics(); mutate(d.failures[0]);
    assert.throws(() => depositDiagnostic(d, 8), /deposit_diagnostics/u);
  }
  const nullable = flowDiagnostics(); nullable.failures[0].agent_detail.flow_acquire = null;
  assert.deepEqual(depositDiagnostic(nullable, 8), nullable);
  for (let version = 1; version <= 7; version++) {
    const d = structuredClone(nullable); d.version = version;
    assert.throws(() => depositDiagnostic(d, version), /deposit_diagnostics/u);
  }
  const appended = appendDiagnostics(); appended.version = 8;
  assert.deepEqual(depositDiagnostic(appended, 8), appended);
  delete appended.failures[0].agent_outcome.append_timing;
  assert.throws(() => depositDiagnostic(appended, 8), /deposit_diagnostics/u);
});

test('profile9 publish preserves closed diagnostic8 with failed node10 and lifecycle11', async () => {
  for (const app of ['image', 'cloud']) {
    const diagnostic = flowDiagnostics(), value = { status: 'incomplete', code: 'retained_operation_incomplete',
      local_process_joined: true, storage: { operation_complete: false, deposit_diagnostics: diagnostic, raw: 'PRIVATE' } };
    const report = publishFailure(value, app, 'deposit', false, 9);
    assert.equal(report.version, 10); assert.equal(report.publish_observation.version, 9);
    assert.deepEqual(report.publish_observation.deposit_diagnostics, diagnostic);
    assert.equal(report.passed, false); assert.equal(report.cleanup_confirmed, false);
    assert.doesNotMatch(JSON.stringify(report), /PRIVATE|raw/u);
    for (let old = 2; old <= 8; old++) assert.equal(publishFailure(value, app, 'deposit', false, old)
      .publish_observation.deposit_diagnostics_state, 'invalid');
    const complete = { status: 'complete', local_process_joined: true, storage: { operation_complete: true,
      deposit_diagnostics: { version: 8, failures: [], omitted_failures: 0 } } };
    assert.doesNotThrow(() => requirePublishComplete(complete, app, 'deposit', 9));
    complete.storage.deposit_diagnostics.version = 7;
    assert.equal(publishFailure(complete, app, 'deposit', false, 9).publish_observation.deposit_diagnostics_state, 'invalid');
    for (const closeFails of [false, true]) {
      const ctx = { profileVersion: 9, provision: 'a'.repeat(64), stage: `${app}_publish`, signal: { aborted: false } };
      let closes = 0, failure;
      try { await withPublishCore(ctx, app, { async close() { closes++; if (closeFails) throw Error('PRIVATE'); } },
        async () => requirePublishComplete(value, app, 'deposit', 9)); }
      catch (error) { failure = consumerFailureReport(ctx, 'publish', error); }
      assert.equal(closes, 1); assert.equal(failure.version, 11);
      assert.deepEqual(failure.publish_cleanup, { app, state: closeFails ? 'failed' : 'complete' });
      assert.deepEqual(failure.publish_observation.deposit_diagnostics, diagnostic);
      assert.equal(failure.cleanup_confirmed, false);
      assert.doesNotMatch(JSON.stringify(failure), /PRIVATE|raw/u);
    }
  }
});

test('only explicit profile8 configuration requests timing while old fixture configs remain absent', () => {
  for (const profile of [1, 2, 3, 4, 5, 6, 7]) {
    assert.doesNotThrow(() => validateAppendProfile({}, profile));
    for (const value of [true, false, null, 1, 'true', {}, []]) {
      assert.throws(() => validateAppendProfile({ appendDiagnosticsV7: value }, profile), /configuration/u);
    }
  }
  assert.doesNotThrow(() => validateAppendProfile({ appendDiagnosticsV7: true }, 8));
  assert.throws(() => validateAppendProfile({}, 8), /configuration/u);
  for (const value of [false, null, 1, 'true', {}, []]) {
    assert.throws(() => validateAppendProfile({ appendDiagnosticsV7: value }, 8), /configuration/u);
  }
  for (const profile of [0, 9, null, true, '8']) {
    assert.throws(() => validateAppendProfile({ appendDiagnosticsV7: true }, profile), /configuration/u);
  }
});

test('profile8 preserves failed publish and finite timing without upgrading historical profiles', () => {
  const buckets = ['under_1s', '1_to_5s', '5_to_15s', '15_to_30s', '30_to_60s', '60_to_90s', '90_to_120s', 'at_least_120s'];
  for (const phase of ['remote_payload_write', 'remote_receipt_read']) {
    for (const before_payload of buckets) for (const in_payload_write_flush of buckets) {
      for (const in_receipt_read of phase === 'remote_payload_write' ? [null] : buckets) {
        const d = appendDiagnostics();
        d.failures[0].agent_outcome.detail.phase = phase;
        d.failures[0].agent_outcome.append_timing = { before_payload, in_payload_write_flush, in_receipt_read };
        assert.deepEqual(depositDiagnostic(d, 7), d);
      }
    }
  }
  for (const app of ['image', 'cloud']) {
    const diagnostic = appendDiagnostics();
    const value = { status: 'incomplete', code: 'retained_operation_incomplete', local_process_joined: true,
      storage: { operation_complete: false, deposit_diagnostics: diagnostic, raw: 'PRIVATE' } };
    const report = publishFailure(value, app, 'deposit', false, 8);
    assert.equal(report.version, 9); assert.equal(report.publish_observation.version, 8);
    assert.equal(report.passed, false); assert.equal(report.cleanup_confirmed, false);
    assert.deepEqual(report.publish_observation.deposit_diagnostics, diagnostic);
    assert.doesNotMatch(JSON.stringify(report), /PRIVATE|raw/u);
    for (const old of [2, 3, 4, 5, 6, 7]) assert.equal(publishFailure(value, app, 'deposit', false, old)
      .publish_observation.deposit_diagnostics_state, 'invalid');
    const complete = { status: 'complete', local_process_joined: true,
      storage: { operation_complete: true, deposit_diagnostics: { version: 7, failures: [], omitted_failures: 0 } } };
    assert.doesNotThrow(() => requirePublishComplete(complete, app, 'deposit', 8));
    complete.storage.deposit_diagnostics.version = 6;
    assert.equal(publishFailure(complete, app, 'deposit', false, 8).publish_observation.deposit_diagnostics_state, 'invalid');
  }
});

test('append timing closes fields and uses original agent phase without inventing receipt entry', () => {
  const mutations = [f => { f.operation = 'finalize'; },
    f => { f.agent_outcome.detail.phase = 'remote_receipt_verify'; },
    f => { f.agent_outcome.detail.phase = 'remote_payload_write'; },
    f => { delete f.agent_outcome.append_timing; },
    f => { f.agent_outcome.append_timing.phase = 'remote_receipt_read'; },
    f => { f.agent_outcome.append_timing.raw = '/private/canary'; },
    ...['before_payload', 'in_payload_write_flush', 'in_receipt_read'].flatMap(key => [
      f => { delete f.agent_outcome.append_timing[key]; },
      ...[null, 0, true, {}, [], 'PRIVATE', 'unobserved'].map(value => f => { f.agent_outcome.append_timing[key] = value; }),
    ])];
  for (const mutate of mutations) {
    const d = appendDiagnostics(); mutate(d.failures[0]);
    assert.throws(() => depositDiagnostic(d, 7), /deposit_diagnostics/u);
  }
  for (const status of ['observed', 'missing', 'pending', 'expired', 'query_failed', 'query_timeout']) {
    const d = appendDiagnostics(), outcome = d.failures[0].agent_outcome;
    outcome.status = status;
    if (status !== 'observed') {
      outcome.detail = null;
      assert.throws(() => depositDiagnostic(d, 7), /deposit_diagnostics/u);
    }
    outcome.append_timing = null;
    assert.deepEqual(depositDiagnostic(d, 7), d);
  }
  for (const version of [4, 5, 6]) {
    const d = appendDiagnostics(); d.version = version;
    assert.throws(() => depositDiagnostic(d, version), /deposit_diagnostics/u);
    d.failures[0].agent_outcome.append_timing = null;
    assert.throws(() => depositDiagnostic(d, version), /deposit_diagnostics/u);
  }
});

test('profile7 observes finite challenge progress without reinterpreting prior profiles', () => {
  const buckets = ['under_1s', '1_to_5s', '5_to_15s', '15_to_30s', '30_to_60s', '60_to_90s', '90_to_120s', 'at_least_120s'];
  for (const phase of ['selector_write_flush', 'grant_write_flush', 'challenge_read_verify']) {
    for (const before_challenge of buckets) for (const in_challenge of buckets) {
      for (const deadline_scope of ['none', 'operation', 'exchange']) {
        const d = challengeDiagnostics();
        Object.assign(d.failures[0].agent_detail, { deadline_scope, challenge: { phase, before_challenge, in_challenge } });
        assert.deepEqual(depositDiagnostic(d, 6), d);
      }
    }
  }
  for (const app of ['image', 'cloud']) {
    const diagnostic = challengeDiagnostics();
    const value = { status: 'incomplete', code: 'retained_operation_incomplete', local_process_joined: true,
      storage: { operation_complete: false, deposit_diagnostics: diagnostic, raw: 'PRIVATE' } };
    const report = publishFailure(value, app, 'deposit', false, 7);
    assert.equal(report.version, 8); assert.equal(report.publish_observation.version, 7);
    assert.deepEqual(report.publish_observation.deposit_diagnostics, diagnostic);
    assert.doesNotMatch(JSON.stringify(report), /PRIVATE|raw/u);
    for (const old of [2, 3, 4, 5, 6]) assert.equal(publishFailure(value, app, 'deposit', false, old)
      .publish_observation.deposit_diagnostics_state, 'invalid');
    const complete = { status: 'complete', local_process_joined: true,
      storage: { operation_complete: true, deposit_diagnostics: { version: 6, failures: [], omitted_failures: 0 } } };
    assert.doesNotThrow(() => requirePublishComplete(complete, app, 'deposit', 7));
    complete.storage.deposit_diagnostics.version = 5;
    assert.equal(publishFailure(complete, app, 'deposit', false, 7).publish_observation.deposit_diagnostics_state, 'invalid');
  }
});

test('challenge detail rejects unknown data and invalid scope, while old JSON remains exact', () => {
  const mutations = [
    f => { delete f.agent_detail.challenge; }, f => { f.agent_detail.challenge.raw = 'PRIVATE'; },
    ...['phase', 'before_challenge', 'in_challenge'].flatMap(key => [
      f => { delete f.agent_detail.challenge[key]; },
      ...[null, 0, true, {}, [], 'PRIVATE', 'unobserved'].map(value => f => { f.agent_detail.challenge[key] = value; }),
    ]),
    ...['stream_open', 'tls_handshake', 'route_connect'].map(value => f => { f.agent_detail.stage = value; }),
    ...['CONTENT_INVALID', 'CONTENT_BUSY', 'CONTENT_POLICY', 'unknown'].map(value => f => { f.agent_code = value; }),
    f => { f.agent_detail.tls_failure = 'io'; }, f => { f.agent_detail.stream_failure = 'flow_acquire'; },
    f => { f.stage = 'wire_receipt'; }, f => { f.category = 'io'; f.agent_code = null; },
  ];
  for (const mutate of mutations) {
    const d = challengeDiagnostics(); mutate(d.failures[0]);
    assert.throws(() => depositDiagnostic(d, 6), /deposit_diagnostics/u);
  }
  const nullable = challengeDiagnostics(); nullable.failures[0].agent_detail.challenge = null;
  assert.deepEqual(depositDiagnostic(nullable, 6), nullable);
  for (const version of [1, 2, 3, 4, 5]) {
    const d = structuredClone(nullable); d.version = version;
    assert.throws(() => depositDiagnostic(d, version), /deposit_diagnostics/u);
  }
});

test('profile6 requires diagnostic5 and failure envelope7 while retaining all historical versions', () => {
  for (const app of ['image', 'cloud']) {
    for (const name of [null, 'policy', 'route_state', 'route_material', 'flow_acquire',
      'transport_certificate', 'transport_tls', 'initial_paths', 'open_tcp_write', 'subflow_readiness', 'stream_attachment']) {
      const diagnostic = streamDiagnostics(name);
      assert.deepEqual(depositDiagnostic(diagnostic, 5), diagnostic);
      const value = { status: 'incomplete', code: 'retained_operation_incomplete',
        local_process_joined: true, storage: { operation_complete: false, deposit_diagnostics: diagnostic, raw: 'PRIVATE' } };
      const report = publishFailure(value, app, 'deposit', false, 6);
      assert.equal(report.version, 7); assert.equal(report.publish_observation.version, 6);
      assert.deepEqual(report.publish_observation.deposit_diagnostics, diagnostic);
      assert.doesNotMatch(JSON.stringify(report), /PRIVATE|raw/u);
      for (const old of [1, 2, 3, 4]) assert.throws(() => depositDiagnostic(diagnostic, old), /deposit_diagnostics/u);
      for (const old of [2, 3, 4, 5]) assert.equal(publishFailure(value, app, 'deposit', false, old)
        .publish_observation.deposit_diagnostics_state, 'invalid');
    }
    const complete = { status: 'complete', local_process_joined: true,
      storage: { operation_complete: true, deposit_diagnostics: { version: 5, failures: [], omitted_failures: 0 } } };
    assert.doesNotThrow(() => requirePublishComplete(complete, app, 'deposit', 6));
    complete.storage.deposit_diagnostics.version = 4;
    assert.equal(publishFailure(complete, app, 'deposit', false, 6).publish_observation.deposit_diagnostics_state, 'invalid');
  }
});

test('stream failure is finite and bound only to stream-open nondeadline unavailable pre-READY', () => {
  const changes = [
    ...['stage', 'deadline_scope', 'tls_failure', 'stream_failure'].map(key => d => { delete d.failures[0].agent_detail[key]; }),
    ...['PRIVATE', 'unknown', '', 1, false, {}, []].map(value => d => { d.failures[0].agent_detail.stream_failure = value; }),
    ...['operation', 'exchange'].map(value => d => { d.failures[0].agent_detail.deadline_scope = value; }),
    ...['route_connect', 'provider_lookup', 'tls_handshake', 'challenge'].map(value => d => { d.failures[0].agent_detail.stage = value; }),
    ...['CONTENT_INVALID', 'CONTENT_POLICY', 'CONTENT_BUSY', 'unknown'].map(value => d => { d.failures[0].agent_code = value; }),
    d => { d.failures[0].stage = 'wire_receipt'; }, d => { d.failures[0].category = 'io'; d.failures[0].agent_code = null; },
    d => { d.failures[0].agent_detail.tls_failure = 'io'; },
    d => { d.failures[0].agent_detail.raw = 'PRIVATE'; }, d => { delete d.failures[0].agent_outcome; },
    d => { d.failures[0].agent_outcome = { status: 'missing', detail: null }; },
  ];
  for (const mutate of changes) {
    const diagnostic = streamDiagnostics(); mutate(diagnostic);
    assert.throws(() => depositDiagnostic(diagnostic, 5), /deposit_diagnostics/u);
  }
  for (const version of [2, 3, 4]) {
    const d = streamDiagnostics(null); d.version = version;
    if (version < 4) delete d.failures[0].agent_outcome;
    assert.throws(() => depositDiagnostic(d, version), /deposit_diagnostics/u);
  }
});

test('profile5 observes diagnostic4 in failure envelope6 without upgrading historical profiles', () => {
  for (const app of ['image', 'cloud']) {
    const diagnostic = outcomeDiagnostics(), value = { status: 'incomplete', code: 'retained_operation_incomplete',
      local_process_joined: true, storage: { operation_complete: false, deposit_diagnostics: diagnostic, raw: 'PRIVATE' } };
    const report = publishFailure(value, app, 'deposit', false, 5);
    assert.equal(report.version, 6); assert.equal(report.publish_observation.version, 5);
    assert.deepEqual(report.publish_observation.deposit_diagnostics, diagnostic);
    assert.doesNotMatch(JSON.stringify(report), /PRIVATE|raw/u);
    for (const old of [1, 2, 3]) assert.throws(() => depositDiagnostic(diagnostic, old), /deposit_diagnostics/u);
    for (const old of [2, 3, 4]) {
      assert.equal(publishFailure(value, app, 'deposit', false, old).publish_observation.deposit_diagnostics_state, 'invalid');
    }
    const complete = { status: 'complete', local_process_joined: true,
      storage: { operation_complete: true, deposit_diagnostics: { version: 4, failures: [], omitted_failures: 0 } } };
    assert.doesNotThrow(() => requirePublishComplete(complete, app, 'deposit', 5));
    delete complete.storage.deposit_diagnostics;
    assert.equal(publishFailure(complete, app, 'deposit', false, 5).publish_observation.deposit_diagnostics_state, 'missing');
  }
});

test('outcome status, nullable fields and post-READY boundary are exact; unknown context never escapes', () => {
  for (const status of ['observed', 'missing', 'pending', 'expired', 'query_failed', 'query_timeout']) {
    for (const detail of [null, outcomeDiagnostics().failures[0].agent_outcome.detail]) {
      const d = outcomeDiagnostics(); d.failures[0].agent_outcome = { status, detail };
      if ((status === 'observed') === (detail !== null)) assert.deepEqual(depositDiagnostic(d, 4), d);
      else assert.throws(() => depositDiagnostic(d, 4), /deposit_diagnostics/u);
    }
  }
  const nullable = outcomeDiagnostics(); nullable.failures[0].agent_outcome = null;
  assert.deepEqual(depositDiagnostic(nullable, 4), nullable);
  const mutations = [d => { delete d.failures[0].agent_outcome; }, d => { delete d.failures[0].agent_outcome.detail; },
    d => { d.failures[0].agent_outcome.raw = 'PRIVATE'; }, d => { d.failures[0].agent_outcome.detail.original_request_id = 'PRIVATE'; },
    d => { d.failures[0].agent_outcome.status = 'PRIVATE'; }, d => { d.failures[0].agent_outcome.detail.phase = 'unobserved'; },
    ...['agent_ready', 'authorization', 'signed_request', 'accounting', 'unknown'].map(stage => d => { d.failures[0].stage = stage; }),
    d => { d.version = 3; }];
  for (const mutate of mutations) {
    const d = outcomeDiagnostics(); mutate(d); assert.throws(() => depositDiagnostic(d, 4), /deposit_diagnostics/u);
    const report = publishFailure({ status: 'incomplete', local_process_joined: true,
      storage: { operation_complete: false, deposit_diagnostics: d } }, 'cloud', 'deposit', false, 5);
    assert.equal(report.publish_observation.deposit_diagnostics_state, 'invalid');
    assert.equal(report.publish_observation.deposit_diagnostics, null); assert.doesNotMatch(JSON.stringify(report), /PRIVATE/u);
  }
});

test('agent outcome phase/deadline matrix preserves actual timeout versus cancellation semantics', () => {
  const phases = ['ready_write', 'local_request_read', 'local_request_verify', 'local_payload_read', 'local_payload_verify',
    'admission', 'remote_request_verify', 'remote_request_write', 'remote_payload_write', 'remote_receipt_read',
    'remote_receipt_verify', 'remote_payload_read', 'remote_payload_verify', 'local_receipt_write', 'local_payload_write',
    'provider_tls_close', 'transport_tls_close', 'final_route_check', 'final_grant_check', 'final_lifetime_check', 'terminal_write'];
  for (const [index, phase] of phases.entries()) for (const category of ['io', 'auth', 'invalid', 'busy', 'store',
    'expired', 'entropy', 'timeout', 'policy', 'unavailable', 'cancelled']) for (const scope of ['none', 'operation', 'exchange', 'bridge', 'remote_wire']) {
    const d = outcomeDiagnostics(); d.failures[0].agent_outcome.detail = { phase, category, deadline_scope: scope };
    const allowed = (category === 'timeout') === (scope !== 'none')
      && (scope !== 'bridge' || (index >= 1 && index <= 14)) && (scope !== 'remote_wire' || (index >= 6 && index <= 12));
    if (allowed) assert.deepEqual(depositDiagnostic(d, 4), d);
    else assert.throws(() => depositDiagnostic(d, 4), /deposit_diagnostics/u);
  }
  const tls = tlsDiagnostics(); tls.version = 4; tls.failures[0].agent_outcome = null;
  assert.deepEqual(depositDiagnostic(tls, 4), tls, 'pre-READY TLS detail remains valid without an outcome claim');
});

test('profile4 binds TLS diagnostic3 to the actual call without changing old profiles', () => {
  for (const app of ['image', 'cloud']) {
    const diagnostic = tlsDiagnostics();
    const value = { status: 'incomplete', code: 'retained_operation_incomplete', local_process_joined: true,
      storage: { operation_complete: false, deposit_diagnostics: diagnostic, private_path: 'SECRET' } };
    const result = publishFailure(value, app, 'deposit', false, 4);
    assert.equal(result.version, 5); assert.equal(result.publish_observation.version, 4);
    assert.deepEqual(result.publish_observation.deposit_diagnostics, diagnostic);
    assert.doesNotMatch(JSON.stringify(result), /SECRET|private_path/u);
    for (const old of [2, 3]) {
      assert.equal(publishFailure(value, app, 'deposit', false, old).publish_observation.deposit_diagnostics_state, 'invalid');
    }
    for (const old of [1, 2]) {
      assert.throws(() => depositDiagnostic(diagnostic, old), /deposit_diagnostics/u);
      const relabeled = structuredClone(diagnostic); relabeled.version = old;
      assert.throws(() => depositDiagnostic(relabeled, old), /deposit_diagnostics/u);
    }
    const complete = { status: 'complete', local_process_joined: true,
      storage: { operation_complete: true, deposit_diagnostics: { ...diagnostic, failures: [] } } };
    assert.doesNotThrow(() => requirePublishComplete(complete, app, 'deposit', 4));
    delete complete.storage.deposit_diagnostics;
    assert.equal(publishFailure(complete, app, 'deposit', false, 4).publish_observation.deposit_diagnostics_state, 'missing');
    assert.equal(publishFailure({ status: 'failed' }, app, 'create', false, 4)
      .publish_observation.deposit_diagnostics_state, 'not_applicable');
  }
});

test('TLS classes require the observed handshake with no enclosing deadline and unavailable code', () => {
  for (const tls of ['offer', 'configuration', 'handshake_deadline', 'authentication', 'tls_other', 'io']) {
    for (const stage of ['tls_handshake', 'stream_open', 'challenge', 'unobserved']) {
      for (const scope of ['none', 'operation', 'exchange']) {
        for (const code of ['CONTENT_UNAVAILABLE', 'CONTENT_INVALID', 'CONTENT_BUSY', 'CONTENT_POLICY', 'unknown']) {
          const value = tlsDiagnostics(tls), failure = value.failures[0];
          failure.agent_detail.stage = stage; failure.agent_detail.deadline_scope = scope; failure.agent_code = code;
          if (stage === 'tls_handshake' && scope === 'none' && code === 'CONTENT_UNAVAILABLE') {
            assert.deepEqual(depositDiagnostic(value, 3), value);
          } else assert.throws(() => depositDiagnostic(value, 3), /deposit_diagnostics/u);
        }
      }
    }
  }
  const absent = tlsDiagnostics(null);
  assert.deepEqual(depositDiagnostic(absent, 3), absent);
  absent.failures[0].agent_detail = null;
  assert.deepEqual(depositDiagnostic(absent, 3), absent);
});

test('profile4 rejects missing reserved malformed and raw TLS details without leaking them', () => {
  const mutations = [d => { delete d.failures[0].agent_detail.tls_failure; },
    ...['unobserved', 'PRIVATE', 0, 1, false, [], {}].map(v => d => { d.failures[0].agent_detail.tls_failure = v; }),
    d => { d.failures[0].agent_detail.raw = 'PRIVATE'; }, d => { d.failures[0].stage = 'agent_terminal'; },
    d => { d.failures[0].category = 'io'; d.failures[0].agent_code = null; },
    d => { d.failures.push(structuredClone(d.failures[0])); }, d => { d.omitted_failures = 1; },
    d => { d.failures = Array(9).fill(d.failures[0]); }, d => { d.version = 2; }];
  for (const mutate of mutations) {
    const diagnostic = tlsDiagnostics(); mutate(diagnostic);
    assert.throws(() => depositDiagnostic(diagnostic, 3), /deposit_diagnostics/u);
    const result = publishFailure({ status: 'complete', local_process_joined: true,
      storage: { operation_complete: true, deposit_diagnostics: diagnostic } }, 'image', 'deposit', false, 4);
    assert.equal(result.passed, false); assert.equal(result.version, 5);
    assert.equal(result.publish_observation.deposit_diagnostics_state, 'invalid');
    assert.equal(result.publish_observation.deposit_diagnostics, null);
    assert.doesNotMatch(JSON.stringify(result), /PRIVATE/u);
  }
  const all = tlsDiagnostics();
  all.failures = Array.from({ length: 8 }, (_, i) => ({ ...all.failures[0], fragment_index: i >> 1, copy_index: i % 2 }));
  assert.equal(depositDiagnostic(all, 3).failures.length, 8);
});

test('profile 3 requires version2 detail without upgrading historical observations', () => {
  for (const app of ['image', 'cloud']) {
    const diagnostic = detailedDiagnostics();
    const value = { status: 'incomplete', code: 'retained_operation_incomplete', local_process_joined: true,
      storage: { operation_complete: false, deposit_diagnostics: diagnostic, raw: '/PRIVATE' } };
    const result = publishFailure(value, app, 'deposit', false, 3);
    assert.equal(result.version, 4); assert.equal(result.publish_observation.version, 3);
    assert.equal(result.publish_observation.deposit_diagnostics_state, 'observed');
    assert.deepEqual(result.publish_observation.deposit_diagnostics, diagnostic);
    assert.doesNotMatch(JSON.stringify(result), /PRIVATE|raw/u);
    assert.equal(publishFailure(value, app, 'deposit', false, 2).publish_observation.deposit_diagnostics_state, 'invalid');
    value.storage.deposit_diagnostics = diagnostics();
    assert.equal(publishFailure(value, app, 'deposit', false, 3).publish_observation.deposit_diagnostics_state, 'invalid');
    assert.equal(publishFailure(value, app, 'deposit', false, 2).version, 3);
    assert.equal(publishFailure(value, app, 'deposit', false, 1).version, 2);
    const complete = { status: 'complete', local_process_joined: true,
      storage: { operation_complete: true, deposit_diagnostics: detailedDiagnostics([]) } };
    assert.doesNotThrow(() => requirePublishComplete(complete, app, 'deposit', 3));
    delete complete.storage.deposit_diagnostics;
    assert.equal(publishFailure(complete, app, 'deposit', false, 3).publish_observation.deposit_diagnostics_state, 'missing');
    const created = publishFailure({ status: 'failed' }, app, 'create', false, 3);
    assert.equal(created.publish_observation.deposit_diagnostics_state, 'not_applicable');
    assert.equal(created.publish_observation.deposit_diagnostics, null);
  }
});

test('agent details accept only the closed stage and actual deadline matrix', () => {
  const stages = ['unobserved', 'route_connect', 'control_selection', 'provider_lookup',
    'provider_cardinality', 'offer_validity', 'stream_open', 'tls_handshake', 'challenge'];
  for (const stage of stages) for (const scope of ['none', 'operation', 'exchange']) {
    const value = detailedDiagnostics([detailedFailure(stage, scope)]);
    const allowed = (stage !== 'unobserved' || scope === 'operation')
      && (scope !== 'exchange' || ['stream_open', 'tls_handshake', 'challenge'].includes(stage));
    if (allowed) assert.deepEqual(depositDiagnostic(value, 2), value);
    else assert.throws(() => depositDiagnostic(value, 2), /deposit_diagnostics/u);
  }
  for (const code of ['CONTENT_INVALID', 'CONTENT_UNAVAILABLE', 'CONTENT_BUSY', 'CONTENT_POLICY']) {
    const value = detailedDiagnostics([{ ...detailedFailure(), agent_code: code }]);
    assert.deepEqual(depositDiagnostic(value, 2), value);
    value.failures[0].agent_detail.deadline_scope = 'operation';
    if (code === 'CONTENT_UNAVAILABLE') assert.deepEqual(depositDiagnostic(value, 2), value);
    else assert.throws(() => depositDiagnostic(value, 2), /deposit_diagnostics/u);
  }
  const nullDetail = detailedDiagnostics([{ ...transferFailure(), agent_detail: null }]);
  assert.deepEqual(depositDiagnostic(nullDetail, 2), nullDetail);
  const all = Array.from({ length: 8 }, (_, i) => ({ ...detailedFailure(), fragment_index: Math.floor(i / 2), copy_index: i % 2 }));
  assert.equal(depositDiagnostic(detailedDiagnostics(all), 2).failures.length, 8);
});

test('profile3 detail mutations cannot leak raw data or be accepted as success', () => {
  const mutations = [d => { delete d.failures[0].agent_detail; },
    d => { d.failures[0].agent_detail = '/PRIVATE'; }, d => { d.failures[0].agent_detail = []; },
    d => { d.failures[0].agent_detail.raw = '/PRIVATE'; }, d => { delete d.failures[0].agent_detail.stage; },
    d => { d.failures[0].agent_detail.stage = '/PRIVATE'; }, d => { d.failures[0].agent_detail.deadline_scope = '/PRIVATE'; },
    d => { d.failures[0].stage = 'agent_terminal'; }, d => { d.failures[0].category = 'io'; d.failures[0].agent_code = null; },
    d => { d.failures[0].agent_code = 'unknown'; }, d => { d.version = 1; },
    d => { d.failures.push(structuredClone(d.failures[0])); }, d => { d.omitted_failures = 1; },
    d => { d.failures = Array(9).fill(d.failures[0]); }];
  for (const mutate of mutations) {
    const value = detailedDiagnostics(); mutate(value);
    assert.throws(() => depositDiagnostic(value, 2), /deposit_diagnostics/u);
    const result = publishFailure({ status: 'complete', local_process_joined: true,
      storage: { operation_complete: true, deposit_diagnostics: value } }, 'cloud', 'deposit', false, 3);
    assert.equal(result.version, 4); assert.equal(result.publish_observation.deposit_diagnostics_state, 'invalid');
    assert.equal(result.publish_observation.deposit_diagnostics, null);
    assert.doesNotMatch(JSON.stringify(result), /PRIVATE/u);
  }
});

test('explicit profile 2 retains bounded actual-call transfer context without raw bridge output', () => {
  for (const app of ['image', 'cloud']) {
    const value = { status: 'incomplete', code: 'retained_operation_incomplete', local_process_joined: true,
      storage: { operation_complete: false, deposit_diagnostics: diagnostics(), private_path: 'SECRET' } };
    const result = publishFailure(value, app, 'deposit', false, 2);
    assert.equal(result.version, 3);
    assert.deepEqual(result.publish_observation, { version: 2, app, operation: 'deposit', status: 'incomplete',
      code: 'retained_operation_incomplete', local_process_joined: true, core_report_present: true,
      core_operation_complete: false, deposit_diagnostics_state: 'observed', deposit_diagnostics: diagnostics() });
    assert.doesNotMatch(JSON.stringify(result), /SECRET|private_path/u);
    assert.equal(publishFailure(value, app).version, 2);
  }
  const rejected = { ...transferFailure(), category: 'agent_rejected', agent_code: 'CONTENT_POLICY' };
  assert.deepEqual(depositDiagnostic(diagnostics([rejected])).failures, [rejected]);
  const all = Array.from({ length: 8 }, (_, i) => ({ ...transferFailure(), fragment_index: Math.floor(i / 2), copy_index: i % 2 }));
  assert.equal(depositDiagnostic(diagnostics(all)).failures.length, 8);
});

test('profile 2 does not call missing malformed or contradictory diagnostic a successful deposit', () => {
  const complete = { status: 'complete', code: 'ok', local_process_joined: true,
    storage: { operation_complete: true, deposit_diagnostics: diagnostics([]) } };
  assert.doesNotThrow(() => requirePublishComplete(complete, 'cloud', 'deposit', 2));
  assert.doesNotThrow(() => requirePublishComplete({ status: 'complete', local_process_joined: true }, 'image', 'create', 2));
  for (const [value, state] of [[{ ...complete, storage: { operation_complete: true } }, 'missing'],
    [{ ...complete, storage: { ...complete.storage, deposit_diagnostics: diagnostics() } }, 'invalid'],
    [{ ...complete, storage: { ...complete.storage, operation_complete: false } }, 'invalid']]) {
    const result = publishFailure(value, 'cloud', 'deposit', false, 2);
    assert.equal(result.publish_observation.deposit_diagnostics_state, state);
    assert.equal(result.publish_observation.deposit_diagnostics, null);
    assert.equal(result.passed, false);
  }
  const created = publishFailure({ status: 'failed', code: 'core_failed' }, 'image', 'create', false, 2);
  assert.equal(created.publish_observation.deposit_diagnostics_state, 'not_applicable');
  assert.equal(created.publish_observation.deposit_diagnostics, null);
});

test('deposit diagnostics reject oversized duplicate forged and private fields without echoing them', () => {
  const mutations = [d => { d.version = true; }, d => { d.omitted_failures = 1; },
    d => { d.failures = Array(9).fill(transferFailure()); }, d => { d.failures.push(transferFailure()); },
    d => { d.raw = 'SECRET'; }, d => { d.failures[0].raw = 'SECRET'; },
    d => { d.failures[0].fragment_index = 4; }, d => { d.failures[0].copy_index = 2; },
    d => { d.failures[0].operation = '/SECRET'; }, d => { d.failures[0].stage = '/SECRET'; },
    d => { d.failures[0].category = '/SECRET'; }, d => { d.failures[0].agent_code = 'CONTENT_POLICY'; },
    d => { d.failures[0].category = 'agent_rejected'; },
    d => { d.failures[0].category = 'agent_rejected'; d.failures[0].agent_code = 'SECRET'; }];
  for (const mutate of mutations) {
    const value = diagnostics(); mutate(value);
    assert.throws(() => depositDiagnostic(value), /deposit_diagnostics/u);
    const report = publishFailure({ status: 'incomplete', local_process_joined: true,
      storage: { operation_complete: false, deposit_diagnostics: value } }, 'cloud', 'deposit', false, 2);
    assert.equal(report.publish_observation.deposit_diagnostics_state, 'invalid');
    assert.equal(report.publish_observation.deposit_diagnostics, null);
    assert.doesNotMatch(JSON.stringify(report), /SECRET/u);
  }
});

test('publish rejection identifies the exact app and operation with closed bridge observations', () => {
  for (const app of ['image', 'cloud']) for (const operation of ['create', 'deposit']) {
    const result = publishFailure({ status: 'incomplete', code: 'retained_operation_incomplete',
      local_process_joined: true, storage: { operation_complete: false, private_key: 'DO-NOT-EXPORT' } }, app, operation);
    assert.equal(result.version, 2);
    assert.equal(result.passed, false);
    assert.equal(result.cleanup_confirmed, false);
    assert.deepEqual(result.publish_observation, { version: 1, app, operation,
      status: 'incomplete', code: 'retained_operation_incomplete', local_process_joined: true,
      core_report_present: true, core_operation_complete: false });
    assert.ok(!JSON.stringify(result).includes('DO-NOT-EXPORT'));
  }
  assert.doesNotThrow(() => requirePublishComplete({ status: 'complete', local_process_joined: true }, 'cloud', 'create'));
  assert.throws(() => requirePublishComplete({}, '/private/path', 'deposit'), /arguments/u);
  assert.throws(() => requirePublishComplete({}, 'image', 'delete'), /arguments/u);
});

test('publish diagnostic maps unfamiliar data to unknown without treating a join as success', () => {
  const result = publishFailure({ status: '/private/status', code: 'SECRET-CODE', local_process_joined: 1,
    storage: { operation_complete: 'SECRET-COMPLETE' }, stderr: 'SECRET-STDERR' });
  assert.deepEqual(result.publish_observation, { version: 1, app: 'cloud', operation: 'deposit',
    status: 'unknown', code: 'unknown', local_process_joined: null, core_report_present: true,
    core_operation_complete: null });
  assert.doesNotMatch(JSON.stringify(result), /private|SECRET/u);
  assert.equal(publishFailure({ status: 'complete', code: 'ok', local_process_joined: false })
    .publish_observation.local_process_joined, false);
  for (const value of [null, undefined, false, 'SECRET', { storage: ['SECRET'] }]) {
    const current = publishFailure(value);
    assert.equal(current.publish_observation.core_report_present, false);
    assert.equal(current.publish_observation.core_operation_complete, null);
    assert.doesNotMatch(JSON.stringify(current), /SECRET/u);
  }
});

test('cancellation and unrelated exceptions cannot inherit or fabricate a publish observation', () => {
  const ctx = { provision: 'a'.repeat(64), stage: 'cloud_publish', signal: { aborted: false } };
  const forged = Object.assign(new Error('PRIVATE'), { code: 'publish_operation', observation: { secret: 'PRIVATE' } });
  const report = consumerFailureReport(ctx, 'publish', forged);
  assert.equal(report.version, 1);
  assert.equal(Object.hasOwn(report, 'publish_observation'), false);
  assert.doesNotMatch(JSON.stringify(report), /PRIVATE/u);
  const cancelled = publishFailure({ status: 'cancelled', code: 'cancelled', local_process_joined: true }, 'image', 'create', true);
  assert.equal(cancelled.code, 'phase_deadline');
  assert.equal(cancelled.publish_observation.status, 'cancelled');
});

const publishContext = (profileVersion = 8) => ({ profileVersion, provision: 'a'.repeat(64),
  stage: 'cloud_catalog_create', signal: { aborted: false } });
class CatalogFixtureError extends Error {
  constructor(code) { super('PRIVATE-EXCEPTION-CANARY'); this.code = code; }
}
async function lifecycleFailure(ctx, operation, close = async () => {}, app = 'cloud') {
  try { await withPublishCore(ctx, app, { close }, operation); assert.fail('expected failure'); }
  catch (error) { return { error, report: consumerFailureReport(ctx, 'publish', error) }; }
}

test('profile8 retains primary catalog error before independent close failure and later cancellation', async () => {
  const ctx = publishContext(), primary = Object.assign(new Error('PRIVATE-PRIMARY'), { code: 'catalog_metadata_validation' });
  let closed = 0;
  const { error, report } = await lifecycleFailure(ctx, async () => { throw primary; }, async () => {
    closed++; ctx.signal.aborted = true; throw new Error('PRIVATE-CLOSE');
  });
  assert.equal(error.cause, primary); assert.equal(closed, 1);
  assert.deepEqual(report, { version: 10, kind: 'storage-consumer-maintenance', phase: 'publish', passed: false,
    provision_sha256: ctx.provision, stage: 'cloud_catalog_create', code: 'catalog_metadata_validation',
    cleanup_confirmed: false, publish_cleanup: { app: 'cloud', state: 'failed' } });
  assert.doesNotMatch(JSON.stringify(report), /PRIVATE/u);
});

test('profile8 close-only error is separate and successful close is not phase or remote cleanup acceptance', async () => {
  for (const failed of [false, true]) {
    const ctx = publishContext();
    const { report } = await lifecycleFailure(ctx, async () => {
      if (!failed) throw new Error('PRIVATE-PRIMARY');
      return 'completed operation';
    }, async () => { if (failed) throw new Error('PRIVATE-CLOSE'); });
    assert.equal(report.stage, failed ? 'cloud_core_close' : 'cloud_catalog_create');
    assert.equal(report.code, failed ? 'core_close_failed' : 'application_failed');
    assert.equal(report.publish_cleanup.state, failed ? 'failed' : 'complete');
    assert.equal(report.passed, false); assert.equal(report.cleanup_confirmed, false);
    assert.doesNotMatch(JSON.stringify(report), /PRIVATE|provider_usage_proven|remote_cleanup_confirmed/u);
  }
});

test('profile8 successful lifecycle preserves return identity and original close count and stage', async () => {
  const ctx = publishContext(), result = {}, calls = [];
  const actual = await withPublishCore(ctx, 'cloud', { close: async () => {
    assert.equal(ctx.stage, 'cloud_core_close'); calls.push('close');
  } }, async () => { calls.push('operation'); return result; });
  assert.equal(actual, result); assert.deepEqual(calls, ['operation', 'close']);
  assert.equal(ctx.stage, 'cloud_catalog_create');
});

test('an unusable optional error classification cannot skip close or export its contents', async () => {
  const ctx = publishContext(), primary = new Error('PRIVATE-PRIMARY'); let closed = 0;
  Object.defineProperty(primary, 'code', { get() { throw new Error('PRIVATE-GETTER'); } });
  const { error, report } = await lifecycleFailure(ctx, async () => { throw primary; }, async () => { closed++; });
  assert.equal(error.cause, primary); assert.equal(closed, 1);
  assert.equal(report.code, 'application_failed'); assert.equal(report.publish_cleanup.state, 'complete');
  assert.doesNotMatch(JSON.stringify(report), /PRIVATE/u);
});

test('typed catalog codes are finite and materialization does not invent a restore or decrypt cause', async () => {
  const cases = { MATERIALIZATION_FAILED: 'catalog_materialization_failed', RESTORE_INCOMPLETE: 'catalog_restore_validation',
    INVALID_SOURCE_METADATA: 'catalog_metadata_validation', SOURCE_SELECTION_MISMATCH: 'catalog_selection_validation',
    RESTORED_FILE_INVALID: 'catalog_plaintext_validation', FILE_VERSION_CHANGED: 'catalog_file_version_changed',
    INVALID_FILE_RECEIPT: 'catalog_receipt_validation', CATALOG_CRYPTO_TIMEOUT: 'catalog_crypto_timeout',
    CATALOG_CRYPTO_UNAVAILABLE: 'catalog_crypto_unavailable', CATALOG_CRYPTO_FAILED: 'catalog_crypto_failed',
    INVALID_CATALOG_CRYPTO_REPORT: 'catalog_crypto_report_invalid', PRIVATE_CLEANUP_FAILED: 'catalog_cleanup_failed',
    PRIVATE_STAGE_CHANGED: 'catalog_stage_changed', CANCELLED: 'catalog_cancelled' };
  for (const [source, expected] of Object.entries(cases)) {
    const ctx = publishContext(), request = {}, options = {}; let calls = 0;
    const modules = { PrivateCatalogError: CatalogFixtureError, createPrivateCatalog: async (r, o) => {
      calls++; assert.equal(r, request); assert.equal(o, options); throw new CatalogFixtureError(source);
    } };
    const { report } = await lifecycleFailure(ctx, () => createPublishCatalog(ctx, modules, request, options));
    assert.equal(calls, 1); assert.equal(report.stage, 'cloud_catalog_create'); assert.equal(report.code, expected);
    assert.equal(report.publish_cleanup.state, 'complete'); assert.doesNotMatch(JSON.stringify(report), /PRIVATE/u);
  }
  for (const error of [new CatalogFixtureError('PRIVATE-UNKNOWN'),
    Object.assign(new Error('PRIVATE'), { code: 'RESTORE_INCOMPLETE' }), null]) {
    const ctx = publishContext();
    const { report } = await lifecycleFailure(ctx, () => createPublishCatalog(ctx, {
      PrivateCatalogError: CatalogFixtureError, createPrivateCatalog: async () => { throw error; },
    }, {}, {}));
    assert.equal(report.code, 'application_failed'); assert.doesNotMatch(JSON.stringify(report), /PRIVATE/u);
  }
});

test('catalog return validation and cancellation retain their actual observed boundary', async () => {
  const ctx = publishContext();
  const { report } = await lifecycleFailure(ctx, () => createPublishCatalog(ctx, {
    createPrivateCatalog: async () => ({ encrypted: true, sourceFallback: true, files: 1 }),
  }, {}, {}));
  assert.equal(report.stage, 'cloud_catalog_validate'); assert.equal(report.code, 'catalog_creation');
  ctx.stage = 'cloud_catalog_create'; ctx.signal.aborted = true;
  const cancelled = await lifecycleFailure(ctx, async () => { throw new Error('PRIVATE'); });
  assert.equal(cancelled.report.code, 'phase_deadline');
});

test('original deposit observation survives profile8 close failure without promotion or mutation', async () => {
  const ctx = publishContext(); ctx.stage = 'cloud_publish';
  const value = { status: 'incomplete', code: 'retained_operation_incomplete', local_process_joined: true,
    storage: { operation_complete: false, deposit_diagnostics: appendDiagnostics() } };
  const original = publishFailure(value, 'cloud', 'deposit', false, 8);
  const { report } = await lifecycleFailure(ctx, async () => requirePublishComplete(value, 'cloud', 'deposit', 8),
    async () => { throw new Error('PRIVATE-CLOSE'); });
  assert.equal(original.version, 9); assert.equal(report.version, 10);
  assert.deepEqual(report.publish_observation, original.publish_observation);
  assert.equal(report.code, 'publish_operation'); assert.equal(report.stage, 'cloud_publish');
});

test('profiles1 through7 preserve original finally precedence and legacy failure shape', async () => {
  for (let profile = 1; profile <= 7; profile++) {
    const ctx = publishContext(profile); ctx.stage = 'cloud_catalog';
    const primary = new CatalogFixtureError('RESTORE_INCOMPLETE'), close = new Error('PRIVATE-CLOSE');
    await assert.rejects(withPublishCore(ctx, 'cloud', { close: async () => { throw close; } },
      () => createPublishCatalog(ctx, { PrivateCatalogError: CatalogFixtureError,
        createPrivateCatalog: async () => { throw primary; } }, {}, {})), error => error === close);
    assert.deepEqual(consumerFailureReport(ctx, 'publish', close), { version: 1,
      kind: 'storage-consumer-maintenance', phase: 'publish', passed: false, provision_sha256: ctx.provision,
      stage: 'cloud_catalog', code: 'application_failed', cleanup_confirmed: false });
  }
});

test('real publish driver distinguishes missing policy read and still closes once', async () => {
  for (const profileVersion of [8, 9]) {
  const root = await mkdtemp(join(tmpdir(), 'vp-publish-'));
  try {
    await mkdir(join(root, 'image'), { mode: 0o700 });
    await mkdir(join(root, 'image/bundle'), { mode: 0o700 });
    const c = { version: 1, stateDirectory: join(root, 'image/archive'), deadlineMs: 100,
      providers: keys.map(key => ({ key })), fragmentBytes: 25,
      ...(profileVersion === 9 ? { flowAcquireDiagnosticsV8: true } : { appendDiagnosticsV7: true }) };
    await writeFile(join(root, 'image/storage.json'), JSON.stringify(c), { mode: 0o600 });
    await writeFile(join(root, 'image/bundle/receipt.json'), JSON.stringify({ cipher_bytes: 100,
      cipher_sha256: 'a'.repeat(64), cipher_file: 'snapshot.pgp' }), { mode: 0o600 });
    const ctx = { ...publishContext(profileVersion), root }, calls = [];
    const modules = { CoreStorage: { open: async configPath => {
      assert.equal(configPath, join(root, 'image/storage.json'));
      assert.deepEqual(JSON.parse(await readFile(configPath, 'utf8')), c);
      return { close: async () => { calls.push('close'); } };
    } },
      runSnapshotStorage: async ({ operation }) => {
        calls.push(operation);
        const value = storage();
        Object.assign(value.storage, { uncertain_payload_bytes: 0, physical_payload_charge_upper_bound: 200,
          deposit_diagnostics: { version: profileVersion - 1, failures: [], omitted_failures: 0 } });
        return value;
      } };
    let failed;
    try { await publish(ctx, modules); } catch (error) { failed = error; }
    assert.ok(failed);
    const report = consumerFailureReport(ctx, 'publish', failed);
    assert.equal(report.version, profileVersion + 2); assert.equal(report.stage, 'image_policy_read');
    assert.equal(report.code, 'application_failed');
    assert.deepEqual(report.publish_cleanup, { app: 'image', state: 'complete' });
    assert.deepEqual(calls, ['create', 'deposit', 'close']);
    assert.doesNotMatch(JSON.stringify(report), /ENOENT|vp-publish|maintenance-policy/u);
  } finally { await rm(root, { recursive: true, force: true }); }
  }
});

test('actual JS v10 failures pass the unchanged Python orchestration entry boundary', async () => {
  const records = [];
  for (const code of ['MATERIALIZATION_FAILED', 'RESTORE_INCOMPLETE']) {
    for (const closeFailed of [false, true]) {
      const ctx = publishContext();
      const { report } = await lifecycleFailure(ctx, () => createPublishCatalog(ctx, {
        PrivateCatalogError: CatalogFixtureError,
        createPrivateCatalog: async () => { throw new CatalogFixtureError(code); },
      }, {}, {}), async () => { if (closeFailed) throw new Error('PRIVATE-CLOSE'); });
      records.push(report);
    }
  }
  const ctx = publishContext();
  records.push((await lifecycleFailure(ctx, async () => {}, async () => { throw new Error('PRIVATE'); })).report);
  const source = 'import json, runpy, sys\n' +
    'm = runpy.run_path(sys.argv[1])\n' +
    'for v in json.load(sys.stdin):\n' +
    '    assert m["validate_node_report"](v, "publish", "a" * 64, profile_version=8) == v\n';
  const child = spawnSync('/usr/bin/python3', ['-I', '-B', '-c', source,
    fileURLToPath(new URL('./storage-consumer-maintenance-smoke.py', import.meta.url))], {
    input: JSON.stringify(records), encoding: 'utf8', timeout: 10000, maxBuffer: 16384,
  });
  assert.equal(child.status, 0, child.stderr); assert.equal(child.stdout, '');
});

test('actual profile9 JS node10 and lifecycle11 pass Python only with exact profile9 binding', async () => {
  const records = [];
  for (const app of ['image', 'cloud']) {
    const value = { status: 'incomplete', code: 'retained_operation_incomplete', local_process_joined: true,
      storage: { operation_complete: false, deposit_diagnostics: flowDiagnostics() } };
    records.push(publishFailure(value, app, 'deposit', false, 9));
    for (const closeFailed of [false, true]) {
      const ctx = { ...publishContext(9), stage: `${app}_publish` };
      records.push((await lifecycleFailure(ctx, () => requirePublishComplete(value, app, 'deposit', 9),
        async () => { if (closeFailed) throw new Error('PRIVATE'); }, app)).report);
    }
  }
  const source = 'import json, runpy, sys\n' +
    'm = runpy.run_path(sys.argv[1])\n' +
    'for v in json.load(sys.stdin):\n' +
    '    assert m["validate_node_report"](v, "publish", "a" * 64, profile_version=9) == v\n' +
    '    for old in range(1, 9):\n' +
    '        try: m["validate_node_report"](v, "publish", "a" * 64, profile_version=old)\n' +
    '        except ValueError: pass\n' +
    '        else: raise AssertionError("historical profile accepted new failure")\n';
  const child = spawnSync('/usr/bin/python3', ['-I', '-B', '-c', source,
    fileURLToPath(new URL('./storage-consumer-maintenance-smoke.py', import.meta.url))], {
    input: JSON.stringify(records), encoding: 'utf8', timeout: 10000, maxBuffer: 16384,
  });
  assert.equal(child.status, 0, child.stderr); assert.equal(child.stdout, '');
});

test('four explicit phases and distinct deterministic incompressible fixture identities', () => {
  assert.deepEqual(PHASES, ['prepare', 'publish', 'exercise', 'finish']);
  const image = fixtureBytes('image'), cloud = fixtureBytes('cloud');
  assert.equal(image.length, PLAIN_BYTES); assert.equal(cloud.length, PLAIN_BYTES);
  assert.ok(PLAIN_BYTES < MAX_CIPHER);
  assert.equal(hash(image), hash(fixtureBytes('image')));
  assert.notEqual(hash(image), hash(cloud));
  assert.notDeepEqual(image.subarray(0, 4096), image.subarray(4096, 8192));
  assert.throws(() => fixtureBytes('other'), /fixture_label/u);
});

test('same-fd private reads admit exact boundary and reject oversize, writable and symlink inputs', async t => {
  const root = await mkdtemp(join(tmpdir(), 'storage-consumer-inert-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const path = join(root, 'owned.json');
  await writeFile(path, 'abcd', { mode: 0o600 });
  assert.equal((await boundedFile(path, 4)).toString(), 'abcd');
  await assert.rejects(boundedFile(path, 3), /private_file/u);
  await chmod(path, 0o644); await assert.rejects(boundedFile(path, 4), /private_file/u);
  await chmod(path, 0o600); await symlink(path, join(root, 'link'));
  await assert.rejects(boundedFile(join(root, 'link'), 4));
});

test('checkpoint validates authority scope and closed stage/cursor bounds', () => {
  const cp = { version: 1, scope: 'owner-private-maintenance', stage: 'working', turns: 3, at: 1,
    core_coordinated: true, new_network_node: false, automatic_grant_refresh: false, private_key_exported: false };
  assert.deepEqual(validateCheckpoint(cp), { stage: 'working', turns: 3 });
  for (const delta of [{ turns: 4097 }, { turns: -1 }, { stage: 'arbitrary' }, { automatic_grant_refresh: true },
    { new_network_node: true }, { private_key_exported: true }, { core_coordinated: false }]) {
    assert.throws(() => validateCheckpoint({ ...cp, ...delta }), /checkpoint/u);
  }
});

test('repair readiness requires both surviving providers and preserved unavailable-source charge', () => {
  assert.equal(replacementReady(repaired(), keys), true);
  for (const mutate of [r => r.pop(), r => r[0].copies.pop(), r => { r[0].copies[0].charge = 'deleted'; },
    r => { r[0].copies[1].provider_key = [...Buffer.from(keys[0], 'hex')]; },
    r => { r[0].handoff.phase = 'copying'; }, r => { r[1].copies[0].charge = 'uncertain'; }]) {
    const value = repaired(); mutate(value); assert.equal(replacementReady(value, keys), false);
  }
});

test('public repair summary retains all eleven copies and the unavailable provider charge', () => {
  const selected = validateStorage(storage(), 100, 'repaired', 75);
  assert.equal(selected.physical_payload_charge_upper_bound, 275);
  assert.equal(selected.pending_retirements, 3);
  assert.equal(selected.retained_copy_records, 11);
  assert.ok(!Object.keys(selected).some(k => /key|archive|grant|path/u.test(k)));
  for (const field of ['pending_retirements', 'retained_copy_records', 'uncertain_payload_bytes',
    'placement_authorizations', 'committed_payload_bytes', 'fragment_count']) {
    const value = storage(); value.storage[field] = 0;
    assert.throws(() => validateStorage(value, 100, 'repaired', 75));
  }
  const noJoin = storage(); noJoin.local_process_joined = false;
  assert.throws(() => validateStorage(noJoin, 100, 'repaired', 75));
});

test('cleanup does not turn incomplete or zero-byte replacement claims into all-copy deletion', () => {
  assert.equal(validateStorage(storage('deleted'), 100, 'deleted').physical_payload_charge_upper_bound, 0);
  for (const mutate of [r => { r.status = 'incomplete'; }, r => { r.storage.operation_complete = false; },
    r => { r.storage.uncertain_payload_bytes = 1; }, r => { r.storage.retained_copy_records = 8; }]) {
    const value = storage('deleted'); mutate(value); assert.throws(() => validateStorage(value, 100, 'deleted'));
  }
  assert.throws(() => validateStorage(storage('published'), 100, 'unknown'), /storage_kind/u);
});

test('observation requires actual overlap window: paused checkpoint, active restore and absent owner', () => {
  const valid = new ForegroundObservation('10:20', 3);
  valid.sample([{ id: '11:21', kind: 'restore' }], { stage: 'paused', turns: 3 });
  const report = valid.finish({ owner: '12:22', turns: 4 });
  assert.equal(report.observed_old_owner_absent_while_foreground_active, true);
  assert.equal(report.exact_join_before_spawn_measured, false);
  assert.ok(!JSON.stringify(report).includes('10:20'));
  for (const [children, cp] of [[[], { stage: 'paused', turns: 3 }],
    [[{ id: '11:21', kind: 'restore' }, { id: '10:20', kind: 'owner' }], { stage: 'paused', turns: 3 }],
    [[{ id: '11:21', kind: 'restore' }], { stage: 'working', turns: 3 }]]) {
    const absent = new ForegroundObservation('10:20', 3); absent.sample(children, cp);
    assert.throws(() => absent.finish({ owner: '12:22', turns: 4 }), /foreground_observation_missing/u);
  }
  assert.throws(() => valid.finish({ owner: '10:20', turns: 4 }));
  assert.throws(() => valid.finish({ owner: '12:22', turns: 3 }));
});

test('retention progress needs original copy identity, committed full bytes and unexpired finite bound', () => {
  const before = Array.from({ length: 8 }, (_, i) => ({ identity: hash(String(i)), last_expiry: 100,
    last_state: 3, last_stored_bytes: 25, ciphertext_bytes: 25 }));
  assert.equal(retentionAdvanced(before, structuredClone(before), 200), 0);
  const after = structuredClone(before); after[0].last_expiry = 150;
  assert.equal(retentionAdvanced(before, after, 200), 1);
  after[0].last_state = 4; assert.equal(retentionAdvanced(before, after, 200), 0);
  after[0].last_state = 3; after[0].last_stored_bytes = 24;
  assert.equal(retentionAdvanced(before, after, 200), 0);
  after[0].last_stored_bytes = 25;
  assert.throws(() => retentionAdvanced(before, after, 149), /retention_identity/u);
  after[0].identity = hash('changed'); assert.throws(() => retentionAdvanced(before, after, 200), /retention_identity/u);
  after[0].identity = before[0].identity; after[0].last_expiry = 99;
  assert.throws(() => retentionAdvanced(before, after, 200), /retention_identity/u);
});

test('post-resume atomic journal replacement retries only inside the original budget', async () => {
  const cancel = new AbortController(), ctx = { signal: cancel.signal, deadline: performance.now() + 1000 };
  let reads = 0;
  assert.deepEqual(await retainedSnapshot(ctx, async () => {
    if (++reads === 1) throw Object.assign(new Error('changed'), { code: 'input_changed' });
    return [{ last_expiry: 100 }];
  }), [{ last_expiry: 100 }]);
  assert.equal(reads, 2);
  await assert.rejects(retainedSnapshot(ctx, async () => { throw Object.assign(new Error('bad mode'), { code: 'private_file' }); }), /bad mode/u);
  const deadline = ctx.deadline;
  cancel.abort();
  await assert.rejects(retainedSnapshot(ctx, async () => []), /phase_deadline/u);
  assert.equal(ctx.deadline, deadline);
});

test('proc identity parsing uses field22 even when process name contains spaces and parentheses', () => {
  const suffix = ['S', ...Array(18).fill('0'), '12345', '999'].join(' ');
  assert.equal(parseProcStat(`25 (name with ) parentheses) ${suffix}`), '12345');
  assert.throws(() => parseProcStat('malformed'), /proc_record/u);
  assert.throws(() => parseProcStat('25 (bad) S 1'), /proc_record/u);
});

test('entrypoint preserves actual app APIs, no runtime injection or reenrollment during exercise', async () => {
  const source = await readFile(new URL('./storage-consumer-maintenance.mjs', import.meta.url), 'utf8');
  const exercise = source.slice(source.indexOf('async function exercise('), source.indexOf('async function finish('));
  assert.match(exercise, /m\.runSnapshotStorage\(\{ operation: 'restore'/u);
  assert.match(exercise, /python\(\['restore'/u);
  assert.match(exercise, /m\.startCloudService/u);
  assert.match(exercise, /storageMaintenance: \[\{ config: join\(app, 'storage.json'\)/u);
  assert.match(exercise, /for await \(const chunk of dav\.streamFile\(selected\)\)/u);
  assert.match(exercise, /negativeAuthorization/u);
  assert.doesNotMatch(exercise, /enrollMaintenance|storePrivateFile|\.deposit\(|\.create\(|spawnProcess|openMaintenance:/u);
  assert.doesNotMatch(source, /npm|sudo|execSync|shell: true/u);
});
