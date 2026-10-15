#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
// Disposable guest proof. App encryption/restore and core maintenance are real;
// this observer neither schedules peers nor manufactures grants or core output.
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, readdir, readlink, realpath, unlink } from 'node:fs/promises';
import http from 'node:http';
import { hostname } from 'node:os';
import { dirname, join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { pathToFileURL } from 'node:url';
import { gzipSync } from 'node:zlib';

export const PHASES = Object.freeze(['prepare', 'publish', 'exercise', 'finish']);
export const MAX_CIPHER = 1024 ** 2;
export const PLAIN_BYTES = 786433;
const IMAGE = '/opt/volparossa-image', CLOUD = '/opt/volparossa-cloud';
const PROVISION = '/opt/volparossa-storage-consumers/provision.json';
const NODE = '/opt/volparossa-node/bin/node';
const REVISIONS = Object.freeze({ image: 'aade424c3e96d0934edbddf31d2434757aa08564',
  cloud: '9cb94fbb83e9f503ff5a66d43ed814f556d4a3af' });
const DIAGNOSTIC_REVISIONS = Object.freeze({ image: 'fa0438747b79bf29e49a2fe65116cb166ebe10df',
  cloud: 'f51b49b84af404cc8dd6e377e0545e2ca1ea4569' });
const DETAIL_REVISIONS = Object.freeze({ image: '87a8016652db629a0afefb41d88b3056539bee17',
  cloud: '54a00b58a6c24432e7427d72ff714c786dbeb0cc' });
const TLS_REVISIONS = Object.freeze({ image: '3b5830476dabd548debfdfade4fdf72acb4fa992',
  cloud: 'ea24b6cd53a14b204a7b8fbfda5c76ec9ca297e7' });
const OUTCOME_REVISIONS = Object.freeze({ image: 'ec6b9dca5789a60447c643652c93643b9a6c4af6',
  cloud: '4409c08680eebb3d679a036546691cb541675f97' });
const STREAM_REVISIONS = Object.freeze({ image: '949f208dbb48fcb734d4dfd33eb1933b69830a01',
  cloud: '7d10c4943062c5a0ae46fc57e293dc3e33db3ed2' });
const CHALLENGE_REVISIONS = Object.freeze({ image: '43029ea8b780de2376a3b7325d24a8e1c657f08e',
  cloud: 'e0db1cacf7bec2df3925ee454ec6216587b8ddef' });
const APPEND_REVISIONS = Object.freeze({ image: '10c46b9d6424929748e324fdd188a2f5ca77851a',
  cloud: 'dda7a21818ece774445cf63d6e9a01fe0f2803b2' });
const FLOW_REVISIONS = Object.freeze({ image: '9694a2b9dcb40aceefd78dbc0ab34303071a0ffd',
  cloud: '47b0f03b84913761570c3de7037ba5509b848c23' });
const CHECKPOINTS = new Set(['enrolled', 'owner_locked', 'waiting_for_core', 'working', 'paused',
  'enrollment_expired', 'core_unavailable', 'core_turn_revoked', 'turn_completed', 'retry_pending']);
const SQL = Buffer.from('-- VOLPAROSSA synthetic quiesced snapshot\nCREATE TABLE fixture (id integer);\nINSERT INTO fixture VALUES (1);\n');
const HASH = /^[a-f0-9]{64}$/u;
const FAILURE_CODES = new Set(['phase_deadline', 'authority_expired', 'authority_changed', 'retained_binding',
  'foreground_observation_missing', 'storage_result', 'repair_charge', 'delete_charge', 'publish_charge',
  'retention_identity', 'retention_geometry', 'checkpoint', 'child_cleanup', 'owner_join', 'image_restore',
  'image_decrypt', 'plaintext_mismatch', 'cloud_size', 'cloud_body', 'cloud_plaintext_cleanup', 'authorization',
  'cipher_identity', 'cipher_receipt', 'snapshot_crypto', 'publish_operation', 'enrollment_policy', 'enrollment',
  'fragment_geometry', 'catalog_creation', 'configuration', 'input_changed', 'private_file', 'private_directory']);
// Exact PrivateCatalogError codes retained by pinned Cloud dda7. In particular,
// MATERIALIZATION_FAILED does NOT distinguish Storage restore from decryption.
const CATALOG_CODES = Object.freeze({
  MATERIALIZATION_FAILED: 'catalog_materialization_failed',
  RESTORE_INCOMPLETE: 'catalog_restore_validation',
  INVALID_SOURCE_METADATA: 'catalog_metadata_validation',
  SOURCE_SELECTION_MISMATCH: 'catalog_selection_validation',
  RESTORED_FILE_INVALID: 'catalog_plaintext_validation',
  FILE_VERSION_CHANGED: 'catalog_file_version_changed',
  INVALID_FILE_RECEIPT: 'catalog_receipt_validation',
  CATALOG_CRYPTO_TIMEOUT: 'catalog_crypto_timeout',
  CATALOG_CRYPTO_UNAVAILABLE: 'catalog_crypto_unavailable',
  CATALOG_CRYPTO_FAILED: 'catalog_crypto_failed',
  INVALID_CATALOG_CRYPTO_REPORT: 'catalog_crypto_report_invalid',
  PRIVATE_CLEANUP_FAILED: 'catalog_cleanup_failed',
  PRIVATE_STAGE_CHANGED: 'catalog_stage_changed',
  CANCELLED: 'catalog_cancelled',
});
const PUBLISH_FAILURE_CODES = new Set([...Object.values(CATALOG_CODES), 'core_close_failed']);
const fail = code => { throw Object.assign(new Error(code), { code }); };
const check = (value, code) => { if (!value) fail(code); };
const sha = value => createHash('sha256').update(value).digest('hex');
const integer = (value, low, high) => Number.isSafeInteger(value) && value >= low && value <= high;
const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const fileSame = (a, b) => ['dev', 'ino', 'mode', 'uid', 'nlink', 'size', 'mtimeNs', 'ctimeNs'].every(k => a[k] === b[k]);
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

const PUBLISH_STATUSES = new Set(['complete', 'incomplete', 'failed', 'cancelled', 'timed_out']);
const PUBLISH_CODES = new Set(['ok', 'retained_operation_incomplete', 'invalid_core_report', 'core_failed',
  'cancelled', 'timed_out', 'report_too_large', 'restore_verification_failed']);
const observedBoolean = value => typeof value === 'boolean' ? value : null;
const DEPOSIT_OPERATIONS = new Set(['prepare', 'reserve', 'progress', 'append', 'finalize', 'renew', 'read_range', 'delete']);
const DEPOSIT_STAGES = new Set(['journal_open', 'authorization', 'agent_ready', 'challenge', 'signed_request',
  'wire_receipt', 'agent_terminal', 'accounting', 'local_input', 'receipt_validation', 'journal_save', 'deadline', 'unknown']);
const DEPOSIT_CATEGORIES = new Set(['io', 'timeout', 'protocol', 'agent_rejected', 'invalid', 'busy', 'store', 'unknown']);
const AGENT_CODES = new Set(['CONTENT_INVALID', 'CONTENT_UNAVAILABLE', 'CONTENT_BUSY', 'CONTENT_POLICY', 'unknown']);
const AGENT_STAGES = new Set(['unobserved', 'route_connect', 'control_selection', 'provider_lookup',
  'provider_cardinality', 'offer_validity', 'stream_open', 'tls_handshake', 'challenge']);
const EXCHANGE_STAGES = new Set(['stream_open', 'tls_handshake', 'challenge']);
const TLS_FAILURES = new Set(['offer', 'configuration', 'handshake_deadline', 'authentication', 'tls_other', 'io']);
const STREAM_FAILURES = new Set(['policy', 'route_state', 'route_material', 'flow_acquire',
  'transport_certificate', 'transport_tls', 'initial_paths', 'open_tcp_write', 'subflow_readiness', 'stream_attachment']);
const CHALLENGE_PHASES = new Set(['selector_write_flush', 'grant_write_flush', 'challenge_read_verify']);
const ELAPSED_BUCKETS = new Set(['under_1s', '1_to_5s', '5_to_15s', '15_to_30s',
  '30_to_60s', '60_to_90s', '90_to_120s', 'at_least_120s']);
const OUTCOME_PHASES = Object.freeze(['ready_write', 'local_request_read', 'local_request_verify',
  'local_payload_read', 'local_payload_verify', 'admission', 'remote_request_verify', 'remote_request_write',
  'remote_payload_write', 'remote_receipt_read', 'remote_receipt_verify', 'remote_payload_read', 'remote_payload_verify',
  'local_receipt_write', 'local_payload_write', 'provider_tls_close', 'transport_tls_close', 'final_route_check',
  'final_grant_check', 'final_lifetime_check', 'terminal_write']);
const closedKeys = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value)
  && equal(Object.keys(value).sort(), [...keys].sort());
const FLOW_HELPER_REASONS = Object.freeze(['helper_kernel', 'helper_capacity', 'helper_unavailable', 'helper_not_found',
  'helper_cleanup_incomplete', 'helper_other_rejection', 'helper_timeout', 'helper_io',
  'helper_validation', 'helper_authority', 'helper_correlation', 'helper_runtime_changed']);
const FLOW_PAIRS = Object.freeze({ source_port: ['entropy'],
  retirement_drain: ['unconfirmed', 'io', ...FLOW_HELPER_REASONS.filter(reason => reason !== 'helper_not_found')],
  material: ['metadata', 'topology'], slot_reservation: ['unconfirmed', 'local_capacity', 'local_unavailable'],
  helper_acquire: FLOW_HELPER_REASONS, descriptor_clone: ['io'],
  descriptor_adoption: ['metadata', 'io'], flow_metadata: ['metadata'] });

function flowAcquire(value) {
  check(closedKeys(value, ['rounds', 'first', 'last']) && integer(value.rounds, 1, 8), 'deposit_diagnostics');
  for (const endpoint of [value.first, value.last]) {
    check(closedKeys(endpoint, ['stage', 'reason']) && typeof endpoint.stage === 'string'
      && typeof endpoint.reason === 'string' && Object.hasOwn(FLOW_PAIRS, endpoint.stage)
      && FLOW_PAIRS[endpoint.stage].includes(endpoint.reason), 'deposit_diagnostics');
  }
  check(value.rounds !== 1 || (value.first.stage === value.last.stage && value.first.reason === value.last.reason),
    'deposit_diagnostics');
  return { rounds: value.rounds, first: { stage: value.first.stage, reason: value.first.reason },
    last: { stage: value.last.stage, reason: value.last.reason } };
}

function agentOutcome(value, stage, version = 4, operation = null) {
  if (value === null) return null;
  check(['wire_receipt', 'agent_terminal', 'deadline'].includes(stage)
    && closedKeys(value, ['status', 'detail', ...([7, 8].includes(version) ? ['append_timing'] : [])])
    && ['observed', 'missing', 'pending', 'expired', 'query_failed', 'query_timeout'].includes(value.status), 'deposit_diagnostics');
  if (value.status !== 'observed') {
    check(value.detail === null, 'deposit_diagnostics');
    if ([7, 8].includes(version)) check(value.append_timing === null, 'deposit_diagnostics');
    return { status: value.status, detail: null, ...([7, 8].includes(version) ? { append_timing: null } : {}) };
  }
  const d = value.detail;
  check(closedKeys(d, ['phase', 'category', 'deadline_scope']) && OUTCOME_PHASES.includes(d.phase)
    && ['io', 'auth', 'invalid', 'busy', 'store', 'expired', 'entropy', 'timeout', 'policy', 'unavailable', 'cancelled'].includes(d.category)
    && ['none', 'operation', 'exchange', 'bridge', 'remote_wire'].includes(d.deadline_scope)
    && (d.category === 'timeout') === (d.deadline_scope !== 'none')
    && (d.deadline_scope !== 'bridge' || OUTCOME_PHASES.slice(1, 15).includes(d.phase))
    && (d.deadline_scope !== 'remote_wire' || OUTCOME_PHASES.slice(6, 13).includes(d.phase)), 'deposit_diagnostics');
  let timing = null;
  if ([7, 8].includes(version) && value.append_timing !== null) {
    const t = value.append_timing;
    check(closedKeys(t, ['before_payload', 'in_payload_write_flush', 'in_receipt_read'])
      && operation === 'append' && ['remote_payload_write', 'remote_receipt_read'].includes(d.phase)
      && ELAPSED_BUCKETS.has(t.before_payload) && ELAPSED_BUCKETS.has(t.in_payload_write_flush)
      && (d.phase === 'remote_payload_write' ? t.in_receipt_read === null : ELAPSED_BUCKETS.has(t.in_receipt_read)),
    'deposit_diagnostics');
    timing = { before_payload: t.before_payload, in_payload_write_flush: t.in_payload_write_flush,
      in_receipt_read: t.in_receipt_read };
  }
  return { status: value.status, detail: { phase: d.phase, category: d.category, deadline_scope: d.deadline_scope },
    ...([7, 8].includes(version) ? { append_timing: timing } : {}) };
}

// This proof has exactly four fragments/two initial copies. The bridge already
// checks general archive geometry; revalidate the narrower exported trial here.
export function depositDiagnostic(value, version = 1) {
  check([1, 2, 3, 4, 5, 6, 7, 8].includes(version), 'deposit_diagnostics');
  check(closedKeys(value, ['version', 'failures', 'omitted_failures']) && value.version === version
    && Array.isArray(value.failures) && value.failures.length <= 8 && value.omitted_failures === 0, 'deposit_diagnostics');
  const seen = new Set(), failures = value.failures.map(failure => {
    check(closedKeys(failure, ['fragment_index', 'copy_index', 'operation', 'stage', 'category', 'agent_code',
      ...(version >= 2 ? ['agent_detail'] : []), ...(version >= 4 ? ['agent_outcome'] : [])])
      && integer(failure.fragment_index, 0, 3) && integer(failure.copy_index, 0, 1)
      && DEPOSIT_OPERATIONS.has(failure.operation) && DEPOSIT_STAGES.has(failure.stage)
      && DEPOSIT_CATEGORIES.has(failure.category)
      && (failure.category === 'agent_rejected' ? AGENT_CODES.has(failure.agent_code) : failure.agent_code === null),
    'deposit_diagnostics');
    let detail = null;
    if (version >= 2 && failure.agent_detail !== null) {
      const value = failure.agent_detail;
      check(failure.stage === 'agent_ready' && failure.category === 'agent_rejected'
        && AGENT_CODES.has(failure.agent_code) && failure.agent_code !== 'unknown'
        && closedKeys(value, ['stage', 'deadline_scope', ...(version >= 3 ? ['tls_failure'] : []),
          ...(version >= 5 ? ['stream_failure'] : []), ...(version >= 6 ? ['challenge'] : []),
          ...(version === 8 ? ['flow_acquire'] : [])])
        && AGENT_STAGES.has(value.stage)
        && ['none', 'operation', 'exchange'].includes(value.deadline_scope)
        && (value.stage !== 'unobserved' || value.deadline_scope === 'operation')
        && (value.deadline_scope !== 'exchange' || EXCHANGE_STAGES.has(value.stage))
        && (value.deadline_scope === 'none' || failure.agent_code === 'CONTENT_UNAVAILABLE'), 'deposit_diagnostics');
      detail = { stage: value.stage, deadline_scope: value.deadline_scope };
      if (version >= 3) {
        check(value.tls_failure === null || (TLS_FAILURES.has(value.tls_failure)
          && value.stage === 'tls_handshake' && value.deadline_scope === 'none'
          && failure.agent_code === 'CONTENT_UNAVAILABLE'), 'deposit_diagnostics');
        detail.tls_failure = value.tls_failure;
      }
      if (version >= 5) {
        check(value.stream_failure === null || (STREAM_FAILURES.has(value.stream_failure)
          && value.stage === 'stream_open' && value.deadline_scope === 'none'
          && value.tls_failure === null && failure.agent_code === 'CONTENT_UNAVAILABLE'), 'deposit_diagnostics');
        detail.stream_failure = value.stream_failure;
      }
      if (version >= 6) {
        const c = value.challenge;
        check(c === null || (closedKeys(c, ['phase', 'before_challenge', 'in_challenge'])
          && CHALLENGE_PHASES.has(c.phase) && ELAPSED_BUCKETS.has(c.before_challenge)
          && ELAPSED_BUCKETS.has(c.in_challenge) && value.stage === 'challenge'
          && value.tls_failure === null && value.stream_failure === null
          && failure.agent_code === 'CONTENT_UNAVAILABLE'), 'deposit_diagnostics');
        detail.challenge = c === null ? null : { phase: c.phase,
          before_challenge: c.before_challenge, in_challenge: c.in_challenge };
      }
      if (version === 8) {
        const flow = value.flow_acquire;
        check(flow === null || (value.stage === 'stream_open' && value.deadline_scope === 'none'
          && value.stream_failure === 'flow_acquire' && value.tls_failure === null && value.challenge === null
          && failure.agent_code === 'CONTENT_UNAVAILABLE'), 'deposit_diagnostics');
        detail.flow_acquire = flow === null ? null : flowAcquire(flow);
      }
    }
    const identity = `${failure.fragment_index}:${failure.copy_index}`;
    check(!seen.has(identity), 'deposit_diagnostics'); seen.add(identity);
    return { fragment_index: failure.fragment_index, copy_index: failure.copy_index,
      operation: failure.operation, stage: failure.stage, category: failure.category, agent_code: failure.agent_code,
      ...(version >= 2 ? { agent_detail: detail } : {}),
      ...(version >= 4 ? { agent_outcome: agentOutcome(failure.agent_outcome, failure.stage, version, failure.operation) } : {}) };
  });
  return { version, failures, omitted_failures: 0 };
}
class PublishFailure extends Error {
  constructor(observation) {
    super('publish_operation');
    this.code = 'publish_operation';
    this.observation = Object.freeze(observation);
  }
}

// Observe only the closed bridge result returned by this exact call. Never
// copy its raw storage report, paths, exceptions or private journal to evidence.
export function requirePublishComplete(value, app, operation, profileVersion = 1) {
  check(['image', 'cloud'].includes(app) && ['create', 'deposit'].includes(operation), 'arguments');
  check([1, 2, 3, 4, 5, 6, 7, 8, 9].includes(profileVersion), 'arguments');
  const report = value?.storage;
  const present = report !== null && typeof report === 'object' && !Array.isArray(report);
  let state = 'not_applicable', diagnostic = null;
  if (profileVersion >= 2 && operation === 'deposit') {
    state = 'missing';
    if (present && Object.hasOwn(report, 'deposit_diagnostics')) {
      try {
        diagnostic = depositDiagnostic(report.deposit_diagnostics, profileVersion - 1);
        check(report.operation_complete === false || (report.operation_complete === true && diagnostic.failures.length === 0),
          'deposit_diagnostics');
        check(value.status !== 'complete' || report.operation_complete === true, 'deposit_diagnostics');
        state = 'observed';
      } catch { state = 'invalid'; diagnostic = null; }
    }
  }
  if (value?.status === 'complete' && value.local_process_joined === true
    && (profileVersion === 1 || operation === 'create' || (state === 'observed' && diagnostic.failures.length === 0))) return;
  throw new PublishFailure({ version: profileVersion, app, operation,
    status: PUBLISH_STATUSES.has(value?.status) ? value.status : 'unknown',
    code: PUBLISH_CODES.has(value?.code) ? value.code : 'unknown',
    local_process_joined: observedBoolean(value?.local_process_joined),
    core_report_present: present,
    core_operation_complete: present ? observedBoolean(report.operation_complete) : null,
    ...(profileVersion >= 2 ? { deposit_diagnostics_state: state, deposit_diagnostics: diagnostic } : {}) });
}

export function consumerFailureReport(ctx, phase, error) {
  if (error instanceof PublishLifecycleFailure) {
    return { ...error.primary, version: ctx.profileVersion === 9 ? 11 : 10, publish_cleanup: error.cleanup };
  }
  const publish = error instanceof PublishFailure;
  return { version: publish ? error.observation.version + 1 : 1, kind: 'storage-consumer-maintenance', phase, passed: false,
    provision_sha256: ctx.provision, stage: ctx.stage,
    code: ctx.signal.aborted ? 'phase_deadline' : FAILURE_CODES.has(error?.code)
      || ([8, 9].includes(ctx.profileVersion) && phase === 'publish' && PUBLISH_FAILURE_CODES.has(error?.code))
      ? error.code : 'application_failed',
    ...(publish ? { publish_observation: error.observation } : {}), cleanup_confirmed: false };
}

class PublishLifecycleFailure extends Error {
  constructor(primary, cleanup, cause) {
    super('publish_lifecycle_failed', { cause });
    this.primary = Object.freeze(primary);
    this.cleanup = Object.freeze(cleanup);
  }
}

// This observation covers only the existing client close() call. It does not
// prove remote provider cleanup, private-directory removal or a successful phase.
export async function withPublishCore(ctx, app, core, operation) {
  if (![8, 9].includes(ctx.profileVersion)) {
    try { return await operation(); } finally { await core.close(); }
  }
  check(['image', 'cloud'].includes(app), 'arguments');
  let result, primary, cause;
  try { result = await operation(); }
  catch (error) {
    cause = error;
    try { primary = consumerFailureReport(ctx, 'publish', error); }
    catch { primary = consumerFailureReport(ctx, 'publish', undefined); }
  }
  const beforeClose = ctx.stage;
  ctx.stage = `${app}_core_close`;
  let state = 'complete';
  try { await core.close(); }
  catch (error) {
    state = 'failed';
    if (!primary) {
      cause = error;
      primary = consumerFailureReport(ctx, 'publish', { code: 'core_close_failed' });
    }
  }
  if (primary) throw new PublishLifecycleFailure(primary, { app, state }, cause);
  ctx.stage = beforeClose;
  return result;
}

export async function createPublishCatalog(ctx, m, request, options) {
  if ([8, 9].includes(ctx.profileVersion)) ctx.stage = 'cloud_catalog_create';
  let created;
  try { created = await m.createPrivateCatalog(request, options); }
  catch (error) {
    if ([8, 9].includes(ctx.profileVersion) && typeof m.PrivateCatalogError === 'function'
      && error instanceof m.PrivateCatalogError
      && Object.hasOwn(CATALOG_CODES, error.code)) {
      const code = CATALOG_CODES[error.code];
      throw Object.assign(new Error(code, { cause: error }), { code });
    }
    throw error;
  }
  if ([8, 9].includes(ctx.profileVersion)) ctx.stage = 'cloud_catalog_validate';
  check(created.encrypted === true && created.sourceFallback === false && created.files === 1, 'catalog_creation');
  return created;
}

export function fixtureBytes(label) {
  check(['image', 'cloud'].includes(label), 'fixture_label');
  const result = Buffer.alloc(PLAIN_BYTES);
  for (let offset = 0; offset < result.length; offset += 32) {
    createHash('sha256').update(`VOLPAROSSA storage consumer ${label} ${offset}`).digest().copy(result, offset);
  }
  return result;
}

async function directory(path) {
  const info = await lstat(path, { bigint: true });
  check(info.isDirectory() && info.uid === BigInt(process.getuid()) && (info.mode & 0o7777n) === 0o700n
    && await realpath(path) === path, 'private_directory');
  return { dev: String(info.dev), ino: String(info.ino) };
}

export async function boundedFile(path, maximum, { publicFile = false } = {}) {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await handle.stat({ bigint: true });
    check(before.isFile() && before.nlink === 1n && before.size > 0n && before.size <= BigInt(maximum)
      && (publicFile ? before.uid === 0n && (before.mode & 0o022n) === 0n
        : before.uid === BigInt(process.getuid()) && (before.mode & 0o7777n) === 0o600n), 'private_file');
    const bytes = Buffer.alloc(Number(before.size) + 1);
    let offset = 0;
    while (offset < bytes.length) {
      const read = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (!read.bytesRead) break;
      offset += read.bytesRead;
    }
    check(offset === Number(before.size) && fileSame(before, await handle.stat({ bigint: true }))
      && fileSame(before, await lstat(path, { bigint: true })), 'input_changed');
    return bytes.subarray(0, offset);
  } finally { await handle.close(); }
}
async function json(path, maximum = 65536, options) {
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(await boundedFile(path, maximum, options))); }
  catch (error) { if (error.code) throw error; fail('invalid_json'); }
}
async function write(path, bytes) {
  await directory(dirname(path));
  const handle = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
}
async function writeJSON(path, value, limit = 16384) {
  const bytes = Buffer.from(`${JSON.stringify(value)}\n`);
  check(bytes.length <= limit, 'output_bound');
  await write(path, bytes);
}
async function absent(path) {
  try { await lstat(path); } catch (error) { if (error.code === 'ENOENT') return; throw error; }
  fail('output_exists');
}
async function fresh(path) { await directory(dirname(path)); await mkdir(path, { mode: 0o700 }); await directory(path); }

export function validateCheckpoint(value) {
  check(value?.version === 1 && value.scope === 'owner-private-maintenance' && CHECKPOINTS.has(value.stage)
    && integer(value.turns, 0, 4096) && integer(value.at, 1, Number.MAX_SAFE_INTEGER)
    && value.core_coordinated === true && value.new_network_node === false
    && value.automatic_grant_refresh === false && value.private_key_exported === false, 'checkpoint');
  return { stage: value.stage, turns: value.turns };
}
async function checkpoint(app) {
  // The core atomically replaces this record. Retry a changed inode; never turn
  // an incomplete read into a successful lifecycle observation.
  try { return validateCheckpoint(await json(join(app, 'maintenance/checkpoint.json'), 32768)); }
  catch (error) { if (error.code === 'input_changed') return null; throw error; }
}

export function validateStorage(result, bytes, kind, aBytes = 0) {
  const s = result?.storage;
  check(result?.status === 'complete' && result.local_process_joined === true
    && s?.operation_complete === true && s.logical_ciphertext_bytes === bytes && s.fragment_count === 4
    && s.copies_per_fragment === 2 && s.distinct_provider_identities === 3
    && s.owner_signature_verified === true && s.reserved_payload_bytes === 0, 'storage_result');
  if (kind === 'deleted') {
    check(s.physical_payload_charge_upper_bound === 0 && s.committed_payload_bytes === 0
      && s.uncertain_payload_bytes === 0 && s.report_version === 2 && s.retained_copy_records === 11,
    'delete_charge');
  } else if (kind === 'repaired') {
    check(s.report_version === 2 && s.placement_authorizations === 3 && s.retained_copy_records === 11
      && s.pending_retirements === 3 && s.replacement_overhead_included === true
      && s.desired_copies_per_fragment === 2 && s.committed_payload_bytes === 2 * bytes
      && s.uncertain_payload_bytes === aBytes && s.physical_payload_charge_upper_bound === 2 * bytes + aBytes
      && s.fragments_with_confirmed_unexpired_copy === 4 && s.fully_redundant_from_retained_receipts === true,
    'repair_charge');
  } else {
    check(kind === 'published', 'storage_kind');
    check(s.physical_payload_charge_upper_bound === 2 * bytes && s.committed_payload_bytes === 2 * bytes
      && s.uncertain_payload_bytes === 0 && s.fully_redundant_from_retained_receipts === true, 'publish_charge');
  }
  return { logical_ciphertext_bytes: bytes, committed_payload_bytes: s.committed_payload_bytes,
    uncertain_payload_bytes: s.uncertain_payload_bytes, physical_payload_charge_upper_bound: s.physical_payload_charge_upper_bound,
    fragment_count: 4, copies_per_fragment: 2, retained_copy_records: s.retained_copy_records ?? 8,
    pending_retirements: s.pending_retirements ?? 0 };
}

function journalIdentity(value) {
  const keys = ['version', 'provider_key', 'owner_key', 'grant_hex', 'archive_id', 'ciphertext_bytes', 'sha256', 'lease'];
  check(keys.every(k => Object.hasOwn(value, k)) && typeof value.lease === 'string' && value.lease.length <= 128, 'journal_identity');
  return sha(JSON.stringify(Object.fromEntries(keys.map(k => [k, value[k]]))));
}
const fragmentPath = (app, i) => join(app, 'archive', `fragment-${String(i).padStart(4, '0')}`);
async function binding(app) {
  await directory(app);
  const config = await json(join(app, 'storage.json'));
  const signed = await json(join(app, 'maintenance/enrollment.json'), 32768);
  const manifest = await json(join(app, 'archive/fragments.json'));
  const e = signed.enrollment, m = manifest.manifest;
  check(config.stateDirectory === join(app, 'archive') && e?.archive === config.stateDirectory
    && integer(e.expires, 1, Number.MAX_SAFE_INTEGER)
    && m?.fragments?.length === 4 && m.providers?.length === 3 && m.copies_per_fragment === 2
    && m.fragments.every((f, i) => f.copies?.length === 2 && f.copies.every((c, j) => c.provider === (i + j) % 3)), 'archive_binding');
  const identities = [];
  for (let i = 0; i < 4; i++) for (let j = 0; j < 2; j++) {
    identities.push(journalIdentity(await json(join(fragmentPath(app, i), `copy-${j}`, 'archive.json'))));
  }
  return { config_sha256: sha(await boundedFile(join(app, 'storage.json'), 65536)),
    enrollment_sha256: sha(await boundedFile(join(app, 'maintenance/enrollment.json'), 32768)),
    root_sha256: sha(await boundedFile(join(app, 'archive/fragments.json'), 65536)),
    archive_directory: await directory(config.stateDirectory), enrollment_directory: await directory(join(app, 'maintenance')),
    journal_identities: identities, expires: e.expires,
    a_bytes: m.fragments.reduce((sum, f) => sum + (f.copies.some(c => c.provider === 0) ? f.length : 0), 0) };
}
async function unchanged(app, retained) { check(equal(await binding(app), retained), 'authority_changed'); }

// This is readiness observation, not a competing repair scheduler. Production
// CoreStorage verifies the full signed root/placement accounting before success.
export function replacementReady(records, providerKeys) {
  if (!Array.isArray(records) || records.length !== 4) return false;
  const hex = array => Array.isArray(array) ? Buffer.from(array).toString('hex') : '';
  return records.every((r, i) => {
    const replaced = i !== 1;
    if (!Array.isArray(r.copies) || r.copies.length !== (replaced ? 3 : 2)) return false;
    const committed = r.copies.filter(c => c.charge === 'committed');
    const uncertain = r.copies.filter(c => c.charge === 'uncertain');
    return committed.length === 2 && equal(committed.map(c => hex(c.provider_key)).sort(), providerKeys.slice(1).sort())
      && uncertain.length === Number(replaced) && uncertain.every(c => hex(c.provider_key) === providerKeys[0])
      && (!replaced || r.handoff?.phase === 'delete_pending');
  });
}
async function repairedOnDisk(app, config) {
  try {
    const records = await Promise.all(Array.from({ length: 4 }, (_, i) => json(join(fragmentPath(app, i), 'replicas.json'))));
    return replacementReady(records, config.providers.map(p => p.key));
  } catch (error) { if (error.code === 'input_changed') return false; throw error; }
}

async function retention(app, config) {
  const result = [];
  for (let i = 0; i < 4; i++) {
    const count = i === 1 ? 2 : 3;
    for (let j = 0; j < count; j++) {
      const path = join(fragmentPath(app, i), `copy-${j}`, 'archive.json');
      const value = await json(path, 16384);
      if (Buffer.from(value.provider_key).toString('hex') === config.providers[0].key) continue;
      result.push({ identity: journalIdentity(value), last_expiry: value.last_expiry,
        last_state: value.last_state, last_stored_bytes: value.last_stored_bytes, ciphertext_bytes: value.ciphertext_bytes });
    }
  }
  check(result.length === 8, 'retention_geometry');
  return result;
}
export function retentionAdvanced(before, after, expiry) {
  check(before.length === 8 && after.length === 8, 'retention_geometry');
  let advanced = 0;
  for (let i = 0; i < before.length; i++) {
    const old = before[i], now = after[i];
    check(HASH.test(now.identity) && now.identity === old.identity && now.ciphertext_bytes === old.ciphertext_bytes
      && integer(old.last_expiry, 1, expiry) && integer(now.ciphertext_bytes, 1, MAX_CIPHER)
      && integer(now.last_expiry, old.last_expiry, expiry), 'retention_identity');
    if (now.last_expiry > old.last_expiry && now.last_state === 3
      && now.last_stored_bytes === now.ciphertext_bytes) advanced++;
  }
  return advanced;
}

async function procText(path, maximum) {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const bytes = Buffer.alloc(maximum + 1);
    const { bytesRead } = await handle.read(bytes, 0, bytes.length, 0);
    check(bytesRead <= maximum, 'proc_bound');
    return bytes.subarray(0, bytesRead).toString('utf8');
  } finally { await handle.close(); }
}
export function parseProcStat(text) {
  const end = text.lastIndexOf(')');
  check(end > 1, 'proc_record');
  const fields = text.slice(end + 2).trim().split(/\s+/u);
  check(fields.length >= 20 && /^[0-9]+$/u.test(fields[19]), 'proc_record');
  return fields[19];
}
async function coreChildren(config, app) {
  const tasks = await readdir('/proc/self/task');
  check(tasks.length <= 64 && tasks.every(t => /^[0-9]+$/u.test(t)), 'proc_bound');
  const pids = new Set();
  for (const task of tasks) {
    let text;
    try { text = await procText(`/proc/self/task/${task}/children`, 4096); }
    catch (error) { if (error.code === 'ENOENT') continue; throw error; }
    check(/^[0-9 ]*$/u.test(text), 'proc_record');
    for (const pid of text.trim().split(' ').filter(Boolean)) pids.add(pid);
  }
  check(pids.size <= 32, 'proc_bound');
  const result = [];
  for (const pid of pids) {
    try {
      const base = `/proc/${pid}`, before = parseProcStat(await procText(`${base}/stat`, 8192));
      if (await readlink(`${base}/exe`) !== config.coreBinary) continue;
      const args = (await procText(`${base}/cmdline`, 16384)).split('\0');
      args.pop();
      const uid = (await procText(`${base}/status`, 16384)).match(/^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/mu);
      check(uid && uid.slice(1).every(v => Number(v) === process.getuid()), 'proc_owner');
      check(args[0] === config.coreBinary && args[1] === '--control-socket' && args[2] === config.controlSocket
        && args[3] === 'storage' && args[4] === 'fragments', 'proc_command');
      let kind = 'other';
      if (args[5] === 'maintenance' && args[6] === 'serve') {
        check(equal(args.slice(7), ['--enrollment', join(app, 'maintenance'), '--identity', config.identity,
          '--passphrase-file', config.passphraseFile]), 'proc_command');
        kind = 'owner';
      } else if (args[5] === 'restore') {
        check(args[6] === '--state' && args[7] === config.stateDirectory, 'proc_command');
        kind = 'restore';
      }
      if (before === parseProcStat(await procText(`${base}/stat`, 8192))) result.push({ id: `${pid}:${before}`, kind });
    } catch (error) { if (['ENOENT', 'ESRCH'].includes(error.code)) continue; throw error; }
  }
  return result;
}

async function until(ctx, predicate) {
  while (!ctx.signal.aborted && performance.now() < ctx.deadline) {
    const value = await predicate();
    if (value) return value;
    await sleep(20);
  }
  fail('phase_deadline');
}
export async function retainedSnapshot(ctx, read) {
  return until(ctx, async () => {
    try { return await read(); }
    catch (error) { if (error.code === 'input_changed') return false; throw error; }
  });
}
async function ownerActive(ctx, app, config, after = -1, exclude = null) {
  return until(ctx, async () => {
    const [cp, children] = await Promise.all([checkpoint(app), coreChildren(config, app)]);
    const owners = children.filter(c => c.kind === 'owner');
    check(owners.length <= 1, 'multiple_owners');
    return cp && cp.stage === 'working' && cp.turns > after && owners.length === 1
      && owners[0].id !== exclude ? { ...cp, owner: owners[0].id } : null;
  });
}

export class ForegroundObservation {
  constructor(oldOwner, before) { this.oldOwner = oldOwner; this.before = before; this.seen = false; }
  sample(children, cp) {
    if (children.some(c => c.kind === 'restore') && !children.some(c => c.id === this.oldOwner)
        && !children.some(c => c.kind === 'owner') && cp?.stage === 'paused' && cp.turns >= this.before) this.seen = true;
  }
  finish(resumed) {
    check(this.seen && resumed.owner !== this.oldOwner && resumed.turns > this.before, 'foreground_observation_missing');
    return { observed_old_owner_absent_while_foreground_active: true,
      observed_paused_checkpoint_during_foreground: true, fresh_owner_observed_after_foreground: true,
      cursor_before: this.before, cursor_after: resumed.turns, cursor_advanced: true,
      exact_join_before_spawn_measured: false };
  }
}
async function observeForeground(ctx, app, config, operation) {
  const before = await ownerActive(ctx, app, config);
  const observation = new ForegroundObservation(before.owner, before.turns);
  let settled = false, value, failure;
  const pending = Promise.resolve().then(operation).then(v => { value = v; }, e => { failure = e; }).finally(() => { settled = true; });
  try {
    await until(ctx, async () => {
      const [cp, children] = await Promise.all([checkpoint(app), coreChildren(config, app)]);
      observation.sample(children, cp);
      return settled;
    });
  } catch (error) { ctx.cancel.abort(); await pending; throw error; }
  await pending;
  if (failure) throw failure;
  const retentionBefore = await retainedSnapshot(ctx, () => retention(app, config));
  const resumed = await ownerActive(ctx, app, config, before.turns, before.owner);
  // No foreground renew/progress is issued here. Only the resumed real owner
  // can advance confirmed lease expiry; a new PID or admitted turn alone does
  // not establish useful maintenance. These are retained core-verified results,
  // not a claim that this JS observer independently verifies wire signatures.
  const authority = (await json(join(app, 'maintenance/enrollment.json'), 32768)).enrollment;
  const advanced = await until(ctx, async () => {
    try { return retentionAdvanced(retentionBefore, await retention(app, config), authority.expires); }
    catch (error) { if (error.code === 'input_changed') return false; throw error; }
  });
  return { value, lifecycle: { ...observation.finish(resumed), confirmed_retention_advanced_after_resume: true,
    confirmed_copy_retentions_advanced: advanced, completed_turn_observed: false } };
}

async function python(args, signal) {
  check(!signal.aborted, 'cancelled');
  return new Promise((resolve, reject) => {
    const child = spawn('/usr/bin/python3', ['-I', '-B', join(IMAGE, 'scripts/immich_snapshot.py'), ...args], {
      detached: true, shell: false, env: { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8' },
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    let bytes = 0, chunks = [], stopped = false, escalation;
    const stop = () => {
      if (stopped) return;
      stopped = true;
      const kill = s => { try { if (child.pid > 1) process.kill(-child.pid, s); } catch {} };
      kill('SIGTERM'); escalation = setTimeout(() => kill('SIGKILL'), 15000);
    };
    signal.addEventListener('abort', stop, { once: true });
    if (signal.aborted) stop();
    const timer = setTimeout(stop, 180000);
    child.stdout.on('data', chunk => { bytes += chunk.length; if (bytes > 65536) stop(); else chunks.push(chunk); });
    child.on('error', stop);
    child.on('close', (code, termination) => {
      clearTimeout(timer); clearTimeout(escalation); signal.removeEventListener('abort', stop);
      if (stopped || code !== 0 || termination !== null) { reject(Object.assign(new Error('snapshot_crypto'), { code: 'snapshot_crypto' })); return; }
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject(Object.assign(new Error('snapshot_crypto'), { code: 'snapshot_crypto' })); }
      chunks = [];
    });
  });
}

async function guard(root, profileVersion) {
  check(process.platform === 'linux' && process.getuid() !== 0 && hostname() === 'volparossa-alpha'
    && process.execPath === NODE && /^\/opt\/va\.[a-f0-9]{32}\.[A-Za-z0-9]{6}\/u\/m$/u.test(root), 'guest_only');
  await directory(root);
  const bytes = await boundedFile(PROVISION, 65536, { publicFile: true });
  const provision = JSON.parse(bytes.toString('utf8'));
  check(provision.version === profileVersion && provision.pins.version === profileVersion
    && provision.kind === 'storage-consumer-maintenance-runtime-provision'
    && provision.success === true && provision.guest_only === true && provision.shared_adapter_verified === true,
  'provision');
  const revisions = profileVersion === 9 ? FLOW_REVISIONS : profileVersion === 8 ? APPEND_REVISIONS : profileVersion === 7 ? CHALLENGE_REVISIONS : profileVersion === 6 ? STREAM_REVISIONS : profileVersion === 5 ? OUTCOME_REVISIONS
    : profileVersion === 4 ? TLS_REVISIONS : profileVersion === 3 ? DETAIL_REVISIONS
    : profileVersion === 2 ? DIAGNOSTIC_REVISIONS : REVISIONS;
  for (const [name, source] of Object.entries(provision.pins.sources)) {
    check(Object.hasOwn(revisions, name) && /^[a-f0-9]{40}$/u.test(revisions[name])
      && source.revision === revisions[name], 'source_pin');
    for (const [file, record] of Object.entries(source.files)) {
      check(/^[A-Za-z0-9_./-]+$/u.test(file) && !file.split('/').includes('..') && !file.startsWith('/'), 'source_pin');
      const raw = await boundedFile(join(name === 'image' ? IMAGE : CLOUD, file), 1024 ** 2, { publicFile: true });
      check(raw.length === record.bytes && sha(raw) === record.sha256, 'source_pin');
    }
  }
  check(equal(Object.keys(provision.pins.sources).sort(), ['cloud', 'image']), 'source_pin');
  return sha(bytes);
}
async function modules() {
  const imports = await Promise.all([
    `${IMAGE}/src/core-storage.mjs`, `${IMAGE}/scripts/snapshot-storage.mjs`, `${CLOUD}/src/private-file.mjs`,
    `${CLOUD}/src/private-catalog.mjs`, `${CLOUD}/scripts/cloud-serve.mjs`, `${CLOUD}/src/opencloud-dav.mjs`,
  ].map(p => import(pathToFileURL(p))));
  return Object.assign({}, ...imports);
}
async function receipt(app, name) {
  await directory(app); await directory(join(app, 'bundle'));
  const r = await json(join(app, 'bundle/receipt.json'), 4096);
  check(integer(r.cipher_bytes, 1, MAX_CIPHER) && HASH.test(r.cipher_sha256)
    && r.cipher_file === (name === 'image' ? 'snapshot.pgp' : 'file.pgp'), 'cipher_receipt');
  return r;
}
export function validateAppendProfile(value, profileVersion) {
  check([1, 2, 3, 4, 5, 6, 7, 8, 9].includes(profileVersion)
    && (profileVersion === 8 ? value.appendDiagnosticsV7 === true : !Object.hasOwn(value, 'appendDiagnosticsV7'))
    && (profileVersion === 9 ? value.flowAcquireDiagnosticsV8 === true : !Object.hasOwn(value, 'flowAcquireDiagnosticsV8')),
  'configuration');
}
async function config(app, profileVersion) {
  const value = await json(join(app, 'storage.json'));
  check(value.version === 1 && value.stateDirectory === join(app, 'archive')
    && value.providers?.length === 3 && new Set(value.providers.map(p => p.key)).size === 3
    && value.providers.every(p => HASH.test(p.key)) && integer(value.deadlineMs, 100, 1800000), 'configuration');
  validateAppendProfile(value, profileVersion);
  return value;
}
async function removeCipher(app, r) {
  await directory(app); await directory(join(app, 'bundle'));
  const path = join(app, 'bundle', r.cipher_file);
  const bytes = await boundedFile(path, MAX_CIPHER);
  check(bytes.length === r.cipher_bytes && sha(bytes) === r.cipher_sha256, 'cipher_identity');
  await unlink(path); // Only this newly generated, verified fixture cache; keep keys and receipts.
  await absent(path);
}
async function prepare(ctx, m) {
  const result = {};
  for (const name of ['image', 'cloud']) {
    ctx.stage = `${name}_encrypt`;
    const app = join(ctx.root, name);
    await fresh(app);
    const plain = fixtureBytes(name);
    if (name === 'image') {
      await fresh(join(app, 'source')); await fresh(join(app, 'source/upload'));
      await write(join(app, 'source/database.sql.gz'), gzipSync(SQL));
      await write(join(app, 'source/upload/synthetic-media.bin'), plain);
      await python(['create', '--source', join(app, 'source'), '--quiesced-copy', '--output', join(app, 'bundle'),
        '--max-bytes', '16777216', '--timeout-seconds', '120'], ctx.signal);
    } else {
      await write(join(app, 'source.bin'), plain);
      await m.sealOwnerUpload({ source: join(app, 'source.bin'), space: 'synthetic-space', name: 'synthetic.bin',
        size: plain.length, sha256: sha(plain), output: join(app, 'bundle') }, { signal: ctx.signal });
    }
    const r = await receipt(app, name);
    const cipher = await boundedFile(join(app, 'bundle', r.cipher_file), MAX_CIPHER);
    check(cipher.length === r.cipher_bytes && sha(cipher) === r.cipher_sha256, 'cipher_identity');
    result[name] = { cipher_bytes: r.cipher_bytes, cipher_sha256: r.cipher_sha256, application_encryption: 'OpenPGP-AES256' };
  }
  return result;
}
export async function publish(ctx, m) {
  const result = {}, retained = { version: 1, provision_sha256: ctx.provision };
  for (const name of ['image', 'cloud']) {
    ctx.stage = `${name}_publish`;
    const app = join(ctx.root, name), r = await receipt(app, name), c = await config(app, ctx.profileVersion);
    check(c.fragmentBytes === Math.ceil(r.cipher_bytes / 4), 'fragment_geometry');
    const core = await m.CoreStorage.open(join(app, 'storage.json'));
    await withPublishCore(ctx, name, core, async () => {
      const factory = async path => { check(path === join(app, 'storage.json'), 'configuration'); return core; };
      let deposited;
      for (const operation of ['create', 'deposit']) {
        const value = name === 'image'
          ? await m.runSnapshotStorage({ operation, config: join(app, 'storage.json'), bundle: join(app, 'bundle') }, { signal: ctx.signal, storageFactory: factory })
          : await m.storePrivateFile(operation, { config: join(app, 'storage.json'), bundle: join(app, 'bundle') }, { signal: ctx.signal, storageFactory: factory });
        requirePublishComplete(value, name, operation, ctx.profileVersion);
        if (operation === 'deposit') deposited = validateStorage(value, r.cipher_bytes, 'published');
      }
      if (name === 'cloud') {
        ctx.stage = [8, 9].includes(ctx.profileVersion) ? 'cloud_catalog_prepare' : 'cloud_catalog';
        await fresh(join(app, 'work'));
        await createPublishCatalog(ctx, m, { selection: [{ segments: ['synthetic-space', 'synthetic.bin'],
          bundle: join(app, 'bundle'), config: join(app, 'storage.json') }], output: join(app, 'catalog'),
        workDirectory: join(app, 'work'), maxTotalBytes: 4 * MAX_CIPHER }, { signal: ctx.signal, storageFactory: factory });
      }
      if ([8, 9].includes(ctx.profileVersion)) ctx.stage = `${name}_policy_read`;
      const policy = await json(join(app, 'maintenance-policy.json'), 32768);
      ctx.stage = `${name}_enroll`;
      check(policy.enrollment === join(app, 'maintenance') && policy.fromProviderKey === c.providers[0].key
        && equal(policy.providers, c.providers.slice(1)) && policy.maximumChargedBytes === 3 * r.cipher_bytes,
      'enrollment_policy');
      const enrolled = await core.enrollMaintenance(policy, { signal: ctx.signal });
      check(enrolled.status === 'complete' && enrolled.local_process_joined === true
        && enrolled.checkpoint?.stage === 'enrolled' && enrolled.checkpoint.turns === 0, 'enrollment');
      retained[name] = await binding(app);
      result[name] = { cipher_sha256: r.cipher_sha256, ...deposited, enrollment_created: true,
        maintenance_started: false, original_journals_bound: true };
    });
  }
  await writeJSON(join(ctx.root, 'consumer-binding.json'), retained);
  return result;
}

async function negativeAuthorization(origin, signal) {
  return new Promise((resolve, reject) => {
    const req = http.request(new URL('/dav/spaces/synthetic-space/synthetic.bin', origin), {
      method: 'GET', agent: false, signal, headers: { Authorization: `Bearer ${randomBytes(32).toString('hex')}` },
      timeout: 10000, maxHeaderSize: 8192,
    }, response => {
      let size = 0;
      response.on('data', chunk => { size += chunk.length; if (size > 4096) response.destroy(); });
      response.on('error', reject);
      response.on('end', () => { try { check(response.statusCode === 401 && size <= 4096, 'authorization'); resolve(true); } catch (e) { reject(e); } });
    });
    req.on('timeout', () => req.destroy()); req.on('error', reject); req.end();
  });
}
async function waitRepaired(ctx, app, c) {
  await until(ctx, () => repairedOnDisk(app, c));
}
async function exercise(ctx, m) {
  const retained = await json(join(ctx.root, 'consumer-binding.json'));
  check(retained.version === 1 && retained.provision_sha256 === ctx.provision, 'retained_binding');
  const expiry = Math.min(retained.image.expires, retained.cloud.expires);
  check(expiry * 1000 > Date.now(), 'authority_expired');
  const timer = setTimeout(() => ctx.cancel.abort(), Math.min(1800000, expiry * 1000 - Date.now()));
  const result = {};
  try {
    for (const name of ['image', 'cloud']) {
      ctx.stage = `${name}_authority`;
      const app = join(ctx.root, name), r = await receipt(app, name), c = await config(app, ctx.profileVersion);
      await unchanged(app, retained[name]);
      await removeCipher(app, r);
      if (name === 'image') {
        const core = await m.CoreStorage.open(join(app, 'storage.json'));
        let session;
        try {
          ctx.stage = 'image_repair';
          session = await core.startMaintenance({ enrollment: join(app, 'maintenance') }, { signal: ctx.signal });
          await waitRepaired(ctx, app, c);
          const accounting = validateStorage(await core.status({ signal: ctx.signal }), r.cipher_bytes, 'repaired', retained[name].a_bytes);
          ctx.stage = 'image_foreground_restore';
          const observed = await observeForeground(ctx, app, c, () => m.runSnapshotStorage({ operation: 'restore',
            config: join(app, 'storage.json'), receipt: join(app, 'bundle/receipt.json'), output: join(app, 'restored-bundle') },
          { signal: ctx.signal, storageFactory: async path => { check(path === join(app, 'storage.json'), 'configuration'); return core; } }));
          check(observed.value.restore_verified === true && observed.value.recovery_bundle_ready === true, 'image_restore');
          validateStorage(observed.value, r.cipher_bytes, 'repaired', retained[name].a_bytes);
          ctx.stage = 'image_decrypt';
          await write(join(app, 'restored-bundle/recovery.key'), await boundedFile(join(app, 'bundle/recovery.key'), 1024));
          const decrypted = await python(['restore', '--bundle', join(app, 'restored-bundle'), '--expected-sha256', r.cipher_sha256,
            '--output', join(app, 'restored-source'), '--max-bytes', '16777216', '--timeout-seconds', '120'], ctx.signal);
          check(decrypted.restored === true && decrypted.manifest_verified === true && decrypted.openpgp_integrity_verified === true,
            'image_decrypt');
          check((await boundedFile(join(app, 'restored-source/upload/synthetic-media.bin'), MAX_CIPHER)).equals(fixtureBytes(name))
            && (await boundedFile(join(app, 'restored-source/database.sql.gz'), 4096)).equals(gzipSync(SQL)), 'plaintext_mismatch');
          await core.close();
          const stopped = await session.done;
          check(stopped.status === 'stopped' && stopped.local_process_joined === true, 'owner_join');
          result.image = { ...accounting, ...observed.lifecycle, cipher_cache_removed_before_read: true,
            application_decryption_verified: true, plaintext_sha256: sha(fixtureBytes(name)), plaintext_bytes: PLAIN_BYTES,
            quiesced_sql_dump_restored: true, original_enrollment_and_journals_retained: true, owner_joined: true };
        } finally { await core.close(); }
      } else {
        ctx.stage = 'cloud_start';
        const token = randomBytes(32).toString('base64url');
        const service = await m.startCloudService({ version: 1, catalog: join(app, 'catalog'), workDirectory: join(app, 'work'),
          bearerToken: token, port: 0, allowedOrigins: [], maxOpenBytes: 4 * MAX_CIPHER, maxConcurrent: 1,
          requestTimeoutMs: 900000, maxRangeBytes: 4 * MAX_CIPHER,
          storageMaintenance: [{ config: join(app, 'storage.json'), enrollment: join(app, 'maintenance') }] }, { signal: ctx.signal });
        try {
          ctx.stage = 'cloud_repair';
          await waitRepaired(ctx, app, c);
          await negativeAuthorization(service.origin, ctx.signal);
          ctx.stage = 'cloud_authenticated_read';
          const dav = m.createOpenCloudDav({ origin: service.origin, bearerToken: token,
            allowInsecureLoopbackForTests: true, maxFileBytes: MAX_CIPHER, maxRequestBytes: MAX_CIPHER,
            timeoutMs: 120000, totalTimeoutMs: 900000 });
          const selected = await dav.stat({ spaceId: 'synthetic-space', pathSegments: ['synthetic.bin'] });
          check(selected.size === PLAIN_BYTES, 'cloud_size');
          const observed = await observeForeground(ctx, app, c, async () => {
            const hash = createHash('sha256'); let bytes = 0;
            for await (const chunk of dav.streamFile(selected)) {
              bytes += chunk.length; check(bytes <= PLAIN_BYTES && !ctx.signal.aborted, 'cloud_body'); hash.update(chunk);
            }
            check(bytes === PLAIN_BYTES && hash.digest('hex') === sha(fixtureBytes(name)), 'plaintext_mismatch');
          });
          await service.close();
          const core = await m.CoreStorage.open(join(app, 'storage.json'));
          try {
            const accounting = validateStorage(await core.status({ signal: ctx.signal }), r.cipher_bytes, 'repaired', retained[name].a_bytes);
            result.cloud = { ...accounting, ...observed.lifecycle, cipher_cache_removed_before_read: true,
              authenticated_get_body_verified: true, wrong_token_status: 401, plaintext_sha256: sha(fixtureBytes(name)),
              plaintext_bytes: PLAIN_BYTES, original_enrollment_and_journals_retained: true, owner_joined: true };
          } finally { await core.close(); }
          check((await readdir(join(app, 'work'))).length === 0, 'cloud_plaintext_cleanup');
        } finally { await service.close(); }
      }
      await unchanged(app, retained[name]);
      ctx.stage = `${name}_joined`;
      check((await coreChildren(c, app)).length === 0, 'child_cleanup');
    }
    check(!ctx.signal.aborted && Date.now() < expiry * 1000, 'authority_expired');
    return result;
  } finally { clearTimeout(timer); }
}
async function finish(ctx, m) {
  const retained = await json(join(ctx.root, 'consumer-binding.json')), result = {};
  check(retained.provision_sha256 === ctx.provision, 'retained_binding');
  for (const name of ['image', 'cloud']) {
    ctx.stage = `${name}_delete`;
    const app = join(ctx.root, name), r = await receipt(app, name), c = await config(app, ctx.profileVersion);
    await unchanged(app, retained[name]);
    const core = await m.CoreStorage.open(join(app, 'storage.json'));
    try {
      const deleted = validateStorage(await core.delete({ signal: ctx.signal }), r.cipher_bytes, 'deleted');
      await core.close();
      check((await coreChildren(c, app)).length === 0, 'child_cleanup');
      result[name] = { ...deleted, all_retained_copies_delete_acknowledged: true, owner_joined: true,
        provider_usage_independently_checked: false, private_fixture_removed: false };
    } finally { await core.close(); }
  }
  return result;
}

export async function main(argv) {
  let profileVersion = 1;
  if (argv.length === 4 && argv[2] === '--profile-version' && ['2', '3', '4', '5', '6', '7', '8', '9'].includes(argv[3])) {
    profileVersion = Number(argv[3]); argv = argv.slice(0, 2);
  }
  check(argv.length === 2 && PHASES.includes(argv[0]), 'arguments');
  process.umask(0o077);
  const [phase, root] = argv, provision = await guard(root, profileVersion), cancel = new AbortController();
  const abort = () => cancel.abort();
  for (const name of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.on(name, abort);
  const timer = setTimeout(abort, 1800000);
  const ctx = { root, provision, profileVersion, cancel, signal: cancel.signal, deadline: performance.now() + 1800000, stage: 'phase_start' };
  try {
    await absent(join(root, `storage-consumer-${phase}.json`));
    if (phase !== 'prepare') {
      const previous = await json(join(root, `storage-consumer-${PHASES[PHASES.indexOf(phase) - 1]}.json`), 16384);
      check(previous.version === 1 && previous.passed === true && previous.provision_sha256 === provision, 'previous_phase');
    }
    const m = await modules(), evidence = await ({ prepare, publish, exercise, finish })[phase](ctx, m);
    check(!ctx.signal.aborted && performance.now() < ctx.deadline, 'phase_deadline');
    const report = { version: 1, kind: 'storage-consumer-maintenance', phase, passed: true,
      provision_sha256: provision, ...evidence, scope: { synthetic_inputs: true,
        private_keys_exported: false, automatic_grant_refresh: false, immich_running_proven: false,
        opencloud_account_server_proven: false, protected_routes_independently_proven: false,
        provider_cleanup_independently_proven: false } };
    await writeJSON(join(root, `storage-consumer-${phase}.json`), report);
    return report;
  } catch (error) {
    // Export no raw app/core exception, command, path, key or process output.
    // A partial phase is never converted to success or a remote cleanup claim.
    const report = consumerFailureReport(ctx, phase, error);
    try { await writeJSON(join(root, `storage-consumer-${phase}.json`), report); } catch { /* Preserve original failure. */ }
    return report;
  } finally {
    clearTimeout(timer); for (const name of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.off(name, abort);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { const report = await main(process.argv.slice(2)); process.stdout.write(`${JSON.stringify(report)}\n`); process.exitCode = report.passed ? 0 : 1; }
  catch { process.stderr.write('{"version":1,"kind":"storage-consumer-maintenance","passed":false,"code":"consumer_phase_failed"}\n'); process.exitCode = 1; }
}
