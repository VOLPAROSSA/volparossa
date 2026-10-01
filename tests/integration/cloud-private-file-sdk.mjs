// SPDX-License-Identifier: GPL-3.0-only
// Disposable guest only: actual pinned Cloud CLIs and published Web SDK. No factories.
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { lstat, readFile, realpath, mkdir, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

const SOURCE = '/opt/volparossa-cloud';
const NODE = '/opt/volparossa-node/bin/node';
const SDK = `${SOURCE}/build/web-sdk`;
const ARCHIVE_SHA = '8954d9ad90e44a6f62d0e32d3280ca92fd7b0ce30042fe07cdde5c653e0739b3';
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const children = new Set();
const cancel = new AbortController();
let cleanupFailed = false;
let stage = 'not_started';
let uiFailure = null;
const insist = value => assert.ok(value, 'Cloud SDK boundary or operation failed');

// Only fixed phase names and process termination metadata cross this boundary.
// Browser text, URLs, bearer input and stderr never become diagnostics.
export function closedUIFailure(stdout, status) {
  const stages = new Set(['input', 'browser_start', 'locked_ui', 'wrong_token', 'unlock',
    'original_download_1', 'original_download_2', 'logout']);
  const signals = new Set(['SIGTERM', 'SIGKILL', 'SIGINT', 'SIGHUP', 'SIGABRT',
    'SIGSEGV', 'SIGBUS', 'SIGILL', 'SIGPIPE']);
  let childStage = 'unreported';
  try {
    const record = JSON.parse(stdout);
    if (record && Object.keys(record).sort().join(',') === 'kind,stage,success'
      && record.success === false && record.kind === 'cloud-private-file-ui-failure'
      && stages.has(record.stage)) childStage = record.stage;
  } catch { /* No extraction, repair or raw output on malformed child reports. */ }
  return { stage: childStage,
    exit_status: Number.isInteger(status?.code) && status.code >= 0 && status.code <= 255 ? status.code : null,
    signal: status?.signal === null ? null : signals.has(status?.signal) ? status.signal : 'UNREPORTED' };
}

async function privateDirectory(directory) {
  const info = await lstat(directory);
  insist(info.isDirectory() && info.uid === process.getuid() && (info.mode & 0o777) === 0o700
    && await realpath(directory) === directory);
}
async function absent(file) {
  try { await lstat(file); } catch (error) { if (error.code === 'ENOENT') return; throw error; }
  throw new Error('Unexpected retained private source');
}
async function privateJSON(file, value) {
  await writeFile(file, JSON.stringify(value) + '\n', { flag: 'wx', mode: 0o600 });
}
async function publicBytes(file) {
  const info = await lstat(file);
  insist(info.isFile() && info.uid === 0 && !(info.mode & 0o222)
    && info.size <= 2 * 1024 ** 2 && await realpath(file) === file);
  return readFile(file);
}
async function sdkProvenance() {
  const bytes = await publicBytes(`${SDK}/receipt.json`);
  const receipt = JSON.parse(bytes);
  const manifest = JSON.parse(await publicBytes(`${SOURCE}/third_party/opencloud-web-sdk.json`));
  const provision = JSON.parse(await publicBytes(`${SOURCE}/provision.json`));
  insist(receipt.version === 1 && receipt.kind === 'opencloud-web-sdk-trial'
    && receipt.archive_sha256 === ARCHIVE_SHA && receipt.package_scripts_run === false
    && receipt.source_build_claimed === false && receipt.global_installation === false
    && receipt.pins_sha256 === digest(await publicBytes(`${SOURCE}/third_party/opencloud-web-sdk.json`))
    && manifest.package === '@opencloud-eu/web-client' && manifest.package_version === '8.0.0'
    && Object.keys(receipt.files).length === 109 && provision.sdk.receipt_sha256 === digest(bytes)
    && provision.sdk.files_verified === true);
  let total = 0;
  for (const [name, record] of Object.entries(receipt.files)) {
    insist(name.startsWith('package/') && !name.includes('\\')
      && name.split('/').every(part => part && part !== '.' && part !== '..'));
    const body = await publicBytes(`${SDK}/${name}`);
    insist(body.length === record.bytes && digest(body) === record.sha256);
    total += body.length;
  }
  insist(total === 1109076 && receipt.files['package/LICENSE']
    && receipt.files['package/dist/web-client/webdav.js']);
  return { receiptSha: digest(bytes), pinsSha: receipt.pins_sha256 };
}

function launchProcess(executable, args, input) {
  insist(!cancel.signal.aborted);
  const child = spawn(executable, args, {
    stdio: [input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'], env: { PATH: '/usr/bin:/bin', LC_ALL: 'C' },
  });
  const state = { child, stdout: '', stderr: '', exited: false, overflow: false };
  children.add(state);
  state.finished = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => { state.exited = true; children.delete(state); resolve({ code, signal }); });
  });
  // Attach the rejection observer before asynchronous readiness checks.
  state.finished.catch(() => {});
  for (const stream of ['stdout', 'stderr']) child[stream].on('data', chunk => {
    if (state[stream].length + chunk.length > 65536) { state.overflow = true; child.kill('SIGTERM'); }
    else state[stream] += chunk.toString('utf8');
  });
  if (input !== undefined) {
    child.stdin.on('error', () => {}); // Child status remains authoritative; never export private input.
    child.stdin.end(input);
  }
  return state;
}
function launch(script, args) {
  return launchProcess(NODE, [`${SOURCE}/scripts/${script}`, ...args]);
}
async function stop(state) {
  if (!state) return;
  if (!state.exited) state.child.kill('SIGTERM');
  const timer = setTimeout(() => { if (!state.exited) state.child.kill('SIGKILL'); }, 15000);
  try { return await state.finished; } finally { clearTimeout(timer); }
}
async function runCLI(script, args) {
  const state = launch(script, args);
  const timer = setTimeout(() => state.child.kill('SIGTERM'), 900000);
  try {
    const status = await state.finished;
    insist(status.code === 0 && status.signal === null && !state.overflow && !state.stderr);
    return JSON.parse(state.stdout.trim());
  } finally { clearTimeout(timer); await stop(state); }
}
async function startService(config) {
  const service = launch('cloud-serve.mjs', ['--config', config]);
  try {
    const deadline = Date.now() + 60000;
    while (!service.stdout.includes('\n')) {
      insist(!service.exited && !service.overflow && !cancel.signal.aborted && Date.now() < deadline);
      await delay(25);
    }
    const record = JSON.parse(service.stdout.split('\n')[0]);
    insist(record.version === 1 && record.kind === 'volparossa-cloud-private-read'
      && record.state === 'listening' && record.readOnly === true && record.loopbackOnly === true
      && record.originalServerFallback === false && record.openCloudAccountService === false
      && /^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/u.test(record.origin));
    return { service, origin: record.origin };
  } catch (error) { await stop(service); throw error; }
}

async function originalUI(root, origin, bearerToken, content) {
  const script = path.join(path.dirname(fileURLToPath(import.meta.url)), 'cloud-private-file-ui.py');
  const input = JSON.stringify({ origin, bearerToken, expectedBytes: content.length, expectedSha256: digest(content) });
  insist(Buffer.byteLength(input) < 4096);
  const state = launchProcess('/usr/bin/python3', ['-B', script, root], input);
  const timer = setTimeout(() => state.child.kill('SIGTERM'), 1900000);
  let status;
  try {
    status = await state.finished;
    insist(status.code === 0 && status.signal === null && !state.overflow && !state.stderr);
    const result = JSON.parse(state.stdout.trim());
    assert.deepEqual(result, { version: 1, kind: 'cloud-private-file-original-ui', success: true,
      original_files_ui: true, actual_owner_service: true, synthetic_backend: false,
      file_downloads_verified: 2, download_bytes: content.length, download_sha256: digest(content),
      wrong_token_denied: true, logout_relocks: true, token_absent_from_url_and_web_storage: true,
      private_profile_removed: true, browser_stopped_and_joined: true,
      browser_version: '140.16.0', owner_secrets_exported: false });
    return result;
  } catch (error) {
    uiFailure = closedUIFailure(state.stdout, status);
    throw error;
  } finally { clearTimeout(timer); await stop(state); }
}

async function main(root) {
  insist(process.argv.length === 3 && path.isAbsolute(root) && process.execPath === NODE);
  await privateDirectory(root);
  await absent(`${root}/bundle/file.pgp`);
  await absent(`${root}/source.private.json`);
  const metadata = JSON.parse(await readFile(`${root}/fixture.json`));
  // Independent fixture bytes; never use restored data itself as its expected hash.
  const content = Buffer.alloc(3 * 262144 + 1);
  for (let index = 0; index < content.length - 1; index += 1) content[index] = index % 256;
  content[content.length - 1] = 67;
  insist(metadata.plaintext_bytes === content.length && metadata.plaintext_sha256 === digest(content));
  const provenance = await sdkProvenance();
  await mkdir(`${root}/w`, { mode: 0o700 });
  await privateJSON(`${root}/selection.json`, { version: 1, files: [{
    segments: ['synthetic-owner', 'private-file.bin'], bundle: `${root}/bundle`, config: `${root}/storage.json`,
  }] });
  stage = 'catalog_create';
  const catalog = await runCLI('cloud-catalog.mjs', ['create', '--selection', `${root}/selection.json`,
    '--catalog', `${root}/catalog`, '--work-directory', `${root}/w`]);
  insist(catalog.version === 1 && catalog.kind === 'volparossa-cloud-private-catalog-created'
    && catalog.files === 1 && catalog.plaintextBytes === content.length
    && catalog.selectedCiphertextBytes === metadata.ciphertext_bytes && catalog.encrypted === true
    && catalog.ownerOnly === true && catalog.sourceFallback === false && catalog.secondDeviceRecoveryProven === false);
  assert.deepEqual(await readdir(`${root}/w`), []);
  const token = randomBytes(32).toString('base64url');
  await privateJSON(`${root}/service.json`, { version: 1, catalog: `${root}/catalog`, workDirectory: `${root}/w`,
    bearerToken: token, port: 0, allowedOrigins: [], maxOpenBytes: 4 * 1024 ** 2,
    maxConcurrent: 2, requestTimeoutMs: 900000, maxRangeBytes: 262144, webDist: `${SOURCE}/build/web-ui` });
  stage = 'service_start';
  const { service, origin } = await startService(`${root}/service.json`);
  let rangeHash, ui;
  try {
    const { webdav } = await import(pathToFileURL(`${SDK}/package/dist/web-client/webdav.js`));
    const client = webdav(origin, () => ({ Authorization: `Bearer ${token}` }));
    const space = { id: 'synthetic-owner', webDavPath: 'spaces/synthetic-owner', driveType: 'personal' };
    stage = 'sdk_list';
    const listing = await client.listFiles(space);
    insist(listing.children.length === 1 && listing.children[0].name === 'private-file.bin');
    assert.deepEqual(await readdir(`${root}/w`), []);
    stage = 'sdk_full_get';
    const full = await client.getFileContents(space, { path: 'private-file.bin' }, { responseType: 'arraybuffer' });
    insist(full.response.status === 200 && full.headers.ETag === `"vp-${digest(content)}"`);
    assert.deepEqual(Buffer.from(full.body), content);
    stage = 'sdk_range_get';
    const partial = await client.getFileContents(space, { path: 'private-file.bin' }, {
      responseType: 'arraybuffer', headers: { Range: 'bytes=3-14', 'If-Match': full.headers.ETag },
    });
    insist(partial.response.status === 206);
    assert.deepEqual(Buffer.from(partial.body), content.subarray(3, 15));
    rangeHash = digest(Buffer.from(partial.body));
    stage = 'sdk_auth';
    const wrong = webdav(origin, () => ({ Authorization: 'Bearer incorrect-token' }));
    await assert.rejects(wrong.getFileContents(space, { path: 'private-file.bin' }, { responseType: 'arraybuffer' }),
      error => error.statusCode === 401);
    await assert.rejects(client.getFileContents(space, { path: 'private-file.bin' }, {
      responseType: 'arraybuffer', headers: { 'If-Match': '"stale-selection"' },
    }), error => error.statusCode === 412);
    stage = 'original_files_ui';
    ui = await originalUI(root, origin, token, content);
  } finally {
    try {
      const status = await stop(service);
      insist(status.code === 0 && status.signal === null && !service.overflow && !service.stderr);
      const lines = service.stdout.trim().split('\n').map(line => JSON.parse(line));
      insist(lines.length === 2 && lines[1].version === 1
        && lines[1].kind === 'volparossa-cloud-private-read' && lines[1].state === 'closed');
    } catch (error) { stage = 'service_close'; throw error; }
  }
  assert.deepEqual(await readdir(`${root}/w`), []);
  await absent(`${root}/bundle/file.pgp`);
  await absent(`${root}/source.private.json`);
  return { version: 1, kind: 'cloud-private-file-sdk-read', sdk_version: '8.0.0',
    sdk_archive_sha256: ARCHIVE_SHA, sdk_pins_sha256: provenance.pinsSha, sdk_receipt_sha256: provenance.receiptSha,
    catalog_verified_full_restore: true, catalog_encrypted: true, metadata_list_verified: true,
    full_get_bytes: content.length, full_get_sha256: digest(content), range_get_bytes: 12, range_get_sha256: rangeHash,
    actual_cloud_cli_service: true, actual_published_sdk: true, file_reconstructions: 5, ui,
    wrong_token_rejected: true, stale_etag_rejected: true, read_service_stopped_and_joined: true,
    temporary_plaintext_removed: true, original_source_fallback: false, local_ciphertext_fallback: false,
    original_files_ui_reads_proven: true, full_web_ui_proven: false, owner_secrets_exported: false };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const interrupted = () => { cancel.abort(); for (const state of children) state.child.kill('SIGTERM'); };
  for (const kind of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.on(kind, interrupted);
  const deadline = setTimeout(interrupted, 2300000);
  try { console.log(JSON.stringify(await main(process.argv[2]))); }
  catch {
    console.log(JSON.stringify({ success: false, kind: 'cloud-private-file-sdk-failure', stage, ui: uiFailure }));
    process.exitCode = 1;
  } finally {
    clearTimeout(deadline);
    try { await Promise.all([...children].map(stop)); }
    catch { cleanupFailed = true; process.exitCode = 1; }
    for (const kind of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.removeListener(kind, interrupted);
  }
  if (cleanupFailed) console.error('Cloud SDK child cleanup unconfirmed; private diagnostics withheld');
}
