// SPDX-License-Identifier: GPL-3.0-only
// Disposable synthetic-code probe. Uses the unmodified, separately pinned client.
'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const assert = require('node:assert/strict');

const [root, socket, inputPath, parentNetwork] = process.argv.slice(2);
let client;
let phase = 'guard';
function save(name, value) {
  const data = JSON.stringify(value);
  assert(Buffer.byteLength(data) <= 65536);
  fs.writeFileSync(path.join(root, name), data, { flag: 'wx', mode: 0o600 });
}
async function main() {
  assert.equal(root, '/home/vpci/private-code');
  assert.equal(process.getuid(), process.geteuid());
  assert.notEqual(process.getuid(), 0);
  assert.equal(process.version, 'v24.19.0');
  assert.notEqual(fs.readlinkSync('/proc/self/ns/net'), parentNetwork);
  assert(Object.keys(os.networkInterfaces()).every(name => name === 'lo'));
  const { PrivateCompute } = require(path.join(root, 'src/private-compute.cjs'));
  const info = fs.lstatSync(inputPath);
  assert(info.isFile() && info.uid === process.getuid() && (info.mode & 0o7777) === 0o600 && info.size <= 65536);
  const input = JSON.parse(fs.readFileSync(inputPath, 'utf8'));
  assert.equal(input.version, 1);
  assert.equal(input.visibility, 'private_local');
  assert.equal(input.question, 'What string does testIdentifier return? Answer with only the string.');
  assert.match(input.context, /^function testIdentifier\(\) \{ return "CANARY[0-9]{8}"; \}$/);
  phase = 'connect';
  client = new PrivateCompute(socket);
  const capabilities = await client.connect();
  save('capabilities.json', capabilities);
  phase = 'submit';
  const pending = client.ask({ question: input.question, context: input.context });
  save('submitted.json', { version: 1, event: 'client_submit_called' });
  phase = 'result';
  const answer = await pending;
  // Kept only within the disposable private root; no raw answer is exported.
  save('answer.json', answer);
  save('client.json', { version: 1, runtime_version: process.version, network_isolated: true,
    private_client_used: true, result_received: true, source_was_synthetic: true });
}
main().catch(error => {
  const known = new Set(['busy', 'invalid_request', 'handshake_required', 'no_such_task',
    'cancelled', 'execution_failed', 'cleanup_unconfirmed', 'socket_ownership', 'socket_changed',
    'socket_unavailable', 'incompatible_capabilities', 'invalid_response', 'invalid_text',
    'response_bound', 'socket_error', 'disconnected', 'frame_timeout', 'handshake_timeout']);
  try { save('failure.json', { version: 1, phase,
    code: known.has(error.code) ? error.code : 'probe_failed' }); } catch { /* No raw exception output. */ }
  process.exitCode = 1;
}).finally(() => client?.close());
