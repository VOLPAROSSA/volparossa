// SPDX-License-Identifier: GPL-3.0-only
// Genuine pinned Node client -> core -> Qwen; no synthesized model responses.
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const assert = require('node:assert/strict');
const { setTimeout: sleep } = require('node:timers/promises');
const [root, socket, parentNetwork] = process.argv.slice(2);
let client, phase = 'guard';
function save(name, value) {
  const raw = JSON.stringify(value);
  assert(Buffer.byteLength(raw) <= 65536);
  fs.writeFileSync(path.join(root, name), raw, {flag:'wx', mode:0o600});
}
async function boundary(turn) {
  const deadline = Date.now() + 90000;
  while (!fs.existsSync(path.join(root, `continue-${turn}.json`))) {
    assert(Date.now() < deadline);
    await sleep(50);
  }
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(root, `continue-${turn}.json`))), {cleanup_observed:true});
}
async function submit(input, turn) {
  phase = `turn-${turn}-submit`;
  save(`input-${turn}.json`, input);
  const pending = client.submit(input);
  save(`submitted-${turn}.json`, {version:1, turn});
  phase = `turn-${turn}-result`;
  const result = await pending;
  // Original answers stay in this disposable root. The outer fixture may explicitly
  // export ONLY a bounded first assistant answer after matching its public input hash.
  save(`result-${turn}.json`, result);
  save(`settled-${turn}.json`, {version:1, turn});
  await boundary(turn);
  assert.equal(result.turn_complete, true);
  return result;
}
async function main() {
  assert.equal(root, '/home/vpci/private-conversation');
  assert.equal(process.getuid(), process.geteuid());
  assert.notEqual(process.getuid(), 0);
  assert.equal(process.version, 'v24.19.0');
  assert.notEqual(fs.readlinkSync('/proc/self/ns/net'), parentNetwork);
  assert(Object.keys(os.networkInterfaces()).every(name => name === 'lo'));
  const {PrivateConversation} = require(path.join(root, 'src/private-conversation.cjs'));
  client = new PrivateConversation(socket);
  phase = 'connect';
  const caps = await client.connect();
  assert.equal(caps.model_profile, 'qwen3-0.6b-v1');
  assert.equal(caps.native_tool_template, true);
  assert.equal(caps.quarantined, false);
  save('capabilities.json', caps);
  const conversation = {version:1, visibility:'private_local',
    instructions:'Use the offered read_file tool to read fixture.js before answering. ' +
      'After receiving its result, answer with only the literal string returned by testIdentifier. ' +
      'Do not guess the string and do not propose another tool call after reading the file.',
    history:[{type:'message', role:'user', text:'Read fixture.js. What string does testIdentifier return?'}],
    tools:[{type:'function', name:'read_file', namespace:'fixture',
      description:'Read the synthetic fixture.js source file. The only allowed path is fixture.js.',
      parameters:{type:'object', properties:{path:{type:'string', enum:['fixture.js']}},
        required:['path'], additionalProperties:false}}]};
  const first = await submit(conversation, 1);
  phase = 'tool-check';
  const call = first.output;
  assert.equal(call.type, 'function_call');
  assert.equal(call.name, 'read_file');
  assert.equal(call.namespace, 'fixture');
  assert.deepEqual(call.arguments, {path:'fixture.js'});
  assert.match(call.call_id, /^vp-[0-9a-f]{32}$/);
  // This fixture harness, not the daemon/model, authorizes and performs the sole tool.
  const target = path.join(root, 'fixture.js');
  const fd = fs.openSync(target, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  let content;
  try {
    const info = fs.fstatSync(fd);
    assert(info.isFile() && info.uid === process.getuid() && info.nlink === 1 &&
      (info.mode & 0o7777) === 0o600 && info.size <= 256);
    content = fs.readFileSync(fd, 'utf8');
  } finally { fs.closeSync(fd); }
  const match = /^function testIdentifier\(\) \{ return "(CANARY[0-9]{8})"; \}\n$/.exec(content);
  assert(match);
  assert(!JSON.stringify(conversation).includes(match[1]));
  save('tool.json', {version:1, authorized_fixture_read:true, tool_calls_executed:1,
    command_execution:false, canary_absent_from_first_input:true, correlated_call_id:call.call_id});
  conversation.history.push(call, {type:'tool_result', call_id:call.call_id, output:content});
  const second = await submit(conversation, 2);
  phase = 'answer-check';
  assert.equal(second.output.type, 'assistant');
  assert(second.output.text.includes(match[1]));
  save('client.json', {version:1, runtime_version:process.version, network_isolated:true,
    genuine_conversation_client:true, model_turns:2, model_selected_tool:true,
    correlated_tool_result_consumed:true, literal_canary_present:true, source_was_synthetic:true,
    codex_app_server_proven:false, code_edit_test_loop_proven:false, general_coding_quality_proven:false});
}
main().catch(error => {
  const known = new Set(['busy','invalid_request','handshake_required','cancelled','execution_failed',
    'cleanup_unconfirmed','socket_ownership','socket_changed','socket_unavailable','incompatible_capabilities',
    'invalid_response','invalid_conversation','request_bound','response_bound','socket_error','disconnected',
    'frame_timeout','handshake_timeout','not_connected']);
  try { save('failure.json', {version:1, phase, code:known.has(error.code) ? error.code : 'probe_failed'}); }
  catch { /* No raw prompt, output or exception export. */ }
  process.exitCode = 1;
}).finally(() => client?.close());
