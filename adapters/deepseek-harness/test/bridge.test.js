import assert from 'node:assert/strict'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { DeepSeekHarnessBridge, clampRecallTimeout } from '../bridge.js'
import { DurableOutbox } from '../outbox.js'

function session(id = 'session-1') {
  return { id, header: { cwd: '/work/repo' } }
}

function config(overrides = {}) {
  return {
    tenantId: 'acme',
    actorId: 'alice',
    agentId: 'deepseek-harness',
    profileId: 'default',
    model: 'deepseek',
    recallEnabled: true,
    captureEnabled: true,
    recallTimeoutMs: 1000,
    recallHardLimitMs: 3000,
    recallBudget: 2048,
    contextMaxChars: 6000,
    ...overrides,
  }
}

class MemoryOutbox {
  constructor() { this.items = new Map() }
  async init() {}
  async put(key, value) { this.items.set(key, value) }
  async list() { return [...this.items].map(([key, value]) => ({ key, value })) }
  async remove(key) { this.items.delete(key) }
}

test('recall runs only after downstream policy and appends untrusted CCOS context', async () => {
  const calls = []
  const client = {
    async start() {},
    async close() {},
    async callTool(name, args, meta) {
      calls.push({ name, args, meta })
      return { content: [{ type: 'text', text: 'accepted-memory' }] }
    },
  }
  const bridge = new DeepSeekHarnessBridge({ client, outbox: new MemoryOutbox(), config: config(), logger: { warn() {} } })
  await bridge.init()
  const s = session()
  const payload = { agent: { session: s }, turn: 2, step: 1, signal: new AbortController().signal }
  const decision = await bridge.beforeStep(payload, async () => ({
    kind: 'enter',
    messages: [{ id: 'u', role: 'user', source: { kind: 'user' }, content: [{ type: 'text', text: 'redacted accepted text' }] }],
  }))
  assert.equal(calls.length, 1)
  assert.equal(calls[0].args.text, 'redacted accepted text')
  assert.equal(decision.messages.length, 2)
  assert.match(decision.messages[1].content[0].text, /<ccos_context trust="untrusted-memory">/)
  assert.match(decision.messages[1].content[0].text, /accepted-memory/)
})

test('rejected turns never recall and recall failures fail open', async () => {
  let calls = 0
  const client = {
    async start() {}, async close() {},
    async callTool() { calls += 1; throw new Error('down') },
  }
  const bridge = new DeepSeekHarnessBridge({ client, outbox: new MemoryOutbox(), config: config(), logger: { warn() {} } })
  await bridge.init()
  const s = session()
  const reject = { kind: 'reject' }
  assert.deepEqual(await bridge.beforeStep({ agent: { session: s }, turn: 1, step: 1 }, async () => reject), reject)
  assert.equal(calls, 0)
  const accepted = { kind: 'enter', messages: [{ role: 'user', source: { kind: 'user' }, content: [{ type: 'text', text: 'hello' }] }] }
  assert.deepEqual(await bridge.beforeStep({ agent: { session: s }, turn: 2, step: 1 }, async () => accepted), accepted)
  assert.equal(calls, 1)
})

test('turn capture is persisted to outbox before send and retained on failure', async () => {
  const root = await mkdtemp(join(tmpdir(), 'ccos-dsh-bridge-'))
  const outbox = new DurableOutbox(root)
  let fail = true
  const calls = []
  const client = {
    async start() {}, async close() {},
    async callTool(name, args, meta) {
      calls.push({ name, args, meta })
      if (fail) throw new Error('offline')
      return { content: [{ type: 'text', text: 'ok' }] }
    },
  }
  const bridge = new DeepSeekHarnessBridge({ client, outbox, config: config({ recallEnabled: false }), logger: { warn() {} } })
  await bridge.init()
  const s = session('persist-me')
  bridge.onSessionEvent(s, { type: 'turn/start', time: 1, data: { turn: 9 } })
  bridge.onSessionEvent(s, { type: 'user/message', time: 2, data: { id: 'u', role: 'user', source: { kind: 'user' }, content: [{ type: 'text', text: 'remember this' }] } })
  bridge.onSessionEvent(s, { type: 'assistant/message', time: 3, data: { turn: 9, message: { content: [{ type: 'text', text: 'done' }] } } })
  bridge.onSessionEvent(s, { type: 'turn/end', time: 4, data: { turn: 9, reason: 'done' } })
  await bridge.flush()
  const retained = await outbox.list()
  assert.equal(retained.length, 1)
  assert.equal(retained[0].value.tool, 'memory.ingest')
  assert.match(retained[0].value.arguments.source, /remember this/)
  assert.match(retained[0].value.arguments.source, /done/)
  assert.equal(retained[0].value.meta.tenant_id, 'acme')

  fail = false
  bridge.init = async () => undefined
  // A second turn schedules another drain; the retained first item is delivered first.
  bridge.onSessionEvent(s, { type: 'turn/start', time: 5, data: { turn: 10 } })
  bridge.onSessionEvent(s, { type: 'user/message', time: 6, data: { id: 'u2', role: 'user', source: { kind: 'user' }, content: [{ type: 'text', text: 'second' }] } })
  bridge.onSessionEvent(s, { type: 'turn/end', time: 7, data: { turn: 10, reason: 'done' } })
  await bridge.flush()
  assert.deepEqual(await outbox.list(), [])
  assert.ok(calls.some((call) => call.args.source.includes('remember this')))
})

test('DeepSeek Harness rc.7 tool/result message is correlated and captured', async () => {
  const outbox = new MemoryOutbox()
  const client = {
    async start() {}, async close() {},
    async callTool() { throw new Error('keep capture in outbox') },
  }
  const bridge = new DeepSeekHarnessBridge({ client, outbox, config: config({ recallEnabled: false }), logger: { warn() {} } })
  await bridge.init()
  const s = session('rc7-tool-result')
  bridge.onSessionEvent(s, { type: 'turn/start', time: 1, data: { turn: 11 } })
  bridge.onSessionEvent(s, { type: 'user/message', time: 2, data: { id: 'u', role: 'user', source: { kind: 'user' }, content: [{ type: 'text', text: 'run tool' }] } })
  bridge.onSessionEvent(s, { type: 'tool/call', time: 3, data: { turn: 11, step: 1, callId: 'call-7', name: 'example_tool', arguments: '{"x":1}' } })
  bridge.onSessionEvent(s, {
    type: 'tool/result',
    time: 4,
    data: {
      turn: 11,
      step: 1,
      message: {
        id: 'tool-message-7',
        role: 'user',
        source: { kind: 'tool', callId: 'call-7' },
        content: [{
          type: 'tool-result',
          toolCallId: 'call-7',
          content: [{ type: 'text', text: 'rc7 tool output' }],
          isError: true,
        }],
      },
      error: { name: 'ExampleError', code: 'EXAMPLE' },
    },
  })
  bridge.onSessionEvent(s, { type: 'turn/end', time: 5, data: { turn: 11, reason: { kind: 'completed' } } })
  await bridge.flush()

  const [capture] = await outbox.list()
  assert.ok(capture)
  assert.match(capture.value.arguments.source, /example_tool \(call-7\)/)
  assert.match(capture.value.arguments.source, /rc7 tool output/)
  assert.match(capture.value.arguments.source, /failed: true/)
})

test('recall timeout is bounded by the hard 3s product ceiling', () => {
  assert.equal(clampRecallTimeout(500, 3000), 500)
  assert.equal(clampRecallTimeout(8000, 9000), 3000)
  assert.equal(clampRecallTimeout(20, 3000), 100)
})
