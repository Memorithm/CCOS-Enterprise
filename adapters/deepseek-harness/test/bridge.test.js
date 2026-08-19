import assert from 'node:assert/strict'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { buildEpisode, DeepSeekHarnessBridge, EPISODE_SCHEMA, clampRecallTimeout } from '../bridge.js'
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

test('L1 episode derives only deterministic evidence and reflection signals', () => {
  const episode = buildEpisode({
    sessionId: 'episode-session',
    turn: 7,
    startedAt: 1000,
    endedAt: 1600,
    assistantText: ['first', 'second'],
    toolCalls: [
      { name: 'example_tool', callId: 'call-1', result: 'bad-1', failed: true },
      { name: 'example_tool', callId: 'call-2', result: 'bad-2', failed: true },
      { name: 'other_tool', callId: 'call-3', result: 'ok', failed: false },
      { name: 'pending_tool', callId: 'call-4' },
    ],
    endReason: { kind: 'completed' },
  })

  assert.equal(episode.schema, EPISODE_SCHEMA)
  assert.equal(episode.evidence_only, true)
  assert.equal(episode.observed_outcome.reason_kind, 'completed')
  assert.equal(episode.reward_proxy.value, 1)
  assert.equal(episode.reward_proxy.heuristic, 'dsh_turn_end_reason_v1')
  assert.equal(episode.timing.duration_ms, 600)
  assert.equal(episode.evidence.assistant_messages, 2)
  assert.equal(episode.evidence.tool_calls, 4)
  assert.equal(episode.evidence.tool_results, 3)
  assert.equal(episode.evidence.tool_failures, 2)
  assert.equal(episode.evidence.unresolved_tool_calls, 1)
  assert.deepEqual(episode.evidence.repeated_tool_failures, [{
    name: 'example_tool',
    count: 2,
    call_ids: ['call-1', 'call-2'],
  }])
  assert.deepEqual(episode.reflection_signals, [
    'tool_failure_observed',
    'repeated_tool_failure',
    'unresolved_tool_call',
    'completed_after_tool_failure',
  ])
})

test('L1 keeps non-success terminal reasons explicit instead of inventing success', () => {
  const aborted = buildEpisode({
    sessionId: 'episode-session',
    turn: 8,
    assistantText: [],
    toolCalls: [],
    endReason: { kind: 'aborted', reason: { kind: 'user' } },
  })
  const capped = buildEpisode({
    sessionId: 'episode-session',
    turn: 9,
    assistantText: [],
    toolCalls: [],
    endReason: { kind: 'max-tokens' },
  })
  const unknown = buildEpisode({
    sessionId: 'episode-session',
    turn: 10,
    assistantText: [],
    toolCalls: [],
    endReason: 'legacy-untyped-reason',
  })

  assert.equal(aborted.observed_outcome.reason_kind, 'aborted')
  assert.equal(aborted.reward_proxy.value, 0)
  assert.deepEqual(aborted.reflection_signals, ['turn_aborted'])
  assert.equal(capped.observed_outcome.reason_kind, 'max-tokens')
  assert.equal(capped.reward_proxy.value, 0)
  assert.deepEqual(capped.reflection_signals, ['turn_max_tokens'])
  assert.equal(unknown.observed_outcome.reason_kind, 'unknown')
  assert.equal(unknown.reward_proxy.value, 0)
})

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
  bridge.onSessionEvent(s, { type: 'turn/end', time: 4, data: { turn: 9, reason: { kind: 'completed' } } })
  await bridge.flush()
  const retained = await outbox.list()
  assert.equal(retained.length, 1)
  assert.equal(retained[0].value.tool, 'memory.ingest')
  assert.match(retained[0].value.arguments.source, /remember this/)
  assert.match(retained[0].value.arguments.source, /done/)
  assert.match(retained[0].value.arguments.source, /CCOS Episode \(evidence-only\)/)
  assert.match(retained[0].value.arguments.source, /"schema": "ccos\.dsh\.episode\.v1"/)
  assert.match(retained[0].value.arguments.source, /"reason_kind": "completed"/)
  assert.equal(retained[0].value.meta.tenant_id, 'acme')
  assert.deepEqual(calls.map((call) => call.name), ['memory.ingest'])

  fail = false
  bridge.init = async () => undefined
  // A second turn schedules another drain; the retained first item is delivered first.
  bridge.onSessionEvent(s, { type: 'turn/start', time: 5, data: { turn: 10 } })
  bridge.onSessionEvent(s, { type: 'user/message', time: 6, data: { id: 'u2', role: 'user', source: { kind: 'user' }, content: [{ type: 'text', text: 'second' }] } })
  bridge.onSessionEvent(s, { type: 'turn/end', time: 7, data: { turn: 10, reason: { kind: 'completed' } } })
  await bridge.flush()
  assert.deepEqual(await outbox.list(), [])
  assert.ok(calls.some((call) => call.args.source.includes('remember this')))
})

test('DeepSeek Harness rc.7 tool/result message is correlated and captured with L1 evidence', async () => {
  const outbox = new MemoryOutbox()
  const calls = []
  const client = {
    async start() {}, async close() {},
    async callTool(name, args, meta) {
      calls.push({ name, args, meta })
      throw new Error('keep capture in outbox')
    },
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
  assert.match(capture.value.arguments.source, /"tool_failures": 1/)
  assert.match(capture.value.arguments.source, /"completed_after_tool_failure"/)
  assert.deepEqual(calls.map((call) => call.name), ['memory.ingest'])
})

test('recall timeout is bounded by the hard 3s product ceiling', () => {
  assert.equal(clampRecallTimeout(500, 3000), 500)
  assert.equal(clampRecallTimeout(8000, 9000), 3000)
  assert.equal(clampRecallTimeout(20, 3000), 100)
})
