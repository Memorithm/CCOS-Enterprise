import assert from 'node:assert/strict'
import test from 'node:test'

import {
  GOVERNED_READ_TOOLS,
  governedToolResultMaxChars,
  governedToolTimeoutMs,
  registerGovernedTools,
} from '../tools.js'

function liveSpecs() {
  return GOVERNED_READ_TOOLS.map((mapping, index) => ({
    name: mapping.enterprise,
    description: `live description ${index}`,
    inputSchema: {
      type: 'object',
      properties: { [`field_${index}`]: { type: 'string' } },
      additionalProperties: false,
    },
  }))
}

function registry(options = {}) {
  const definitions = []
  const disposed = []
  const ctx = {
    tools: {
      register(definition) {
        if (options.failAt !== undefined && definitions.length === options.failAt) {
          throw new Error('registration conflict')
        }
        definitions.push(definition)
        return () => disposed.push(definition.name)
      },
    },
  }
  return { ctx, definitions, disposed }
}

function config(overrides = {}) {
  return {
    recallHardLimitMs: 3000,
    toolRecallTimeoutMs: 3000,
    toolTimeoutMs: 60_000,
    toolResultMaxChars: 6000,
    ...overrides,
  }
}

test('native surface is the exact governed read-only allowlist', () => {
  assert.deepEqual(
    GOVERNED_READ_TOOLS.map((mapping) => [mapping.enterprise, mapping.dsh]),
    [
      ['memory.recall', 'ccos_recall'],
      ['memory.recall_what_if', 'ccos_recall_what_if'],
      ['memory.get', 'ccos_get'],
      ['memory.stats', 'ccos_stats'],
      ['memory.timeline', 'ccos_timeline'],
      ['memory.verify', 'ccos_verify'],
      ['context.retrieve', 'ccos_context_retrieve'],
      ['ccos.causal_blame', 'ccos_causal_blame'],
      ['ccos.causal_flash', 'ccos_causal_flash'],
      ['ccos.drift_cause', 'ccos_drift_cause'],
      ['ccos.retrodict_belief', 'ccos_retrodict_belief'],
    ],
  )
  const capabilities = GOVERNED_READ_TOOLS.map((mapping) => mapping.enterprise)
  for (const forbidden of [
    'memory.ingest',
    'memory.page_fault',
    'memory.sync',
    'ccos.causal_intervene',
    'ccos.signal_failure',
    'shell.exec',
    'code.execute',
    'repository.modify',
    'patch.apply',
    'self.modify',
  ]) {
    assert.equal(capabilities.includes(forbidden), false, `${forbidden} must not be model-visible`)
  }
})

test('registration consumes live Enterprise schemas and keeps tools exclusive', async () => {
  const specs = liveSpecs()
  const client = {
    async request(method) {
      assert.equal(method, 'tools/list')
      return { tools: specs }
    },
  }
  const { ctx, definitions } = registry()
  const dispose = await registerGovernedTools(ctx, {
    client,
    bridge: { executionIdentity() { return {} } },
    config: config(),
  })

  assert.equal(definitions.length, GOVERNED_READ_TOOLS.length)
  for (let index = 0; index < definitions.length; index += 1) {
    const definition = definitions[index]
    assert.equal(definition.name, GOVERNED_READ_TOOLS[index].dsh)
    assert.deepEqual(definition.parameters, specs[index].inputSchema)
    assert.equal(definition.isConcurrencySafe, undefined, 'CCOS reads stay exclusive for journal ordering')
  }
  dispose()
})

test('tool execution uses canonical Enterprise name and DSH correlation metadata', async () => {
  const calls = []
  const client = {
    async request() { return { tools: liveSpecs() } },
    async callTool(name, args, meta, options) {
      calls.push({ name, args, meta, options })
      return { content: [{ type: 'text', text: 'ok' }], structuredContent: { ok: true } }
    },
  }
  const identity = {
    tenant_id: 'acme',
    actor_id: 'alice',
    dsh_session_id: 'session-1',
    turn_id: '8',
    step_id: '2',
    tool_call_id: 'call-9',
  }
  const bridge = { executionIdentity() { return identity } }
  const { ctx, definitions } = registry()
  await registerGovernedTools(ctx, { client, bridge, config: config() })
  const recall = definitions.find((definition) => definition.name === 'ccos_recall')
  const signal = new AbortController().signal
  const args = { strategy: 'semantic', text: 'alpha', budget: 777 }
  const result = await recall.execute(args, { callId: 'call-9', signal, agent: { session: { id: 'session-1' } } })

  assert.deepEqual(result.structuredContent, { ok: true })
  assert.equal(calls.length, 1)
  assert.equal(calls[0].name, 'memory.recall')
  assert.deepEqual(calls[0].args, args)
  assert.equal(calls[0].meta, identity)
  assert.equal(calls[0].options.signal, signal)
  assert.equal(calls[0].options.timeoutMs, 3000)
})

test('non-recall reads have a finite timeout and bounded model projection', async () => {
  const client = {
    async request() { return { tools: liveSpecs() } },
    async callTool() { return { content: [{ type: 'text', text: 'x'.repeat(1000) }] } },
  }
  const { ctx, definitions } = registry()
  await registerGovernedTools(ctx, {
    client,
    bridge: { executionIdentity() { return { tenant_id: 'acme' } } },
    config: config({ toolTimeoutMs: 12_345, toolResultMaxChars: 300 }),
  })
  const stats = definitions.find((definition) => definition.name === 'ccos_stats')
  const value = await stats.execute({}, { signal: new AbortController().signal, agent: { session: { id: 's' } } })
  assert.equal(stats.timeoutMs, 12_345)
  const rendered = stats.output.render({}, value)[0].text
  assert.ok(rendered.length < 400)
  assert.match(rendered, /CCOS tool result truncated/)
})

test('timeouts and result budgets are bounded even for hostile configuration', () => {
  assert.equal(governedToolTimeoutMs('memory.recall', config({ toolRecallTimeoutMs: 90_000 })), 3000)
  assert.equal(governedToolTimeoutMs('memory.stats', config({ toolTimeoutMs: 999_999 })), 300_000)
  assert.equal(governedToolTimeoutMs('memory.stats', config({ toolTimeoutMs: Number.NaN })), 60_000)
  assert.equal(governedToolResultMaxChars(config({ toolResultMaxChars: 1 })), 256)
  assert.equal(governedToolResultMaxChars(config({ toolResultMaxChars: 999_999 })), 20_000)
})

test('catalogue drift or registration conflicts roll back partial tool generations', async () => {
  const incomplete = liveSpecs().slice(0, 1)
  const first = registry()
  await assert.rejects(
    () => registerGovernedTools(first.ctx, {
      client: { async request() { return { tools: incomplete } } },
      bridge: { executionIdentity() { return {} } },
      config: config(),
    }),
    /did not advertise memory\.recall_what_if/,
  )
  assert.deepEqual(first.disposed, ['ccos_recall'])

  const second = registry({ failAt: 2 })
  await assert.rejects(
    () => registerGovernedTools(second.ctx, {
      client: { async request() { return { tools: liveSpecs() } } },
      bridge: { executionIdentity() { return {} } },
      config: config(),
    }),
    /registration conflict/,
  )
  assert.deepEqual(second.disposed.sort(), ['ccos_recall', 'ccos_recall_what_if'].sort())
})

test('MCP tool failures propagate and are never rendered as successful evidence', async () => {
  const client = {
    async request() { return { tools: liveSpecs() } },
    async callTool() {
      const error = new Error('permission denied')
      error.code = 'MCP_TOOL_ERROR'
      throw error
    },
  }
  const { ctx, definitions } = registry()
  await registerGovernedTools(ctx, {
    client,
    bridge: { executionIdentity() { return { tenant_id: 'acme' } } },
    config: config(),
  })
  const verify = definitions.find((definition) => definition.name === 'ccos_verify')
  await assert.rejects(() => verify.execute({}, { agent: { session: { id: 's' } } }), /permission denied/)
})
