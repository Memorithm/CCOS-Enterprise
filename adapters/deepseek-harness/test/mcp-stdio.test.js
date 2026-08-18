import assert from 'node:assert/strict'
import { mkdtemp, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

import { StdioMcpClient, textFromMcpToolResult } from '../mcp-stdio.js'

const here = dirname(fileURLToPath(import.meta.url))

function clientFor(log) {
  return new StdioMcpClient({
    command: process.execPath,
    args: [join(here, 'fake-mcp-server.mjs')],
    env: log ? { FAKE_MCP_LOG: log } : {},
    logger: { warn() {} },
  })
}

test('stdio client initializes and sends CCOS identity in MCP _meta', async () => {
  const root = await mkdtemp(join(tmpdir(), 'ccos-dsh-mcp-'))
  const log = join(root, 'calls.jsonl')
  const client = clientFor(log)
  try {
    await client.start()
    const result = await client.callTool('memory.recall', { text: 'hello' }, {
      tenant_id: 'acme',
      actor_id: 'alice',
      request_id: 'stable-request',
    })
    assert.equal(textFromMcpToolResult(result), 'remembered fact')
  } finally {
    await client.close()
  }
  const [call] = (await readFile(log, 'utf8')).trim().split('\n').map(JSON.parse)
  assert.equal(call.name, 'memory.recall')
  assert.equal(call.arguments.text, 'hello')
  assert.equal(call._meta.ccos.tenant_id, 'acme')
  assert.equal(call._meta.ccos.actor_id, 'alice')
  assert.equal(call._meta.ccos.request_id, 'stable-request')
  assert.match(call._meta.ccos.execution_attempt_id, /^[0-9a-f-]{36}$/)
})

test('physical retries keep request_id but receive distinct execution attempt ids', async () => {
  const root = await mkdtemp(join(tmpdir(), 'ccos-dsh-attempt-'))
  const log = join(root, 'calls.jsonl')
  const client = clientFor(log)
  const meta = {
    tenant_id: 'acme',
    actor_id: 'alice',
    request_id: 'outbox-stable-id',
  }
  try {
    await client.start()
    await client.callTool('memory.recall', { text: 'first' }, meta)
    await client.callTool('memory.recall', { text: 'second' }, meta)
  } finally {
    await client.close()
  }
  const calls = (await readFile(log, 'utf8')).trim().split('\n').map(JSON.parse)
  assert.equal(calls.length, 2)
  assert.equal(calls[0]._meta.ccos.request_id, 'outbox-stable-id')
  assert.equal(calls[1]._meta.ccos.request_id, 'outbox-stable-id')
  assert.notEqual(
    calls[0]._meta.ccos.execution_attempt_id,
    calls[1]._meta.ccos.execution_attempt_id,
  )
})

test('MCP tool-level isError is a failed operation, not an acknowledgement', async () => {
  const client = clientFor()
  try {
    await client.start()
    await assert.rejects(
      client.callTool('memory.fail', {}, { tenant_id: 'acme', actor_id: 'alice' }),
      (error) => error?.code === 'MCP_TOOL_ERROR' && /governed refusal/.test(error.message),
    )
  } finally {
    await client.close()
  }
})
