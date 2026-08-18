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
    const result = await client.callTool('memory.recall', { text: 'hello' }, { tenant_id: 'acme', actor_id: 'alice' })
    assert.equal(textFromMcpToolResult(result), 'remembered fact')
  } finally {
    await client.close()
  }
  const [call] = (await readFile(log, 'utf8')).trim().split('\n').map(JSON.parse)
  assert.equal(call.name, 'memory.recall')
  assert.equal(call.arguments.text, 'hello')
  assert.equal(call._meta.ccos.tenant_id, 'acme')
  assert.equal(call._meta.ccos.actor_id, 'alice')
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
