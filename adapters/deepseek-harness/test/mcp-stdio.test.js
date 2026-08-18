import assert from 'node:assert/strict'
import { mkdtemp, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

import { StdioMcpClient, textFromMcpToolResult } from '../mcp-stdio.js'

const here = dirname(fileURLToPath(import.meta.url))

test('stdio client initializes and sends CCOS identity in MCP _meta', async () => {
  const root = await mkdtemp(join(tmpdir(), 'ccos-dsh-mcp-'))
  const log = join(root, 'calls.jsonl')
  const client = new StdioMcpClient({
    command: process.execPath,
    args: [join(here, 'fake-mcp-server.mjs')],
    env: { FAKE_MCP_LOG: log },
    logger: { warn() {} },
  })
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
