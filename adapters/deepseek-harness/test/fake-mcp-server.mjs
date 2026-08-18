import { appendFileSync } from 'node:fs'
import { createInterface } from 'node:readline'

const log = process.env.FAKE_MCP_LOG
const rl = createInterface({ input: process.stdin, crlfDelay: Infinity })
for await (const line of rl) {
  const message = JSON.parse(line)
  if (!Object.prototype.hasOwnProperty.call(message, 'id')) continue
  let result
  if (message.method === 'initialize') {
    result = { protocolVersion: '2024-11-05', capabilities: {}, serverInfo: { name: 'fake', version: '1' } }
  } else if (message.method === 'tools/call') {
    if (log) appendFileSync(log, `${JSON.stringify(message.params)}\n`)
    const tool = message.params?.name
    result = {
      content: [{ type: 'text', text: tool === 'memory.recall' ? 'remembered fact' : 'stored' }],
      isError: false,
    }
  } else {
    result = {}
  }
  process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id: message.id, result })}\n`)
}
