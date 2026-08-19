import assert from 'node:assert/strict'
import {
  createPrivateKey,
  createPublicKey,
  randomUUID,
  sign,
} from 'node:crypto'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { StdioMcpClient } from '../mcp-stdio.js'

const serverPath = process.env.CCOS_REAL_MCP_SERVER
const PKCS8_ED25519_SEED_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')

function identityFixture() {
  const seed = Buffer.alloc(32, 0x5a)
  const privateKey = createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_SEED_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  })
  const publicDer = createPublicKey(privateKey).export({ format: 'der', type: 'spki' })
  const publicKeyHex = publicDer.subarray(-32).toString('hex')
  const now = Math.floor(Date.now() / 1000)
  const claims = {
    version: 1,
    jti: `e2e-${randomUUID()}`,
    org: 'memorithm',
    actor: 'alice',
    audience: 'ccos-dsh-e2e',
    issued_at: now - 1,
    expires_at: now + 600,
    not_before: null,
  }
  const payload = Buffer.from(JSON.stringify(claims)).toString('base64url')
  const signingInput = `ccosid1.ed25519.e2e-key.${payload}`
  const signature = sign(null, Buffer.from(signingInput), privateKey).toString('base64url')
  return {
    publicKeyHex,
    token: `${signingInput}.${signature}`,
  }
}

function ccosMeta(requestId, actor = 'alice') {
    return {
      tenant_id: 'acme',
      actor_id: actor,
      agent_id: 'deepseek-harness-agent',
      host: 'deepseek-harness',
      dsh_profile: 'e2e',
      request_id: requestId,
      model: 'deepseek-harness',
      dsh_session_id: 'real-rust-e2e-session',
      turn_id: '1',
      step_id: '1',
      trace_id: '0123456789abcdef0123456789abcdef',
    }
  }

function clientFor(stateDir, identity) {
  return new StdioMcpClient({
    command: serverPath,
    env: {
      CCOS_ENTERPRISE_AUDIENCE: 'ccos-dsh-e2e',
      CCOS_ENTERPRISE_ISSUER_KID: 'e2e-key',
      CCOS_ENTERPRISE_ISSUER_PUBLIC_KEY_HEX: identity.publicKeyHex,
      CCOS_ENTERPRISE_IDENTITY_TOKEN: identity.token,
      CCOS_ENTERPRISE_TENANT: 'acme',
      CCOS_ENTERPRISE_MODEL: 'deepseek-harness',
      CCOS_ENTERPRISE_TOKEN_BUDGET: '1000',
      CCOS_ENTERPRISE_CALL_COST_TOKENS: '1',
      CCOS_ENTERPRISE_STATE_DIR: stateDir,
    },
    logger: { warn() {} },
    requestTimeoutMs: 30_000,
  })
}

test(
  'DSH stdio client reaches the real governed Rust server and durable Core state',
  { skip: !serverPath },
  async () => {
    const root = await mkdtemp(join(tmpdir(), 'ccos-dsh-real-rust-'))
    const identity = identityFixture()
    const requestId = 'real-rust-ingest'

    try {
      const first = clientFor(root, identity)
      try {
        await first.start()
        const catalogue = await first.request('tools/list', {})
        const names = new Set(catalogue.tools.map((tool) => tool.name))
        assert.ok(names.has('memory.ingest'))
        assert.ok(names.has('memory.recall'))
        assert.ok(names.has('memory.stats'))

        const ingested = await first.callTool(
          'memory.ingest',
          { uri: 'dsh/e2e.md', source: 'DeepSeek Harness real Rust transport proof' },
          ccosMeta(requestId),
        )
        assert.notEqual(ingested?.isError, true)
      } finally {
        await first.close()
      }

      // A fresh child process reloads the durable Enterprise ledger. Reusing
      // the stable request_id must suppress the effect even though the stdio
      // client creates a fresh physical execution_attempt_id.
      const restarted = clientFor(root, identity)
      try {
        await restarted.start()
        const replay = await restarted.callTool(
          'memory.ingest',
          { uri: 'dsh/e2e.md', source: 'must not execute twice' },
          ccosMeta(requestId),
        )
        assert.equal(replay.structuredContent?.replayed, true)

        await assert.rejects(
          restarted.callTool('memory.stats', {}, ccosMeta('forged-actor', 'mallory')),
          (error) => error?.code === -32001 && /not authenticated/.test(error.message),
        )
      } finally {
        await restarted.close()
      }
    const correlationText = await readFile(
      join(root, '.execution', 'acme', 'correlation.jsonl'),
      'utf8',
    )
    const correlation = correlationText
      .trim()
      .split('\n')
      .filter(Boolean)
      .map((line) => JSON.parse(line).event)
      .filter((event) => event.type === 'host_call_correlated')
    assert.equal(
      correlation.length,
      2,
      'forged actor must not create an accepted host-correlation row',
    )
    assert.equal(correlation[0].request_id, requestId)
    assert.equal(correlation[1].request_id, requestId)
    assert.notEqual(correlation[0].call_id, correlation[1].call_id)
    assert.equal(correlation[0].host, 'deepseek-harness')
    assert.equal(correlation[0].host_session_id, 'real-rust-e2e-session')
    assert.equal(correlation[0].agent_id, 'deepseek-harness-agent')
    assert.equal(correlation[0].profile, 'e2e')
    assert.equal(correlation[0].trace_id, '0123456789abcdef0123456789abcdef')

    } finally {
      await rm(root, { recursive: true, force: true })
    }
  },
)
