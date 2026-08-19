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

function ccosMeta(requestId, actor = 'alice', turn = '1') {
  return {
    tenant_id: 'acme',
    actor_id: actor,
    agent_id: 'deepseek-harness-agent',
    host: 'deepseek-harness',
    dsh_profile: 'e2e',
    request_id: requestId,
    model: 'deepseek-harness',
    dsh_session_id: 'real-rust-e2e-session',
    turn_id: turn,
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

function l1Capture({ secret, tool = 'memory.recall', turn = 2 }) {
  const episode = {
    schema: 'ccos.dsh.episode.v1',
    evidence_only: true,
    host: 'deepseek-harness',
    session_id: 'real-rust-e2e-session',
    turn,
    timing: {
      started_at_ms: 100,
      ended_at_ms: 120,
      duration_ms: 20,
    },
    observed_outcome: {
      reason_kind: 'completed',
    },
    reward_proxy: {
      value: 1,
      range: [-1, 1],
      heuristic: 'dsh_turn_end_reason_v1',
    },
    evidence: {
      assistant_messages: 1,
      tool_calls: 1,
      tool_results: 1,
      tool_failures: 0,
      unresolved_tool_calls: 0,
      failed_tools: [],
      repeated_tool_failures: [],
    },
    reflection_signals: [],
  }
  return [
    `# DeepSeek Harness turn ${turn}`,
    '',
    'session: real-rust-e2e-session',
    '',
    '## User',
    secret,
    '',
    '## Assistant',
    'done',
    '',
    '## Tools',
    `- ${tool} (skill-call-1)`,
    `  input: ${JSON.stringify({ secret })}`,
    '  output: "ok"',
    '',
    'turn_end_reason: {"kind":"completed"}',
    '',
    '## CCOS Episode (evidence-only)',
    '```json',
    JSON.stringify(episode, null, 2),
    '```',
  ].join('\n')
}

function observationalTrialCapture(skillRead, { secret, turn }) {
  const episode = {
    schema: 'ccos.dsh.episode.v1',
    evidence_only: true,
    host: 'deepseek-harness',
    session_id: 'real-rust-e2e-session',
    turn,
    observed_outcome: { reason_kind: 'completed' },
    evidence: {
      tool_calls: 2,
      tool_failures: 0,
      unresolved_tool_calls: 0,
    },
  }
  return [
    `# DeepSeek Harness turn ${turn}`,
    '',
    'session: real-rust-e2e-session',
    '',
    '## User',
    secret,
    '',
    '## Assistant',
    'done',
    '',
    '## Tools',
    '- ccos_skills (trial-read)',
    '  input: {"limit":4}',
    `  output: ${JSON.stringify(skillRead.content)}`,
    '- memory.recall (trial-use)',
    '  input: {}',
    '  output: "ok"',
    '',
    'turn_end_reason: {"kind":"completed"}',
    '',
    '## CCOS Episode (evidence-only)',
    '```json',
    JSON.stringify(episode, null, 2),
    '```',
  ].join('\n')
}

function malformedL1Capture() {
  return [
    '# DeepSeek Harness turn 1',
    '',
    'session: real-rust-e2e-session',
    '',
    '## User',
    'malformed evidence must not wedge later ingestion',
    '',
    '## CCOS Episode (evidence-only)',
    '```json',
    '{ definitely-not-valid-json',
    '```',
  ].join('\n')
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

test(
  'successful L1 ingest crystallizes once without retaining raw content',
  { skip: !serverPath },
  async () => {
    const root = await mkdtemp(join(tmpdir(), 'ccos-dsh-skill-e2e-'))
    const identity = identityFixture()
    const requestId = 'real-rust-skill-ingest'
    const secret = 'RAW-SKILL-SECRET-MUST-NEVER-PERSIST'
    const source = l1Capture({ secret, turn: 2 })

    try {
      const first = clientFor(root, identity)
      try {
        await first.start()

        // Core already accepted this memory document, so a permanently
        // malformed L1 projection must be quarantined/cleared rather than
        // wedging the tenant's future automatic capture queue.
        const malformed = await first.callTool(
          'memory.ingest',
          { uri: 'dsh/malformed-l1.md', source: malformedL1Capture() },
          ccosMeta('malformed-l1-ingest', 'alice', '1'),
        )
        assert.notEqual(malformed?.isError, true)

        // This second ingest proves the malformed receipt was durably cleared.
        // If it remained pending, the server would reject this different
        // request_id before Core execution.
        const ingested = await first.callTool(
          'memory.ingest',
          { uri: 'dsh/skill-e2e.md', source },
          ccosMeta(requestId, 'alice', '2'),
        )
        assert.notEqual(ingested?.isError, true)
      } finally {
        await first.close()
      }

      const skillsPath = join(root, '.skills', 'acme', 'skills.json')
      const firstDisk = await readFile(skillsPath, 'utf8')
      assert.equal(firstDisk.includes(secret), false)
      assert.equal(firstDisk.includes('malformed evidence must not wedge later ingestion'), false)
      const firstSnapshot = JSON.parse(firstDisk)
      const firstSkills = Object.values(firstSnapshot.skills)
      assert.equal(firstSkills.length, 1)
      assert.deepEqual(firstSkills[0].tool_sequence, ['memory.recall'])
      assert.equal(firstSkills[0].status, 'candidate')
      assert.equal(firstSkills[0].support, 1)
      assert.equal(firstSkills[0].trials_attempted, 1)
      assert.equal(firstSkills[0].trials_passed, 1)

      const restarted = clientFor(root, identity)
      try {
        await restarted.start()
        const changedSource = l1Capture({
          secret: 'ATTACKER-SUBSTITUTED-REPLAY-CONTENT',
          tool: 'memory.timeline',
          turn: 99,
        })
        const replay = await restarted.callTool(
          'memory.ingest',
          { uri: 'dsh/skill-e2e.md', source: changedSource },
          ccosMeta(requestId, 'alice', '99'),
        )
        assert.equal(replay.structuredContent?.replayed, true)
      } finally {
        await restarted.close()
      }

      const replayDisk = await readFile(skillsPath, 'utf8')
      assert.equal(replayDisk.includes('ATTACKER-SUBSTITUTED-REPLAY-CONTENT'), false)
      const replaySnapshot = JSON.parse(replayDisk)
      const replaySkills = Object.values(replaySnapshot.skills)
      assert.equal(replaySkills.length, 1)
      assert.deepEqual(replaySkills[0].tool_sequence, ['memory.recall'])
      assert.equal(replaySkills[0].support, 1)
      assert.equal(replaySkills[0].trials_attempted, 1)
      assert.equal(replaySkills[0].trials_passed, 1)
    } finally {
      await rm(root, { recursive: true, force: true })
    }
  },
)

test(
  'governed skill read becomes one private observational trial through real Rust projection',
  { skip: !serverPath },
  async () => {
    const root = await mkdtemp(join(tmpdir(), 'ccos-dsh-skill-trial-e2e-'))
    const identity = identityFixture()
    const trialRequestId = 'real-rust-observational-trial'
    const trialSecret = 'RAW-TRIAL-CONTENT-MUST-NEVER-PERSIST'

    try {
      const client = clientFor(root, identity)
      try {
        await client.start()
        for (const turn of [10, 11, 12]) {
          const ingested = await client.callTool(
            'memory.ingest',
            {
              uri: `dsh/activate-${turn}.md`,
              source: l1Capture({ secret: `activate-${turn}`, turn }),
            },
            ccosMeta(`activate-skill-${turn}`, 'alice', String(turn)),
          )
          assert.notEqual(ingested?.isError, true)
        }

        const skillRead = await client.callTool(
          'memory.skills',
          { limit: 4 },
          ccosMeta('real-rust-skill-read', 'alice', '20'),
        )
        assert.equal(skillRead.structuredContent?.returned, 1)
        assert.equal(skillRead.structuredContent?.skills?.[0]?.status, 'active')
        const exposedSkillId = skillRead.structuredContent.skills[0].id

        const source = observationalTrialCapture(skillRead, {
          secret: trialSecret,
          turn: 20,
        })
        const outcome = await client.callTool(
          'memory.ingest',
          { uri: 'dsh/observational-trial.md', source },
          ccosMeta(trialRequestId, 'alice', '21'),
        )
        assert.notEqual(outcome?.isError, true)

        const trialsPath = join(root, '.skills', 'acme', 'skill-trials.json')
        const disk = await readFile(trialsPath, 'utf8')
        assert.equal(disk.includes('real-rust-e2e-session'), false)
        assert.equal(disk.includes(trialSecret), false)
        assert.equal(disk.includes('input'), false)
        assert.equal(disk.includes('output'), false)
        const snapshot = JSON.parse(disk)
        assert.equal(Object.keys(snapshot.trials).length, 1)
        const trial = Object.values(snapshot.trials)[0]
        assert.equal(trial.skill_id, exposedSkillId)
        assert.equal(trial.status, 'passed')
        assert.match(trial.turn_key, /^[0-9a-f]{64}$/)
        assert.match(trial.evidence_id, /^[0-9a-f]{64}$/)

        const replay = await client.callTool(
          'memory.ingest',
          {
            uri: 'dsh/observational-trial.md',
            source: l1Capture({ secret: 'ATTACKER-TRIAL-REPLAY', tool: 'memory.timeline', turn: 99 }),
          },
          ccosMeta(trialRequestId, 'alice', '99'),
        )
        assert.equal(replay.structuredContent?.replayed, true)

        const afterReplay = JSON.parse(await readFile(trialsPath, 'utf8'))
        assert.equal(Object.keys(afterReplay.trials).length, 1)
        assert.equal(Object.values(afterReplay.trials)[0].status, 'passed')
      } finally {
        await client.close()
      }
    } finally {
      await rm(root, { recursive: true, force: true })
    }
  },
)
