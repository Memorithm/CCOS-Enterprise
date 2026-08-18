import assert from 'node:assert/strict'
import test from 'node:test'

import { DeepSeekHarnessBridge } from '../bridge.js'

function config() {
  return {
    tenantId: 'acme',
    actorId: 'alice',
    agentId: 'deepseek-harness',
    profileId: 'prod',
    model: 'deepseek-harness',
    recallEnabled: false,
    captureEnabled: false,
  }
}

test('execution identity follows DSH turn/step and includes tool call id', () => {
  const bridge = new DeepSeekHarnessBridge({
    client: {},
    outbox: {},
    config: config(),
    logger: { warn() {} },
  })
  const session = { id: 'session-7', header: { cwd: '/repo' } }
  bridge.onSessionEvent(session, { type: 'turn/start', time: 1, data: { turn: 12 } })
  bridge.onSessionEvent(session, { type: 'step/start', time: 2, data: { turn: 12, step: 3 } })

  const active = bridge.executionIdentity({
    callId: 'call-42',
    agent: { session },
  })
  assert.equal(active.tenant_id, 'acme')
  assert.equal(active.actor_id, 'alice')
  assert.equal(active.dsh_session_id, 'session-7')
  assert.equal(active.turn_id, '12')
  assert.equal(active.step_id, '3')
  assert.equal(active.tool_call_id, 'call-42')
  assert.equal(active.workspace, '/repo')

  bridge.onSessionEvent(session, { type: 'step/end', time: 3, data: { turn: 12, step: 3 } })
  const afterStep = bridge.executionIdentity({ callId: 'call-43', agent: { session } })
  assert.equal(afterStep.turn_id, '12')
  assert.equal(afterStep.step_id, '0')
  assert.equal(afterStep.tool_call_id, 'call-43')

  bridge.onSessionDisposed(session)
  const disposed = bridge.executionIdentity({ callId: 'call-44', agent: { session } })
  assert.equal(disposed.turn_id, '0')
  assert.equal(disposed.step_id, '0')
})
