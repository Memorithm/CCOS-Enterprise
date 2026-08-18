import assert from 'node:assert/strict'
import test from 'node:test'

import { captureKey, resolveIdentity } from '../identity.js'

test('identity binds tenant actor DSH session turn and workspace', () => {
  const identity = resolveIdentity(
    { tenantId: 'acme', actorId: 'alice', agentId: 'deepseek-harness', profileId: 'prod', model: 'deepseek' },
    { id: 's-1', header: { cwd: '/repo' } },
    7,
    1,
  )
  assert.equal(identity.tenant_id, 'acme')
  assert.equal(identity.actor_id, 'alice')
  assert.equal(identity.dsh_session_id, 's-1')
  assert.equal(identity.turn_id, '7')
  assert.equal(identity.step_id, '1')
  assert.equal(identity.workspace, '/repo')
  assert.match(identity.request_id, /^[0-9a-f-]{36}$/)
  assert.match(identity.trace_id, /^[0-9a-f]{32}$/)
})

test('capture keys isolate tenants even for identical DSH session/turn ids', () => {
  const session = { id: 'same-session' }
  const a = resolveIdentity({ tenantId: 'tenant-a', actorId: 'alice' }, session, 3, 0)
  const b = resolveIdentity({ tenantId: 'tenant-b', actorId: 'alice' }, session, 3, 0)
  assert.notEqual(captureKey(a), captureKey(b))
})

test('missing tenant or actor is rejected rather than guessed', () => {
  assert.throws(() => resolveIdentity({ actorId: 'alice' }, { id: 's' }, 1), /tenantId/)
  assert.throws(() => resolveIdentity({ tenantId: 'acme' }, { id: 's' }, 1), /actorId/)
})
