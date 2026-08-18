import { createHash, randomUUID } from 'node:crypto'

export const HOST_KIND = 'deepseek-harness'

function required(value, name) {
  const text = typeof value === 'string' ? value.trim() : ''
  if (!text) throw new Error(`CCOS DeepSeek adapter requires ${name}`)
  return text
}

export function resolveIdentity(config, session, turn, step = 0, extra = {}) {
  const tenantId = required(config.tenantId, 'tenantId')
  const actorId = required(config.actorId, 'actorId')
  const agentId = required(config.agentId || HOST_KIND, 'agentId')
  const sessionId = required(session?.id, 'DeepSeek Harness session.id')
  const turnId = Number.isFinite(turn) ? String(turn) : '0'
  const stepId = Number.isFinite(step) ? String(step) : '0'
  const requestId = randomUUID()
  const traceId = createHash('sha256')
    .update(`${tenantId}\0${actorId}\0${sessionId}\0${turnId}\0${stepId}\0${requestId}`)
    .digest('hex')
    .slice(0, 32)
  const toolCallId = typeof extra.toolCallId === 'string' && extra.toolCallId.trim()
    ? extra.toolCallId.trim()
    : undefined

  return Object.freeze({
    tenant_id: tenantId,
    actor_id: actorId,
    agent_id: agentId,
    host: HOST_KIND,
    dsh_profile: typeof config.profileId === 'string' && config.profileId.trim()
      ? config.profileId.trim()
      : 'default',
    dsh_session_id: sessionId,
    turn_id: turnId,
    step_id: stepId,
    request_id: requestId,
    trace_id: traceId,
    model: typeof config.model === 'string' && config.model.trim()
      ? config.model.trim()
      : HOST_KIND,
    workspace: typeof session?.header?.cwd === 'string' ? session.header.cwd : undefined,
    ...(toolCallId ? { tool_call_id: toolCallId } : {}),
  })
}

export function captureKey(identity) {
  return createHash('sha256')
    .update(`${identity.tenant_id}\0${identity.dsh_session_id}\0${identity.turn_id}`)
    .digest('hex')
}
