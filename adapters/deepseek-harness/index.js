import { homedir } from 'node:os'
import { join } from 'node:path'

import { DeepSeekHarnessBridge, memoryGuidance } from './bridge.js'
import { StdioMcpClient } from './mcp-stdio.js'
import { DurableOutbox } from './outbox.js'

export const name = 'ccos-enterprise-memory'
export const inject = ['systemPrompt']

function normalizeConfig(config = {}) {
  const dshHome = process.env.DSH_HOME?.trim() || join(homedir(), '.dsh')
  return {
    enabled: config.enabled !== false,
    command: typeof config.command === 'string' && config.command.trim()
      ? config.command.trim()
      : 'ccos-enterprise-mcp-server',
    args: Array.isArray(config.args) ? config.args.map(String) : [],
    cwd: typeof config.cwd === 'string' && config.cwd.trim() ? config.cwd : undefined,
    env: config.env && typeof config.env === 'object' ? config.env : {},
    tenantId: typeof config.tenantId === 'string' ? config.tenantId : '',
    actorId: typeof config.actorId === 'string' ? config.actorId : '',
    agentId: typeof config.agentId === 'string' && config.agentId.trim()
      ? config.agentId.trim()
      : 'deepseek-harness',
    profileId: typeof config.profileId === 'string' && config.profileId.trim()
      ? config.profileId.trim()
      : 'default',
    model: typeof config.model === 'string' && config.model.trim()
      ? config.model.trim()
      : 'deepseek-harness',
    recallEnabled: config.recallEnabled !== false,
    captureEnabled: config.captureEnabled !== false,
    recallTimeoutMs: Number(config.recallTimeoutMs ?? 1000),
    recallHardLimitMs: Number(config.recallHardLimitMs ?? 3000),
    recallBudget: Number(config.recallBudget ?? 2048),
    contextMaxChars: Number(config.contextMaxChars ?? 6000),
    failOnStartupError: config.failOnStartupError === true,
    stateDir: typeof config.stateDir === 'string' && config.stateDir.trim()
      ? config.stateDir.trim()
      : join(dshHome, 'ccos-enterprise', 'outbox'),
  }
}

export async function apply(ctx, rawConfig = {}) {
  const config = normalizeConfig(rawConfig)
  if (!config.enabled) return async () => undefined

  const client = new StdioMcpClient({
    command: config.command,
    args: config.args,
    cwd: config.cwd,
    env: config.env,
    logger: ctx.logger,
  })
  const outbox = new DurableOutbox(config.stateDir)
  const bridge = new DeepSeekHarnessBridge({ client, outbox, config, logger: ctx.logger })

  try {
    await bridge.init()
  } catch (error) {
    ctx.logger?.warn?.(`ccos-enterprise-memory: startup connection failed: ${error?.message || String(error)}`)
    if (config.failOnStartupError) throw error
    await outbox.init()
  }

  const unregister = []
  if (ctx.systemPrompt?.section) {
    unregister.push(ctx.systemPrompt.section({
      name: 'tool:ccos-enterprise-memory',
      order: 114,
      text: memoryGuidance(),
    }))
  }
  if (ctx.on) {
    unregister.push(ctx.on('agent/pre-step', (payload, next) => bridge.beforeStep(payload, next)))
    unregister.push(ctx.on('session/event', (session, event) => bridge.onSessionEvent(session, event)))
    unregister.push(ctx.on('session/disposed', () => undefined))
  }

  ctx.logger?.info?.(
    `ccos-enterprise-memory: ready (recall=${config.recallEnabled}, capture=${config.captureEnabled}, stateDir=${config.stateDir})`,
  )

  return async () => {
    for (const dispose of unregister.reverse()) {
      try { dispose?.() } catch { /* best-effort Cordis cleanup */ }
    }
    await bridge.dispose()
    ctx.logger?.info?.('ccos-enterprise-memory: stopped')
  }
}
