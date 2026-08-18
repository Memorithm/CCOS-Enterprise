import { homedir } from 'node:os'
import { join } from 'node:path'

import { DeepSeekHarnessBridge, memoryGuidance } from './bridge.js'
import { StdioMcpClient } from './mcp-stdio.js'
import { DurableOutbox } from './outbox.js'
import { governedToolGuidance, registerGovernedTools } from './tools.js'

export const name = 'ccos-enterprise-memory'
export const inject = ['systemPrompt', 'tools']

function configuredString(value, fallback = '') {
  if (typeof value === 'string' && value.trim()) return value.trim()
  return typeof fallback === 'string' ? fallback.trim() : ''
}

function normalizeConfig(config = {}) {
  const dshHome = process.env.DSH_HOME?.trim() || join(homedir(), '.dsh')
  return {
    enabled: config.enabled !== false,
    command: configuredString(config.command, 'ccos-enterprise-mcp-server'),
    args: Array.isArray(config.args) ? config.args.map(String) : [],
    cwd: configuredString(config.cwd) || undefined,
    env: config.env && typeof config.env === 'object' ? config.env : {},
    tenantId: configuredString(config.tenantId, process.env.CCOS_ENTERPRISE_TENANT),
    actorId: configuredString(config.actorId, process.env.CCOS_ENTERPRISE_ACTOR),
    agentId: configuredString(config.agentId, 'deepseek-harness'),
    profileId: configuredString(config.profileId, 'default'),
    model: configuredString(config.model, process.env.CCOS_ENTERPRISE_MODEL || 'deepseek-harness'),
    recallEnabled: config.recallEnabled !== false,
    captureEnabled: config.captureEnabled !== false,
    toolsEnabled: config.toolsEnabled !== false,
    recallTimeoutMs: Number(config.recallTimeoutMs ?? 1000),
    recallHardLimitMs: Number(config.recallHardLimitMs ?? 3000),
    recallBudget: Number(config.recallBudget ?? 2048),
    contextMaxChars: Number(config.contextMaxChars ?? 6000),
    toolRecallTimeoutMs: Number(config.toolRecallTimeoutMs ?? 3000),
    toolTimeoutMs: Number(config.toolTimeoutMs ?? 60_000),
    toolResultMaxChars: Number(config.toolResultMaxChars ?? 6000),
    failOnStartupError: config.failOnStartupError === true,
    stateDir: configuredString(config.stateDir) || join(dshHome, 'ccos-enterprise', 'outbox'),
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

  let connected = false
  try {
    await bridge.init()
    connected = true
  } catch (error) {
    ctx.logger?.warn?.(`ccos-enterprise-memory: startup connection failed: ${error?.message || String(error)}`)
    if (config.failOnStartupError) throw error
    await outbox.init()
  }

  const unregister = []
  let toolsReady = false
  if (config.toolsEnabled && connected) {
    try {
      unregister.push(await registerGovernedTools(ctx, { client, bridge, config }))
      toolsReady = true
    } catch (error) {
      ctx.logger?.warn?.(`ccos-enterprise-memory: governed tool discovery failed: ${error?.message || String(error)}`)
      if (config.failOnStartupError) {
        await bridge.dispose()
        throw error
      }
    }
  } else if (config.toolsEnabled) {
    ctx.logger?.warn?.('ccos-enterprise-memory: governed tools unavailable because the Enterprise MCP startup connection failed')
  }

  try {
    if (ctx.systemPrompt?.section) {
      unregister.push(ctx.systemPrompt.section({
        name: 'tool:ccos-enterprise-memory',
        order: 114,
        text: [memoryGuidance(), toolsReady ? governedToolGuidance() : ''].filter(Boolean).join(' '),
      }))
    }
    if (ctx.on) {
      unregister.push(ctx.on('agent/pre-step', (payload, next) => bridge.beforeStep(payload, next)))
      unregister.push(ctx.on('session/event', (session, event) => bridge.onSessionEvent(session, event)))
      unregister.push(ctx.on('session/disposed', (session) => bridge.onSessionDisposed(session)))
    }
  } catch (error) {
    for (const dispose of unregister.reverse()) {
      try { dispose?.() } catch { /* best-effort rollback */ }
    }
    await bridge.dispose()
    throw error
  }

  ctx.logger?.info?.(
    `ccos-enterprise-memory: ready (recall=${config.recallEnabled}, capture=${config.captureEnabled}, tools=${toolsReady}, stateDir=${config.stateDir})`,
  )

  return async () => {
    for (const dispose of unregister.reverse()) {
      try { dispose?.() } catch { /* best-effort Cordis cleanup */ }
    }
    await bridge.dispose()
    ctx.logger?.info?.('ccos-enterprise-memory: stopped')
  }
}
