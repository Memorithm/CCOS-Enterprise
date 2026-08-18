import { spawn } from 'node:child_process'
import { createInterface } from 'node:readline'

const MCP_PROTOCOL_VERSION = '2024-11-05'

export class StdioMcpClient {
  constructor(options) {
    this.command = options.command
    this.args = Array.isArray(options.args) ? options.args : []
    this.env = { ...process.env, ...(options.env || {}) }
    this.cwd = options.cwd || undefined
    this.logger = options.logger || console
    this.requestTimeoutMs = options.requestTimeoutMs || 60_000
    this.child = null
    this.pending = new Map()
    this.nextId = 1
    this.closed = false
    this.startPromise = null
  }

  async start() {
    if (this.child) return
    if (this.startPromise) return this.startPromise
    this.startPromise = this.#startImpl()
    try {
      await this.startPromise
    } finally {
      this.startPromise = null
    }
  }

  async #startImpl() {
    if (!this.command || !String(this.command).trim()) {
      throw new Error('CCOS DeepSeek adapter requires an MCP command')
    }

    const child = spawn(this.command, this.args, {
      cwd: this.cwd,
      env: this.env,
      stdio: ['pipe', 'pipe', 'pipe'],
      shell: false,
    })
    this.child = child

    const stdout = createInterface({ input: child.stdout, crlfDelay: Infinity })
    stdout.on('line', (line) => this.#onLine(line))
    child.stderr.setEncoding('utf8')
    child.stderr.on('data', (chunk) => {
      const text = String(chunk).trim()
      if (text) this.logger.warn?.(`ccos-enterprise-mcp: ${text}`)
    })
    child.once('error', (error) => this.#failAll(error))
    child.once('exit', (code, signal) => {
      const reason = new Error(`CCOS Enterprise MCP exited (code=${code}, signal=${signal})`)
      this.child = null
      if (!this.closed) this.#failAll(reason)
    })

    const init = await this.request('initialize', {
      protocolVersion: MCP_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: {
        name: '@memorithm/ccos-deepseek-harness',
        version: '0.1.0-pre',
      },
    })
    if (!init || typeof init !== 'object') {
      throw new Error('CCOS Enterprise MCP returned an invalid initialize result')
    }
    this.notify('notifications/initialized', {})
  }

  async callTool(name, arguments_, meta, options = {}) {
    if (!this.child) await this.start()
    const params = {
      name,
      arguments: arguments_ || {},
      _meta: { ccos: meta || {} },
    }
    return this.request('tools/call', params, options)
  }

  request(method, params, options = {}) {
    if (!this.child?.stdin?.writable) {
      return Promise.reject(new Error('CCOS Enterprise MCP is not running'))
    }
    const id = this.nextId++
    const timeoutMs = options.timeoutMs ?? this.requestTimeoutMs
    const signal = options.signal
    return new Promise((resolve, reject) => {
      let timer
      const cleanup = () => {
        if (timer) clearTimeout(timer)
        signal?.removeEventListener('abort', onAbort)
        this.pending.delete(id)
      }
      const onAbort = () => {
        cleanup()
        reject(signal.reason instanceof Error ? signal.reason : new Error('request aborted'))
      }
      if (signal?.aborted) return onAbort()
      if (signal) signal.addEventListener('abort', onAbort, { once: true })
      if (Number.isFinite(timeoutMs) && timeoutMs > 0) {
        timer = setTimeout(() => {
          cleanup()
          reject(new Error(`MCP request ${method} exceeded ${timeoutMs}ms`))
        }, timeoutMs)
      }
      this.pending.set(id, {
        resolve: (value) => { cleanup(); resolve(value) },
        reject: (error) => { cleanup(); reject(error) },
      })
      try {
        this.#write({ jsonrpc: '2.0', id, method, params })
      } catch (error) {
        cleanup()
        reject(error)
      }
    })
  }

  notify(method, params) {
    this.#write({ jsonrpc: '2.0', method, params })
  }

  async close() {
    this.closed = true
    const child = this.child
    this.child = null
    this.#failAll(new Error('CCOS Enterprise MCP client closed'))
    if (!child) return
    if (child.stdin.writable) child.stdin.end()
    if (child.exitCode === null && child.signalCode === null) {
      await new Promise((resolve) => {
        const timer = setTimeout(() => {
          child.kill('SIGTERM')
          resolve()
        }, 500)
        child.once('exit', () => {
          clearTimeout(timer)
          resolve()
        })
      })
    }
  }

  #write(message) {
    if (!this.child?.stdin?.writable) throw new Error('CCOS Enterprise MCP stdin is closed')
    this.child.stdin.write(`${JSON.stringify(message)}\n`)
  }

  #onLine(line) {
    let message
    try {
      message = JSON.parse(line)
    } catch {
      this.logger.warn?.('ccos-enterprise-mcp: ignored non-JSON stdout line')
      return
    }
    if (!Object.prototype.hasOwnProperty.call(message, 'id')) return
    const pending = this.pending.get(message.id)
    if (!pending) return
    if (message.error) {
      const error = new Error(message.error.message || 'MCP request failed')
      error.code = message.error.code
      error.data = message.error.data
      pending.reject(error)
    } else {
      pending.resolve(message.result)
    }
  }

  #failAll(error) {
    for (const pending of [...this.pending.values()]) pending.reject(error)
    this.pending.clear()
  }
}

export function textFromMcpToolResult(result) {
  if (!result || typeof result !== 'object') return ''
  const blocks = Array.isArray(result.content) ? result.content : []
  return blocks
    .filter((block) => block && block.type === 'text' && typeof block.text === 'string')
    .map((block) => block.text)
    .join('\n')
    .trim()
}
