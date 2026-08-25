import { mkdir, open, readdir, readFile, rename, rm } from 'node:fs/promises'
import { join } from 'node:path'

// A single capture is a rendered turn: bounded by DSH context limits in
// practice, but the outbox still refuses to load an entry larger than this so
// a hostile or corrupted file cannot buy an unbounded allocation.
const MAX_ENTRY_BYTES = 8 * 1024 * 1024

export class DurableOutbox {
  constructor(root) {
    this.root = root
    this.logger = undefined
  }

  async init() {
    await mkdir(this.root, { recursive: true })
  }

  async put(key, value) {
    await this.init()
    const target = join(this.root, `${key}.json`)
    const temp = join(this.root, `.${key}.${process.pid}.${Date.now()}.tmp`)
    const handle = await open(temp, 'wx', 0o600)
    try {
      await handle.writeFile(`${JSON.stringify(value)}\n`, 'utf8')
      await handle.sync()
    } finally {
      await handle.close()
    }
    await rename(temp, target)
    return target
  }

  /**
   * List pending entries oldest-first.
   *
   * A corrupt or oversized entry never fails the listing: it would otherwise
   * poison the drain loop forever (the entry cannot deliver, so the outbox can
   * never empty). Such an entry is reported through `onCorrupt` — when given —
   * and left on disk for operator inspection; healthy entries still flow.
   */
  async list({ limit = Infinity, onCorrupt } = {}) {
    await this.init()
    const names = (await readdir(this.root))
      .filter((name) => name.endsWith('.json') && !name.startsWith('.'))
      .sort()
    const entries = []
    for (const name of names) {
      if (entries.length >= limit) break
      let raw
      try {
        raw = await readFile(join(this.root, name))
      } catch (error) {
        if (error?.code === 'ENOENT') continue // removed concurrently
        throw error
      }
      if (raw.byteLength > MAX_ENTRY_BYTES) {
        onCorrupt?.(name.slice(0, -5), new Error(`entry exceeds ${MAX_ENTRY_BYTES} bytes`))
        continue
      }
      try {
        entries.push({ key: name.slice(0, -5), value: JSON.parse(raw.toString('utf8')) })
      } catch (error) {
        onCorrupt?.(name.slice(0, -5), error)
      }
    }
    return entries
  }

  async remove(key) {
    await rm(join(this.root, `${key}.json`), { force: true })
  }
}
