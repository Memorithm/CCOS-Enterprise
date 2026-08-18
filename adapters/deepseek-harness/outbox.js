import { mkdir, open, readdir, readFile, rename, rm } from 'node:fs/promises'
import { join } from 'node:path'

export class DurableOutbox {
  constructor(root) {
    this.root = root
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

  async list() {
    await this.init()
    const names = (await readdir(this.root))
      .filter((name) => name.endsWith('.json'))
      .sort()
    const entries = []
    for (const name of names) {
      const raw = await readFile(join(this.root, name), 'utf8')
      entries.push({ key: name.slice(0, -5), value: JSON.parse(raw) })
    }
    return entries
  }

  async remove(key) {
    await rm(join(this.root, `${key}.json`), { force: true })
  }
}
