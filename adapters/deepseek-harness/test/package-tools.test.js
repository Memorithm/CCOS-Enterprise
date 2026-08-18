import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const here = dirname(fileURLToPath(import.meta.url))
const root = join(here, '..')

test('bundle enables governed tools with finite default budgets', async () => {
  const patch = await readFile(join(root, 'cordis.patch.yml'), 'utf8')
  const manifest = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'))
  assert.match(manifest.scripts.check, /tools\.js/)
  assert.match(patch, /toolsEnabled: true/)
  assert.match(patch, /toolRecallTimeoutMs: 3000/)
  assert.match(patch, /toolTimeoutMs: 60000/)
  assert.match(patch, /toolResultMaxChars: 6000/)
  assert.doesNotMatch(patch, /toolTimeoutMs:\s*0/)
})
