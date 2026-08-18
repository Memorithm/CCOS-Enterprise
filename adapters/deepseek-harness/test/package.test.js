import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const here = dirname(fileURLToPath(import.meta.url))
const root = join(here, '..')

test('bundle patch resolves the installed package name and declared main', async () => {
  const manifest = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'))
  const patch = await readFile(join(root, 'cordis.patch.yml'), 'utf8')
  const main = await readFile(join(root, manifest.main), 'utf8')

  assert.equal(manifest.dsh.bundle.patch, './cordis.patch.yml')
  assert.match(patch, new RegExp(`name: ['"]${manifest.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}['"]`))
  assert.ok(main.includes("export const name = 'ccos-enterprise-memory'"))
  assert.doesNotMatch(patch, /ccos-deepseek-harness\/index\.js/)
})
