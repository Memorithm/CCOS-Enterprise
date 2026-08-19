import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const here = dirname(fileURLToPath(import.meta.url))
const root = join(here, '..')

async function manifest() {
  return JSON.parse(await readFile(join(root, 'package.json'), 'utf8'))
}

test('bundle patch resolves the installed package name and declared main', async () => {
  const packageManifest = await manifest()
  const patch = await readFile(join(root, 'cordis.patch.yml'), 'utf8')
  const main = await readFile(join(root, packageManifest.main), 'utf8')

  assert.equal(packageManifest.dsh.bundle.patch, './cordis.patch.yml')
  assert.match(patch, new RegExp(`name: ['"]${packageManifest.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}['"]`))
  assert.ok(main.includes("export const name = 'ccos-enterprise-memory'"))
  assert.doesNotMatch(patch, /ccos-deepseek-harness\/index\.js/)
})

test('manifest advertises only the tested DeepSeek Harness rc.7 host floor', async () => {
  const packageManifest = await manifest()
  assert.equal(packageManifest.engines.node, '^22.19.0 || >=24.0.0')

  for (const dependency of [
    '@deepseek-ai/dsh-agent',
    '@deepseek-ai/dsh-session',
    '@deepseek-ai/dsh-system-prompt',
    '@deepseek-ai/dsh-tools',
  ]) {
    assert.equal(packageManifest.peerDependencies[dependency], '>=0.1.0-rc.7 <0.2.0')
  }
})
