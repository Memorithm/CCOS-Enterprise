import assert from 'node:assert/strict'
import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { DurableOutbox } from '../outbox.js'

test('outbox persists before acknowledgement and removes only explicitly', async () => {
  const root = await mkdtemp(join(tmpdir(), 'ccos-dsh-outbox-'))
  const outbox = new DurableOutbox(root)
  await outbox.put('abc', { n: 1 })
  assert.deepEqual(await outbox.list(), [{ key: 'abc', value: { n: 1 } }])
  const raw = await readFile(join(root, 'abc.json'), 'utf8')
  assert.equal(raw, '{"n":1}\n')
  await outbox.remove('abc')
  assert.deepEqual(await outbox.list(), [])
})

test('a corrupt entry never poisons the listing of healthy entries', async () => {
  const root = await mkdtemp(join(tmpdir(), 'ccos-dsh-outbox-'))
  const outbox = new DurableOutbox(root)
  await outbox.put('a-first', { n: 1 })
  // A crash or disk corruption left a torn file behind.
  await writeFile(join(root, 'b-torn.json'), '{"partial": ', 'utf8')
  await outbox.put('c-last', { n: 3 })

  const corrupted = []
  const entries = await outbox.list({ onCorrupt: (key) => corrupted.push(key) })
  assert.deepEqual(entries.map((entry) => entry.key), ['a-first', 'c-last'])
  assert.deepEqual(corrupted, ['b-torn'])
  // The corrupt file stays on disk for operator inspection.
  assert.equal(await readFile(join(root, 'b-torn.json'), 'utf8'), '{"partial": ')
})

test('listing honours the batch limit and skips temp files', async () => {
  const root = await mkdtemp(join(tmpdir(), 'ccos-dsh-outbox-'))
  const outbox = new DurableOutbox(root)
  for (const key of ['a-1', 'a-2', 'a-3']) await outbox.put(key, { key })
  // In-flight temp files from a concurrent put are never listed.
  await writeFile(join(root, `.a-4.${process.pid}.1.tmp`), 'x', 'utf8')

  assert.deepEqual((await outbox.list({ limit: 2 })).map((e) => e.key), ['a-1', 'a-2'])
  assert.deepEqual((await outbox.list()).length, 3)
})

test('an oversized entry is quarantined rather than loaded into memory', async () => {
  const root = await mkdtemp(join(tmpdir(), 'ccos-dsh-outbox-'))
  const outbox = new DurableOutbox(root)
  await writeFile(join(root, 'huge.json'), `{"pad":"${'x'.repeat(9 * 1024 * 1024)}"}\n`, 'utf8')
  await outbox.put('small', { ok: true })

  const corrupted = []
  const entries = await outbox.list({ onCorrupt: (key) => corrupted.push(key) })
  assert.deepEqual(entries.map((entry) => entry.key), ['small'])
  assert.deepEqual(corrupted, ['huge'])
})
