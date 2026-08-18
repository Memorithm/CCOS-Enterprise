import assert from 'node:assert/strict'
import { mkdtemp, readFile } from 'node:fs/promises'
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
