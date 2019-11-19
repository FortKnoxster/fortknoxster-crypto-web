import test from 'ava'
import { hashAnything } from './digest'

test('Test hash anything - mix of variables, objects, arrays, strings etc.', async t => {
  const a = 'test'
  const b = [11, 22, 33]
  const c = { a: 1, b: [1, 2, 3], c: 'test' }
  const d = 123213
  const hash = await hashAnything(a, b, c, d)
  t.is(hash.length, 64)
})
