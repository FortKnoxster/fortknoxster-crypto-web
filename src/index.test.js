import test from 'ava'
import { isCryptoSupported } from './index'

test('can add numbers', t => {
  t.is(1 + 1, 2)
})

test('index.js exports isCryptoSupported', t => {
  t.assert(isCryptoSupported)
})
