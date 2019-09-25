import test from 'ava'
import { isCryptoSupported } from './index'
import { generateSessionKey } from './kryptos/core/keys'
import * as algorithms from './kryptos/algorithms'

test('can add numbers', t => {
  t.is(1 + 1, 2)
})

test('index.js exports isCryptoSupported', t => {
  t.assert(isCryptoSupported)
})

test('Test generate encryption key AES-CBC', async t => {
  const sessionKey = await generateSessionKey(algorithms.AES_CBC_ALGO)
  console.log(sessionKey)
  t.is(sessionKey, CryptoKey)
})
