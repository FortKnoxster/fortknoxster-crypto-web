import test from 'ava'
import * as kryptos from '../index'
import { generateSigningKeyPair, generateSessionKey } from './keys'
import * as algorithms from './algorithms'

test.before(async t => {
  // eslint-disable-next-line no-param-reassign
  t.context = {
    password: 'Pa$$w0rd!',
  }
})

test('Test deriveAccountPassword', async t => {
  const encryptedPassword = await kryptos.deriveAccountPassword(
    'FortKnoxster',
    t.context.password,
    'fortknoxster.com',
  )
  t.is(encryptedPassword.length, 64)
})

test('Test generate RSA signing key pair', async t => {
  const keyPair = await generateSigningKeyPair(
    algorithms.RSASSA_PKCS1_V1_5_ALGO,
  )

  t.assert(keyPair.publicKey && keyPair.privateKey)
})

test('Test generate Elliptic Curve signing key pair', async t => {
  const keyPair = await generateSigningKeyPair(algorithms.ECDSA_ALGO)

  t.assert(keyPair.publicKey && keyPair.privateKey)
})

test('Test generateSessionKey AES-CBC-256', async t => {
  const sessionKey = await generateSessionKey(algorithms.AES_CBC_ALGO)
  t.assert(
    sessionKey.algorithm.name === algorithms.AES_CBC_ALGO.name &&
      sessionKey.algorithm.length === algorithms.AES_CBC_ALGO.length,
  )
})

test('Test generateSessionKey AES-GCM-256', async t => {
  const sessionKey = await generateSessionKey(algorithms.AES_GCM_ALGO)
  t.assert(
    sessionKey.algorithm.name === algorithms.AES_GCM_ALGO.name &&
      sessionKey.algorithm.length === algorithms.AES_GCM_ALGO.length,
  )
})
