import test from 'ava'
import * as kryptos from './index'
import { generateIdentityKeys } from './kryptos/keyStore'
import { setupKeys } from './kryptos/core/keystore'
import { generateSigningKeyPair, generateSessionKey } from './kryptos/core/keys'
import * as algorithms from './kryptos/algorithms'

test.before(async t => {
  t.log('Start test')
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

test('Test Identity keys setup.', async t => {
  const keyContainer = await generateIdentityKeys(t.context.password)
  t.assert(
    keyContainer.psk &&
      keyContainer.pvk &&
      keyContainer.fingerprint &&
      keyContainer.psk.encryptedKey &&
      keyContainer.psk.keyProtectors[0],
  )
})

test('Test RSA keys setup', async t => {
  const keyPair = await generateSigningKeyPair(algorithms.ECDSA_ALGO)
  const keyContainers = await setupKeys(
    t.context.password,
    keyPair.privateKey,
    algorithms.RSASSA_PKCS1_V1_5_ALGO,
    algorithms.RSA_OAEP_ALGO,
  )
  t.assert(
    keyContainers.psk &&
      keyContainers.pvk &&
      keyContainers.pdk &&
      keyContainers.pek &&
      keyContainers.signature &&
      keyContainers.psk.encryptedKey &&
      keyContainers.psk.keyProtectors[0] &&
      keyContainers.pdk.encryptedKey &&
      keyContainers.pdk.keyProtectors[0],
  )
})

test('Test Elliptic Curve keys setup', async t => {
  const keyPair = await generateSigningKeyPair(algorithms.ECDSA_ALGO)
  const keyContainers = await setupKeys(
    t.context.password,
    keyPair.privateKey,
    algorithms.ECDSA_ALGO,
    algorithms.ECDH_ALGO,
  )
  t.assert(
    keyContainers.psk &&
      keyContainers.pvk &&
      keyContainers.pdk &&
      keyContainers.pek &&
      keyContainers.signature &&
      keyContainers.psk.encryptedKey &&
      keyContainers.psk.keyProtectors[0] &&
      keyContainers.pdk.encryptedKey &&
      keyContainers.pdk.keyProtectors[0],
  )
})

test('Test generateSessionKey AES-CBC', async t => {
  const sessionKey = await generateSessionKey(algorithms.AES_CBC_ALGO)
  t.assert(
    sessionKey.algorithm.name === algorithms.AES_CBC_ALGO.name &&
      sessionKey.algorithm.length === algorithms.AES_CBC_ALGO.length,
  )
})

test('Test generateSessionKey AES-GCM', async t => {
  const sessionKey = await generateSessionKey(algorithms.AES_GCM_ALGO)
  t.assert(
    sessionKey.algorithm.name === algorithms.AES_GCM_ALGO.name &&
      sessionKey.algorithm.length === algorithms.AES_GCM_ALGO.length,
  )
})
