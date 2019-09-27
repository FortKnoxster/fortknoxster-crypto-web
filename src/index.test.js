import test from 'ava'
import * as kryptos from './index'
import { generateIdentityKeys } from './kryptos/serviceKeyStore'
import { setupKeys, unlock } from './kryptos/keystore'
import { generateSigningKeyPair, generateSessionKey } from './kryptos/keys'
import * as algorithms from './kryptos/algorithms'
import { PROTECTOR_TYPES } from './kryptos/constants'

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

test('Test Identity key store setup.', async t => {
  const keyContainer = await generateIdentityKeys(t.context.password)
  t.assert(
    keyContainer.psk &&
      keyContainer.pvk &&
      keyContainer.fingerprint &&
      keyContainer.psk.encryptedKey &&
      keyContainer.psk.keyProtectors[0],
  )
})

test('Test RSA key store setup', async t => {
  const keyPair = await generateSigningKeyPair(algorithms.ECDSA_ALGO)
  const keyStore = await setupKeys(
    t.context.password,
    keyPair.privateKey,
    algorithms.RSASSA_PKCS1_V1_5_ALGO,
    algorithms.RSA_OAEP_ALGO,
  )
  t.assert(
    keyStore.psk &&
      keyStore.pvk &&
      keyStore.pdk &&
      keyStore.pek &&
      keyStore.signature &&
      keyStore.psk.encryptedKey &&
      keyStore.psk.keyProtectors[0] &&
      keyStore.pdk.encryptedKey &&
      keyStore.pdk.keyProtectors[0],
  )
})

test('Test Elliptic Curve key store setup', async t => {
  const keyPair = await generateSigningKeyPair(algorithms.ECDSA_ALGO)
  const keyStore = await setupKeys(
    t.context.password,
    keyPair.privateKey,
    algorithms.ECDSA_ALGO,
    algorithms.ECDH_ALGO,
  )
  t.assert(
    keyStore.psk &&
      keyStore.pvk &&
      keyStore.pdk &&
      keyStore.pek &&
      keyStore.signature &&
      keyStore.psk.encryptedKey &&
      keyStore.psk.keyProtectors[0] &&
      keyStore.pdk.encryptedKey &&
      keyStore.pdk.keyProtectors[0],
  )
})

test('Test RSA key store unlock', async t => {
  const keyPair = await generateSigningKeyPair(algorithms.ECDSA_ALGO)
  const keyStore = await setupKeys(
    t.context.password,
    keyPair.privateKey,
    algorithms.RSASSA_PKCS1_V1_5_ALGO,
    algorithms.RSA_OAEP_ALGO,
  )
  const unlockedKeyStore = await unlock(
    keyStore,
    t.context.password,
    PROTECTOR_TYPES.password,
  )
  t.assert(unlockedKeyStore)
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
