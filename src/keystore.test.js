import test from 'ava'
import { setupIdentityKeys, setupKeys, unlock } from './kryptos/keystore'
import { generateSigningKeyPair } from './kryptos/keys'
import * as algorithms from './kryptos/algorithms'
import { PROTECTOR_TYPES } from './kryptos/constants'

test.before(async t => {
  // eslint-disable-next-line no-param-reassign
  t.context = {
    password: 'Pa$$w0rd!',
  }
})

test('Test Identity key store setup.', async t => {
  const keyStore = await setupIdentityKeys(
    'identity',
    t.context.password,
    algorithms.ECDSA_ALGO,
  )
  t.assert(keyStore.keyContainers && keyStore.pskPrivateKey)
})

test('Test RSA key store setup', async t => {
  const keyPair = await generateSigningKeyPair(algorithms.ECDSA_ALGO)
  const keyStore = await setupKeys(
    'storage',
    t.context.password,
    keyPair.privateKey,
    algorithms.RSASSA_PKCS1_V1_5_ALGO,
    algorithms.RSA_OAEP_ALGO,
  )
  t.assert(
    keyStore.keyContainers && keyStore.pdkPrivateKey && keyStore.pskPrivateKey,
  )
})

test('Test Elliptic Curve key store setup', async t => {
  const keyPair = await generateSigningKeyPair(algorithms.ECDSA_ALGO)
  const keyStore = await setupKeys(
    'storage',
    t.context.password,
    keyPair.privateKey,
    algorithms.ECDSA_ALGO,
    algorithms.ECDH_ALGO,
  )
  t.assert(keyStore.keyContainers && keyStore.pskPrivateKey)
})

test('Test Identity key store unlock.', async t => {
  const keyStore = await setupIdentityKeys(
    'identity',
    t.context.password,
    algorithms.ECDSA_ALGO,
  )
  t.assert(keyStore.keyContainers && keyStore.pskPrivateKey)
  const keyContainers = [keyStore.keyContainers.psk]
  const unlockedKeyStore = await unlock(
    keyContainers,
    t.context.password,
    PROTECTOR_TYPES.password,
  )
  t.assert(unlockedKeyStore)
})

test('Test RSA key store unlock', async t => {
  const keyPair = await generateSigningKeyPair(algorithms.ECDSA_ALGO)
  const keyStore = await setupKeys(
    'storage',
    t.context.password,
    keyPair.privateKey,
    algorithms.RSASSA_PKCS1_V1_5_ALGO,
    algorithms.RSA_OAEP_ALGO,
  )
  const keyContainers = [keyStore.keyContainers.psk, keyStore.keyContainers.pdk]
  const unlockedKeyStore = await unlock(
    keyContainers,
    t.context.password,
    PROTECTOR_TYPES.password,
  )
  t.assert(unlockedKeyStore)
})

test('Test Elliptic Curve key store unlock', async t => {
  const keyPair = await generateSigningKeyPair(algorithms.ECDSA_ALGO)
  const keyStore = await setupKeys(
    'storage',
    t.context.password,
    keyPair.privateKey,
    algorithms.ECDSA_ALGO,
    algorithms.ECDH_ALGO,
  )
  const keyContainers = [keyStore.keyContainers.psk, keyStore.keyContainers.pdk]
  const unlockedKeyStore = await unlock(
    keyContainers,
    t.context.password,
    PROTECTOR_TYPES.password,
  )
  t.assert(unlockedKeyStore)
})
