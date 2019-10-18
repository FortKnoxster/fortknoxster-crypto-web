import test from 'ava'
import { setupIdentityKeys, setupKeys, unlock } from './kryptos/keystore'
import {
  generateSigningKeyPair,
  generateEncryptionKeyPair,
} from './kryptos/keys'
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
  t.assert(keyStore.keyContainers && keyStore.psk.privateKey)
})

test('Test RSA key store setup with password protector', async t => {
  const keyPair = await generateSigningKeyPair(algorithms.ECDSA_ALGO)
  const keyStore = await setupKeys(
    'storage',
    t.context.password,
    keyPair.privateKey,
    algorithms.RSASSA_PKCS1_V1_5_ALGO,
    algorithms.RSA_OAEP_ALGO,
    PROTECTOR_TYPES.password,
  )
  t.assert(
    keyStore.keyContainers &&
      keyStore.pdk.privateKey &&
      keyStore.psk.privateKey,
  )
})

test('Test RSA key store setup with asymmetric protector', async t => {
  const keyPair = await generateEncryptionKeyPair(algorithms.RSA_OAEP_ALGO)
  const signingKeyPair = await generateSigningKeyPair(algorithms.ECDSA_ALGO)
  const keyStore = await setupKeys(
    'storage',
    keyPair.publicKey,
    signingKeyPair.privateKey,
    algorithms.RSASSA_PKCS1_V1_5_ALGO,
    algorithms.RSA_OAEP_ALGO,
    PROTECTOR_TYPES.asymmetric,
  )
  t.assert(
    keyStore.keyContainers &&
      keyStore.pdk.privateKey &&
      keyStore.psk.privateKey,
  )
})

test('Test Elliptic Curve key store setup with password protector', async t => {
  const keyPair = await generateSigningKeyPair(algorithms.ECDSA_ALGO)
  const keyStore = await setupKeys(
    'storage',
    t.context.password,
    keyPair.privateKey,
    algorithms.ECDSA_ALGO,
    algorithms.ECDH_ALGO,
    PROTECTOR_TYPES.password,
  )
  t.assert(keyStore.keyContainers && keyStore.psk.privateKey)
})

test('Test Elliptic Curve key store setup with asymmetric protector', async t => {
  const keyPair = await generateEncryptionKeyPair(algorithms.RSA_OAEP_ALGO)
  const signingKeyPair = await generateSigningKeyPair(algorithms.ECDSA_ALGO)
  const keyStore = await setupKeys(
    'storage',
    keyPair.publicKey,
    signingKeyPair.privateKey,
    algorithms.ECDSA_ALGO,
    algorithms.ECDH_ALGO,
    PROTECTOR_TYPES.asymmetric,
  )
  t.assert(keyStore.keyContainers && keyStore.psk.privateKey)
})

test('Test Identity key store unlock.', async t => {
  const service = 'identity'
  const keyStore = await setupIdentityKeys(
    service,
    t.context.password,
    algorithms.ECDSA_ALGO,
  )
  const unlockedKeyStore = await unlock(
    service,
    keyStore.keyContainers,
    t.context.password,
    PROTECTOR_TYPES.password,
  )
  t.assert(unlockedKeyStore)
})

test('Test RSA key store unlock', async t => {
  const keyPair = await generateSigningKeyPair(algorithms.ECDSA_ALGO)
  const service = 'storage'
  const keyStore = await setupKeys(
    service,
    t.context.password,
    keyPair.privateKey,
    algorithms.RSASSA_PKCS1_V1_5_ALGO,
    algorithms.RSA_OAEP_ALGO,
  )
  const unlockedKeyStore = await unlock(
    service,
    keyStore.keyContainers,
    t.context.password,
    PROTECTOR_TYPES.password,
  )
  t.assert(unlockedKeyStore)
})

test('Test Elliptic Curve key store unlock', async t => {
  const keyPair = await generateSigningKeyPair(algorithms.ECDSA_ALGO)
  const service = 'protocol'
  const keyStore = await setupKeys(
    service,
    t.context.password,
    keyPair.privateKey,
    algorithms.ECDSA_ALGO,
    algorithms.ECDH_ALGO,
  )
  const unlockedKeyStore = await unlock(
    service,
    keyStore.keyContainers,
    t.context.password,
    PROTECTOR_TYPES.password,
  )
  t.assert(unlockedKeyStore)
})
