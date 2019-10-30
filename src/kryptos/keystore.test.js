/* eslint-disable max-lines */
import test from 'ava'
import { setupIdentityKeys, setupKeys, unlock, lock } from './keystore'
import { generateSigningKeyPair, generateEncryptionKeyPair } from './keys'
import * as algorithms from './algorithms'
import { randomString } from './utils'
import { PROTECTOR_TYPES, SERVICES } from './constants'
import { initKeyStores, unlockKeyStores } from './serviceKeyStore'
import keyStoresJson from '../test/json/keyStores'
import initKeyStoresJson from '../test/json/initKeyStores'

test.before(async t => {
  // eslint-disable-next-line no-param-reassign
  t.context = {
    password: 'Pa$$w0rd!',
  }
})

test('Test Identity key store setup.', async t => {
  const keyStore = await setupIdentityKeys(
    SERVICES.identity,
    t.context.password,
    algorithms.ECDSA_ALGO,
  )
  t.assert(keyStore.keyContainers && keyStore.psk.privateKey)
})

test('Test RSA key store setup with password protector', async t => {
  const keyPair = await generateSigningKeyPair(algorithms.ECDSA_ALGO)
  const keyStore = await setupKeys(
    SERVICES.storage,
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
    SERVICES.storage,
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
    SERVICES.storage,
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
    SERVICES.storage,
    keyPair.publicKey,
    signingKeyPair.privateKey,
    algorithms.ECDSA_ALGO,
    algorithms.ECDH_ALGO,
    PROTECTOR_TYPES.asymmetric,
  )
  t.assert(keyStore.keyContainers && keyStore.psk.privateKey)
})

test('Test Identity key store unlock.', async t => {
  const service = SERVICES.identity
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
  const service = SERVICES.storage
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
  const service = SERVICES.protocol
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

test('Test unlock user key stores', async t => {
  const serviceKeyStores = await unlockKeyStores(
    keyStoresJson,
    'Test123456',
    PROTECTOR_TYPES.password,
  )

  t.assert(serviceKeyStores)
})

test('Test init unlock user key stores with existing derived password protector', async t => {
  const success = await initKeyStores(initKeyStoresJson)
  t.assert(success)
})

test('Test RSA key store lock with new recovery key protector', async t => {
  const keyPair = await generateSigningKeyPair(algorithms.ECDSA_ALGO)
  const service = SERVICES.storage
  const keyStore = await setupKeys(
    service,
    t.context.password,
    keyPair.privateKey,
    algorithms.RSASSA_PKCS1_V1_5_ALGO,
    algorithms.RSA_OAEP_ALGO,
  )
  const recoveryKey = randomString()
  await lock(
    keyStore.keyContainers,
    t.context.password,
    PROTECTOR_TYPES.password,
    recoveryKey,
    PROTECTOR_TYPES.recovery,
  )
  const hasPasswordProtector = keyStore.keyContainers.psk.keyProtectors.find(
    protector => protector.type === PROTECTOR_TYPES.password,
  )
  const hasRecoveryProtector = keyStore.keyContainers.psk.keyProtectors.find(
    protector => protector.type === PROTECTOR_TYPES.recovery,
  )
  t.assert(hasPasswordProtector && hasRecoveryProtector)
})

test('Test RSA key store lock with new password protector', async t => {
  const keyPair = await generateSigningKeyPair(algorithms.ECDSA_ALGO)
  const service = SERVICES.storage
  const keyStore = await setupKeys(
    service,
    t.context.password,
    keyPair.privateKey,
    algorithms.RSASSA_PKCS1_V1_5_ALGO,
    algorithms.RSA_OAEP_ALGO,
  )
  const newPassword = randomString()
  await lock(
    keyStore.keyContainers,
    t.context.password,
    PROTECTOR_TYPES.password,
    newPassword,
    PROTECTOR_TYPES.password,
  )
  const hasPasswordProtector = keyStore.keyContainers.psk.keyProtectors.find(
    protector => protector.type === PROTECTOR_TYPES.password,
  )
  // Todo: Also check actual password protector got replaced
  t.assert(hasPasswordProtector)
})

test('Test RSA key store lock with new asymmetric protector', async t => {
  const keyPair = await generateSigningKeyPair(algorithms.ECDSA_ALGO)
  const service = SERVICES.storage
  const keyStore = await setupKeys(
    service,
    t.context.password,
    keyPair.privateKey,
    algorithms.RSASSA_PKCS1_V1_5_ALGO,
    algorithms.RSA_OAEP_ALGO,
  )
  const newProtectorKeyPair = await generateEncryptionKeyPair(
    algorithms.RSA_OAEP_ALGO,
  )
  await lock(
    keyStore.keyContainers,
    t.context.password,
    PROTECTOR_TYPES.password,
    newProtectorKeyPair.publicKey,
    PROTECTOR_TYPES.asymmetric,
  )
  const hasPasswordProtector = keyStore.keyContainers.psk.keyProtectors.find(
    protector => protector.type === PROTECTOR_TYPES.password,
  )
  const hasAsymmetricProtector = keyStore.keyContainers.psk.keyProtectors.find(
    protector => protector.type === PROTECTOR_TYPES.password,
  )
  t.assert(hasPasswordProtector && hasAsymmetricProtector)
})

test('Test Elliptic Curve key store lock with new recovery key protector', async t => {
  const keyPair = await generateSigningKeyPair(algorithms.ECDSA_ALGO)
  const service = SERVICES.storage
  const keyStore = await setupKeys(
    service,
    t.context.password,
    keyPair.privateKey,
    algorithms.ECDSA_ALGO,
    algorithms.ECDH_ALGO,
  )
  const recoveryKey = randomString()
  await lock(
    keyStore.keyContainers,
    t.context.password,
    PROTECTOR_TYPES.password,
    recoveryKey,
    PROTECTOR_TYPES.recovery,
  )
  const hasPasswordProtector = keyStore.keyContainers.psk.keyProtectors.find(
    protector => protector.type === PROTECTOR_TYPES.password,
  )
  const hasRecoveryProtector = keyStore.keyContainers.psk.keyProtectors.find(
    protector => protector.type === PROTECTOR_TYPES.recovery,
  )
  t.assert(hasPasswordProtector && hasRecoveryProtector)
})

test('Test Elliptic Curve key store lock with new password protector', async t => {
  const keyPair = await generateSigningKeyPair(algorithms.ECDSA_ALGO)
  const service = SERVICES.storage
  const keyStore = await setupKeys(
    service,
    t.context.password,
    keyPair.privateKey,
    algorithms.ECDSA_ALGO,
    algorithms.ECDH_ALGO,
  )
  const newPassword = randomString()
  await lock(
    keyStore.keyContainers,
    t.context.password,
    PROTECTOR_TYPES.password,
    newPassword,
    PROTECTOR_TYPES.password,
  )
  const hasPasswordProtector = keyStore.keyContainers.psk.keyProtectors.find(
    protector => protector.type === PROTECTOR_TYPES.password,
  )
  // Todo: Also check actual password protector got replaced
  t.assert(hasPasswordProtector)
})

test('Test Elliptic Curve key store lock with new asymmetric protector', async t => {
  const keyPair = await generateSigningKeyPair(algorithms.ECDSA_ALGO)
  const service = SERVICES.storage
  const keyStore = await setupKeys(
    service,
    t.context.password,
    keyPair.privateKey,
    algorithms.ECDSA_ALGO,
    algorithms.ECDH_ALGO,
  )
  const newProtectorKeyPair = await generateEncryptionKeyPair(
    algorithms.RSA_OAEP_ALGO,
  )
  await lock(
    keyStore.keyContainers,
    t.context.password,
    PROTECTOR_TYPES.password,
    newProtectorKeyPair.publicKey,
    PROTECTOR_TYPES.asymmetric,
  )
  const hasPasswordProtector = keyStore.keyContainers.psk.keyProtectors.find(
    protector => protector.type === PROTECTOR_TYPES.password,
  )
  const hasAsymmetricProtector = keyStore.keyContainers.psk.keyProtectors.find(
    protector => protector.type === PROTECTOR_TYPES.password,
  )
  t.assert(hasPasswordProtector && hasAsymmetricProtector)
})
