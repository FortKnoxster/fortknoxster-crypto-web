/* eslint-disable max-lines */
import test from 'ava'
import {
  generateEncryptionKeyPair,
  getSessionKey,
  generateWrapKey,
} from './keys.js'
import * as algorithms from './algorithms.js'
import { PROTECTOR_TYPES } from './constants.js'
import {
  lockKeyContainer,
  unlockKeyContainer,
  replaceOrAddProtector,
} from './keyContainer.js'
import {
  getSymmetricHkdfProtector,
  getProtector,
  getSymmetricAesGcmProtector,
} from './protector.js'
import { base64ToArrayBuffer, stringToArrayBuffer } from './utils.js'

test.before(async (t) => {
  // eslint-disable-next-line no-param-reassign
  t.context = {
    wallet: {
      privateWallet:
        'fan stay program laundry type jump state clever cheap jump edge ring double hover smoke crush raise focus anxiety unit there tortoise actual until',
    },
    type: 'wallet',
    keyPair8k: await generateEncryptionKeyPair(algorithms.RSA_OAEP_ALGO_8K),
    keyPair4k: await generateEncryptionKeyPair(algorithms.RSA_OAEP_ALGO_4K),
    key: 'Kb/qSxFwiD0oVwgpRzDMhLyb6mV9lHyfYt6er02P8gY=',
    itemKey: 'qeLWV3XRJINA4178BmMnvnZ8L3yeh/t7REsCS9YGy/s=',
    secretKey: await generateWrapKey(),
    lockKey: await generateWrapKey(),
  }
})

test('Test AES-GCM key lock key container with symmetric HKDF protector', async (t) => {
  const bufferedKey = base64ToArrayBuffer(t.context.key)
  const protectorKey = await getSymmetricHkdfProtector(bufferedKey)
  const sessionKey = await getSessionKey(
    algorithms.AES_GCM_ALGO,
    t.context.itemKey,
  )
  const keyContainer = await lockKeyContainer(
    protectorKey,
    algorithms.AES_GCM_256,
    sessionKey,
    PROTECTOR_TYPES.symmetric,
  )
  t.assert(
    keyContainer.encryptedKey &&
      keyContainer.protectType === 'AES-GCM-256' &&
      keyContainer.keyProtectors[0].type === 'symmetric' &&
      keyContainer.keyProtectors[0].name === 'HKDF' &&
      keyContainer.keyProtectors[0].hash === 'SHA-256',
  )
})

test('Test AES-GCM key lock & unlock key container with symmetric HKDF protector', async (t) => {
  const bufferedKey = base64ToArrayBuffer(t.context.key)
  const protectorKey = await getSymmetricHkdfProtector(bufferedKey)
  const sessionKey = await getSessionKey(
    algorithms.AES_GCM_ALGO,
    t.context.itemKey,
  )
  const keyContainer = await lockKeyContainer(
    protectorKey,
    algorithms.AES_GCM_256,
    sessionKey,
    PROTECTOR_TYPES.symmetric,
  )
  const { privateKey: unlockedKeyContainer } = await unlockKeyContainer(
    keyContainer,
    protectorKey,
    PROTECTOR_TYPES.symmetric,
  )
  t.assert(
    unlockedKeyContainer &&
      unlockedKeyContainer.type === sessionKey.type &&
      unlockedKeyContainer.algorithm.name === sessionKey.algorithm.name,
  )
})

test('Test wallet lock key container with symmetric HKDF protector', async (t) => {
  const bufferedKey = base64ToArrayBuffer(t.context.key)
  const derivedKey = await getSymmetricHkdfProtector(bufferedKey)
  const keyContainer = await lockKeyContainer(
    derivedKey,
    algorithms.AES_GCM_256,
    t.context.wallet,
    PROTECTOR_TYPES.symmetric,
  )
  t.assert(
    keyContainer.encryptedKey &&
      keyContainer.protectType === 'AES-GCM-256' &&
      keyContainer.keyProtectors[0].type === 'symmetric' &&
      keyContainer.keyProtectors[0].name === 'HKDF' &&
      keyContainer.keyProtectors[0].hash === 'SHA-256',
  )
})

test('Test wallet lock & unlock key container with symmetric HKDF protector', async (t) => {
  const bufferedKey = base64ToArrayBuffer(t.context.key)
  const protectorKey = await getSymmetricHkdfProtector(bufferedKey)
  const keyContainer = await lockKeyContainer(
    protectorKey,
    t.context.type,
    t.context.wallet,
    PROTECTOR_TYPES.symmetric,
  )
  const { privateKey: unlockedKeyContainer } = await unlockKeyContainer(
    keyContainer,
    protectorKey,
    PROTECTOR_TYPES.symmetric,
  )
  t.assert(
    unlockedKeyContainer.privateWallet === t.context.wallet.privateWallet,
  )
})

test('Test wallet lock key container with asymmetric RSA 8K protector', async (t) => {
  const keyContainer = await lockKeyContainer(
    t.context.keyPair8k.publicKey,
    t.context.type,
    t.context.wallet,
    PROTECTOR_TYPES.asymmetric,
  )

  t.assert(
    keyContainer.encryptedKey &&
      keyContainer.protectType === 'AES-GCM-256' &&
      keyContainer.keyProtectors[0].type === 'asymmetric' &&
      keyContainer.keyProtectors[0].name === 'RSA-OAEP' &&
      keyContainer.keyProtectors[0].hash === 'SHA-256',
  )
})

test('Test wallet lock & unlock key container with asymmetric RSA 8K protector', async (t) => {
  const keyContainer = await lockKeyContainer(
    t.context.keyPair8k.publicKey,
    t.context.type,
    t.context.wallet,
    PROTECTOR_TYPES.asymmetric,
  )

  const { privateKey: unlockedKeyContainer } = await unlockKeyContainer(
    keyContainer,
    t.context.keyPair8k.privateKey,
    PROTECTOR_TYPES.asymmetric,
  )

  t.assert(
    unlockedKeyContainer.privateWallet === t.context.wallet.privateWallet,
  )
})

test('Test wallet lock key container with asymmetric RSA 8K protector and new symmetric HKDF protector', async (t) => {
  const keyContainer = await lockKeyContainer(
    t.context.keyPair8k.publicKey,
    t.context.type,
    t.context.wallet,
    PROTECTOR_TYPES.asymmetric,
  )
  const protector = await getProtector(t.context.keyPair8k.privateKey)

  const bufferedKey = base64ToArrayBuffer(t.context.key)
  const newProtector = await getSymmetricHkdfProtector(bufferedKey)

  const { wallet: newKeyContainer } = await replaceOrAddProtector(
    t.context.type,
    keyContainer,
    protector,
    keyContainer.keyProtectors[0],
    newProtector,
    PROTECTOR_TYPES.symmetric,
  )

  t.assert(
    newKeyContainer.encryptedKey &&
      newKeyContainer.protectType === 'AES-GCM-256' &&
      newKeyContainer.keyProtectors[0].type === 'asymmetric' &&
      newKeyContainer.keyProtectors[0].name === 'RSA-OAEP' &&
      newKeyContainer.keyProtectors[0].hash === 'SHA-256' &&
      newKeyContainer.keyProtectors[1].type === 'symmetric' &&
      newKeyContainer.keyProtectors[1].name === 'HKDF' &&
      newKeyContainer.keyProtectors[1].hash === 'SHA-256',
  )
})

test('Test wallet lock & unlock key container with asymmetric RSA 8K protector and new symmetric HKDF protector', async (t) => {
  const keyContainer = await lockKeyContainer(
    t.context.keyPair8k.publicKey,
    t.context.type,
    t.context.wallet,
    PROTECTOR_TYPES.asymmetric,
  )
  const protector = await getProtector(t.context.keyPair8k.privateKey)

  const bufferedKey = base64ToArrayBuffer(t.context.key)
  const newProtector = await getSymmetricHkdfProtector(bufferedKey)

  const { wallet: newKeyContainer } = await replaceOrAddProtector(
    t.context.type,
    keyContainer,
    protector,
    keyContainer.keyProtectors[0],
    newProtector,
    PROTECTOR_TYPES.symmetric,
  )

  const { privateKey: unlockedKeyContainer } = await unlockKeyContainer(
    newKeyContainer,
    t.context.keyPair8k.privateKey,
    PROTECTOR_TYPES.asymmetric,
  )

  const { privateKey: symmetricUnlockedKeyContainer } =
    await unlockKeyContainer(
      newKeyContainer,
      newProtector,
      PROTECTOR_TYPES.symmetric,
    )
  t.assert(
    unlockedKeyContainer.privateWallet === t.context.wallet.privateWallet &&
      symmetricUnlockedKeyContainer.privateWallet ===
        t.context.wallet.privateWallet,
  )
})

test('Test AES-GCM key lock key container with symmetric AES-GCM protector', async (t) => {
  const protectorKey = await getSymmetricAesGcmProtector(t.context.lockKey)
  const keyContainer = await lockKeyContainer(
    protectorKey,
    algorithms.AES_GCM_256,
    t.context.secretKey, // CryptoKey
    PROTECTOR_TYPES.symmetric,
  )
  t.assert(
    keyContainer.encryptedKey &&
      keyContainer.protectType === 'AES-GCM-256' &&
      keyContainer.keyProtectors[0].type === 'symmetric' &&
      keyContainer.keyProtectors[0].name === 'AES-GCM' &&
      keyContainer.keyProtectors[0].iv,
  )
})

test('Test AES-GCM key lock & unlock key container with symmetric AES-GCM protector', async (t) => {
  const protectorKey = await getSymmetricAesGcmProtector(t.context.lockKey)
  const keyContainer = await lockKeyContainer(
    protectorKey,
    algorithms.AES_GCM_256,
    t.context.secretKey, // CryptoKey
    PROTECTOR_TYPES.symmetric,
  )
  const { privateKey: unlockedKeyContainer } = await unlockKeyContainer(
    keyContainer,
    protectorKey,
    PROTECTOR_TYPES.symmetric,
  )
  t.assert(
    unlockedKeyContainer &&
      unlockedKeyContainer.type === t.context.secretKey.type &&
      unlockedKeyContainer.algorithm.name ===
        t.context.secretKey.algorithm.name,
  )
})

test('Test AES-GCM key lock & unlock key container with symmetric AES-GCM protector with AAD additional authenticated data', async (t) => {
  const additionalData = stringToArrayBuffer('identityHash')
  const protectorKey = await getSymmetricAesGcmProtector(
    t.context.lockKey,
    null,
    additionalData,
  )
  const keyContainer = await lockKeyContainer(
    protectorKey,
    algorithms.AES_GCM_256,
    t.context.secretKey, // CryptoKey
    PROTECTOR_TYPES.symmetric,
  )
  const { privateKey: unlockedKeyContainer } = await unlockKeyContainer(
    keyContainer,
    protectorKey,
    PROTECTOR_TYPES.symmetric,
  )
  t.assert(
    unlockedKeyContainer &&
      unlockedKeyContainer.type === t.context.secretKey.type &&
      unlockedKeyContainer.algorithm.name ===
        t.context.secretKey.algorithm.name,
  )
})

test('Test AES-GCM key lock & unlock key container with symmetric AES-GCM protector fails with incorrect AAD additional authenticated data', async (t) => {
  const additionalData = stringToArrayBuffer('identityHash')
  const protectorKey = await getSymmetricAesGcmProtector(
    t.context.lockKey,
    null,
    additionalData,
  )
  const keyContainer = await lockKeyContainer(
    protectorKey,
    algorithms.AES_GCM_256,
    t.context.secretKey, // CryptoKey
    PROTECTOR_TYPES.symmetric,
  )

  const additionalData2 = stringToArrayBuffer('identityHashMissMatch')
  const protectorKeyRecreated = await getSymmetricAesGcmProtector(
    t.context.lockKey,
    null,
    additionalData2,
  )

  const promise = unlockKeyContainer(
    keyContainer,
    protectorKeyRecreated,
    PROTECTOR_TYPES.symmetric,
  )

  const error = await t.throwsAsync(promise)
  t.is(error.message, 'Unsupported state or unable to authenticate data')
})

test('Test wallet lock key container with asymmetric RSA 4K protector and new symmetric AES-GCM protector', async (t) => {
  const keyContainer = await lockKeyContainer(
    t.context.keyPair4k.publicKey,
    t.context.type,
    t.context.wallet,
    PROTECTOR_TYPES.asymmetric,
  )
  const protector = await getProtector(t.context.keyPair4k.privateKey)

  const newProtector = await getSymmetricAesGcmProtector(t.context.lockKey)

  const { wallet: newKeyContainer } = await replaceOrAddProtector(
    t.context.type,
    keyContainer,
    protector,
    keyContainer.keyProtectors[0],
    newProtector,
    PROTECTOR_TYPES.symmetric,
  )

  t.assert(
    newKeyContainer.encryptedKey &&
      newKeyContainer.protectType === 'AES-GCM-256' &&
      newKeyContainer.keyProtectors[0].type === 'asymmetric' &&
      newKeyContainer.keyProtectors[0].name === 'RSA-OAEP' &&
      newKeyContainer.keyProtectors[0].hash === 'SHA-256' &&
      newKeyContainer.keyProtectors[1].type === 'symmetric' &&
      newKeyContainer.keyProtectors[1].name === 'AES-GCM' &&
      newKeyContainer.keyProtectors[1].iv,
  )
})

test('Test wallet lock & unlock key container with asymmetric RSA 4K protector and new symmetric AES-GCM protector', async (t) => {
  const keyContainer = await lockKeyContainer(
    t.context.keyPair4k.publicKey,
    t.context.type,
    t.context.wallet,
    PROTECTOR_TYPES.asymmetric,
  )
  const protector = await getProtector(t.context.keyPair4k.privateKey)

  const newProtector = await getSymmetricAesGcmProtector(t.context.lockKey)

  const { wallet: newKeyContainer } = await replaceOrAddProtector(
    t.context.type,
    keyContainer,
    protector,
    keyContainer.keyProtectors[0],
    newProtector,
    PROTECTOR_TYPES.symmetric,
  )

  const { privateKey: unlockedKeyContainer } = await unlockKeyContainer(
    newKeyContainer,
    t.context.keyPair4k.privateKey,
    PROTECTOR_TYPES.asymmetric,
  )

  const { privateKey: symmetricUnlockedKeyContainer } =
    await unlockKeyContainer(
      newKeyContainer,
      newProtector,
      PROTECTOR_TYPES.symmetric,
    )
  t.assert(
    unlockedKeyContainer.privateWallet === t.context.wallet.privateWallet &&
      symmetricUnlockedKeyContainer.privateWallet ===
        t.context.wallet.privateWallet,
  )
})
