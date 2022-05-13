/* eslint-disable max-lines */
import test from 'ava'
import { generateEncryptionKeyPair, getSessionKey } from './keys.js'
import * as algorithms from './algorithms.js'
import { PROTECTOR_TYPES } from './constants.js'
import { lockKeyContainer, unlockKeyContainer } from './keyContainer.js'
import { getSymmetricProtector } from './protector.js'
import { base64ToArrayBuffer } from './utils.js'

test.before(async (t) => {
  // eslint-disable-next-line no-param-reassign
  t.context = {
    wallet: {
      privateWallet:
        'fan stay program laundry type jump state clever cheap jump edge ring double hover smoke crush raise focus anxiety unit there tortoise actual until',
    },
    type: 'wallet',
    keyPair: await generateEncryptionKeyPair(algorithms.RSA_OAEP_ALGO_8K),
    key: 'Kb/qSxFwiD0oVwgpRzDMhLyb6mV9lHyfYt6er02P8gY=',
    itemKey: 'qeLWV3XRJINA4178BmMnvnZ8L3yeh/t7REsCS9YGy/s=',
  }
})

test('Test AES-GCM key lock key container with symmetric HKDF protector', async (t) => {
  const bufferedKey = base64ToArrayBuffer(t.context.key)
  const protectorKey = await getSymmetricProtector(bufferedKey)
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
  const protectorKey = await getSymmetricProtector(bufferedKey)
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
  const derivedKey = await getSymmetricProtector(bufferedKey)
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
  const protectorKey = await getSymmetricProtector(bufferedKey)
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
    t.context.keyPair.publicKey,
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
    t.context.keyPair.publicKey,
    t.context.type,
    t.context.wallet,
    PROTECTOR_TYPES.asymmetric,
  )

  const { privateKey: unlockedKeyContainer } = await unlockKeyContainer(
    keyContainer,
    t.context.keyPair.privateKey,
    PROTECTOR_TYPES.asymmetric,
  )

  t.assert(
    unlockedKeyContainer.privateWallet === t.context.wallet.privateWallet,
  )
})
