/* eslint-disable max-lines */
import test from 'ava'
import { generateEncryptionKeyPair } from './keys.js'
import * as algorithms from './algorithms.js'
import { PROTECTOR_TYPES } from './constants.js'
import { lockKeyContainer, unlockKeyContainer } from './keyContainer.js'

test.before(async (t) => {
  // eslint-disable-next-line no-param-reassign
  t.context = {
    wallet: {
      privateWallet:
        'fan stay program laundry type jump state clever cheap jump edge ring double hover smoke crush raise focus anxiety unit there tortoise actual until',
    },
    type: 'wallet',
    keyPair: await generateEncryptionKeyPair(algorithms.RSA_OAEP_ALGO_8K),
  }
})

test('Test wallet lock key container with asymmetric RSA 8K protector', async (t) => {
  const keyContainer = await lockKeyContainer(
    t.context.keyPair.publicKey,
    'wallet',
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
