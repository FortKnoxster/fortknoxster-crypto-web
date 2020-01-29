import test from 'ava'
import {
  encryptNewItemAssignment,
  decryptItemAssignment,
  encryptItem,
} from './storage'
import { setupKeys } from './keystore'
import { generateSigningKeyPair } from './keys'
import * as algorithms from './algorithms'
import * as utils from './utils'
import { PROTECTOR_TYPES, SERVICES } from './constants'
import { initKeyStores } from './serviceKeyStore'

// We need a storage keystore
test.before(async () => {
  const keyPair = await generateSigningKeyPair(algorithms.ECDSA_ALGO)
  const keyStore = await setupKeys(
    SERVICES.storage,
    'Pa$$w0rd!',
    keyPair.privateKey,
    algorithms.RSASSA_PKCS1_V1_5_ALGO,
    algorithms.RSA_OAEP_ALGO,
    PROTECTOR_TYPES.password,
  )
  await initKeyStores([keyStore])
})

test('Test encrypt new item assignment (encryptNewItemAssignment)', async t => {
  const itemData = { d: { a: 1, b: 2, c: 3 }, rid: '123' }
  const encryptedItem = await encryptNewItemAssignment(itemData)
  t.assert(encryptedItem)
})

test('Test encrypt new item (encryptItem)', async t => {
  const itemData = { d: { a: 1, b: 2, c: 3 } }
  const encryptedItem = await encryptItem(itemData)
  t.assert(encryptedItem)
})

test('Test encrypt new items (encryptItems)', async t => {
  const newItems = [
    { d: { a: 1, b: 2, c: 3 }, rid: '123' },
    { d: { a: 1, b: 2, c: 3 }, rid: '123' },
    { d: { a: 1, b: 2, c: 3 }, rid: '123' },
  ]
  const encryptedItems = await Promise.all(newItems.map(i => encryptItem(i)))
  t.assert(encryptedItems)
})

test('Test decrypt item assignment (decryptItemAssignment)', async t => {
  const itemData = { d: { a: 1, b: 2, c: 3 } }
  const encryptedItem = await encryptNewItemAssignment(itemData)
  const { m, iv, s, keys } = encryptedItem
  const metaData = { d: m, iv, s }
  const decryptedItem = await decryptItemAssignment(
    metaData,
    utils.arrayBufferToBase64(keys[0]),
  )
  t.assert(decryptedItem)
})
