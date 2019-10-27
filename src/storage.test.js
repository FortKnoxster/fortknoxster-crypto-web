import test from 'ava'
import {
  encryptNewItemAssignment,
  decryptItemAssignment,
  encryptItem,
  encryptItems,
} from './kryptos/storage'
import { setupKeys } from './kryptos/keystore'
import { generateSigningKeyPair } from './kryptos/keys'
import * as algorithms from './kryptos/algorithms'
import { PROTECTOR_TYPES, SERVICES } from './kryptos/constants'
import { initKeyStores } from './kryptos/serviceKeyStore'

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
  const encryptedItems = await Promise.all(encryptItems(newItems))
  t.assert(encryptedItems)
})

test('Test decrypt item assignment (decryptItemAssignment)', async t => {
  const newItem = { d: { a: 1, b: 2, c: 3 } }
  const item = {
    item: {
      // eslint-disable-next-line camelcase
      meta_data: '',
    },
    // eslint-disable-next-line camelcase
    item_key: '',
  }
  const encryptedItem = await encryptNewItemAssignment(newItem)
  const { s, iv, d, key } = encryptedItem
  // eslint-disable-next-line camelcase
  item.item.meta_data = JSON.stringify({ s, so: 'test', iv, v: 1, d })
  // eslint-disable-next-line camelcase
  item.item_key = key
  const decryptedItem = await decryptItemAssignment(item)
  t.assert(decryptedItem)
})
