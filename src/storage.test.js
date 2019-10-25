import test from 'ava'
import { encryptNewItemAssignment } from './kryptos/storage'
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
  const itemData = { a: 1, b: 2, c: 3 }
  const encryptedItem = await encryptNewItemAssignment(itemData)
  t.assert(encryptedItem)
})
