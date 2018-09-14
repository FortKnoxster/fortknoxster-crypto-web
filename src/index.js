import { KRYPTOS } from './legacy/kryptos.core'

export { deriveAccountPassword } from './kryptos/derive'
export { unlockKeyStores } from './kryptos/keyStore'
export {
  initProtocol,
  encryptProtocol,
  decryptProtocol,
} from './kryptos/protocol'
export {
  addStoragePublicKeys,
  childItem,
  createItem,
  setupStorage,
  initStorage,
  encryptItems,
  encryptExistingItem,
  encryptFilePart,
  itemFromJson,
  decryptItemAssignment,
  decryptItem,
  decryptChildItems,
} from './kryptos/storage'

// LEGACY exports
export { KeyStore } from './legacy/kryptos.keystore'

KRYPTOS.check.support()
