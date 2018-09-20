import { KRYPTOS } from './legacy/kryptos.core'

export { deriveAccountPassword } from './kryptos/derive'
export { unlockKeyStores } from './kryptos/keyStore'
export { generateId } from './kryptos/utils'
export {
  initProtocol,
  encryptProtocol,
  decryptProtocol,
} from './kryptos/protocol'

export {
  addStoragePublicKeys,
  initStorage,
  encryptNewItemAssignment,
  encryptItems,
  encryptExistingItem,
  encryptFilePart,
  decryptItemAssignment,
  decryptItem,
  decryptChildItems,
} from './kryptos/storage'

// LEGACY exports
export { KeyStore } from './legacy/kryptos.keystore'

KRYPTOS.check.support()
