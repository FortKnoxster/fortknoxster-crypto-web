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
  encryptItemAssignment,
  encryptNewItemAssignment,
  encryptItems,
  encryptExistingItem,
  encryptFilePart,
  decryptFilePart,
  decryptItemAssignment,
  decryptItem,
  decryptChildItems,
} from './kryptos/storage'

export { initIdentity, verifyContactKeys } from './kryptos/identity'
// LEGACY exports
export { KeyStore } from './legacy/kryptos.keystore'

KRYPTOS.check.support()
