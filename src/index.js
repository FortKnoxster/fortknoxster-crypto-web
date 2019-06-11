import { KRYPTOS } from './legacy/kryptos.core'

export { deriveAccountPassword } from './kryptos/derive'
export {
  unlockKeyStores,
  lockKeyStores,
  verifyKeyProtector,
} from './kryptos/keyStore'
export {
  generateId,
  blobToDataUrl,
  dataUrlToBlob,
  randomString,
} from './kryptos/utils'
export {
  initProtocol,
  encryptProtocol,
  decryptProtocol,
  generalSettingsType,
  requestEmailChangeType,
  confirmEmailChangeType,
  requestPhoneChangeType,
  confirmPhoneChangeType,
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
} from './kryptos/storage'

export {
  initIdentity,
  signContact,
  verifyContactKeys,
  verifyContact,
} from './kryptos/identity'
// LEGACY exports
export { KeyStore } from './legacy/kryptos.keystore'

KRYPTOS.check.support()
