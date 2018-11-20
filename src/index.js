import { KRYPTOS } from './legacy/kryptos.core'

export { deriveAccountPassword } from './kryptos/derive'
export { unlockKeyStores } from './kryptos/keyStore'
export { generateId, blobToDataUrl, dataUrlToBlob } from './kryptos/utils'
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
  encryptNewItemAssignment,
  encryptItems,
  encryptExistingItem,
  encryptFilePart,
  decryptFilePart,
  decryptItemAssignment,
  decryptItem,
  decryptChildItems,
} from './kryptos/storage'

// LEGACY exports
export { KeyStore } from './legacy/kryptos.keystore'

KRYPTOS.check.support()
