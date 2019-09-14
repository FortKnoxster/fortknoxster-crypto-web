export { initKryptos } from './kryptos/kryptos'
export { deriveAccountPassword } from './kryptos/derive'
export { PROTECTOR_TYPES, SERVICES, SERVICE_MODES } from './kryptos/constants'
export {
  newKeyStore,
  newKeyStores,
  setupKeys,
  generateSignKeys,
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
  createIdentity,
  initIdentity,
  signContact,
  verifyContactKeys,
  verifyContact,
} from './kryptos/identity'
// LEGACY exports
export { KeyStore } from './kryptos/core/kryptos.keystore'
