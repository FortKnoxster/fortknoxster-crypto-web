import { KRYPTOS } from './legacy/kryptos.core'

export { deriveAccountPassword } from './kryptos/derive'
export { unlockKeyStores } from './kryptos/keyStore'
export {
  initProtocol,
  encryptProtocol,
  decryptProtocol,
} from './kryptos/protocol'
// LEGACY exports
// export { KRYPTOS as kryptos } from './legacy/kryptos.core'
export { KeyStore } from './legacy/kryptos.keystore'

KRYPTOS.check.support()
