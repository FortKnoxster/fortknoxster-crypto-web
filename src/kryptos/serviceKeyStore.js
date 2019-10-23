import { setupIdentityKeys, setupKeys, unlock, init } from './keystore'
import {
  ECDSA_ALGO,
  ECDH_ALGO,
  RSASSA_PKCS1_V1_5_ALGO,
  RSA_OAEP_ALGO,
} from './algorithms'
import { SERVICES, PROTECTOR_TYPES } from './constants'
import { initIdentity } from './identity'
import { initStorage } from './storage'
import { initProtocol } from './protocol'
import { initChat } from './chat'

const serviceKeyStore = {
  keyStores: null,
}

export async function initKeyStores(keyStores, type, nodeId, userId) {
  try {
    const serviceKeyStores = await Promise.all(
      keyStores
        .filter(keyStore =>
          keyStore.keyContainers.psk.keyProtectors.find(
            keyProtector => keyProtector.type === PROTECTOR_TYPES.password,
          ),
        )
        .map(keyStore => init(keyStore.id, keyStore, type)),
    )
    await initIdentity(
      serviceKeyStores.find(keyStore => keyStore.id === SERVICES.identity),
      userId,
    )
    initProtocol(
      serviceKeyStores.find(keyStore => keyStore.id === SERVICES.protocol),
      nodeId,
      userId,
    )
    const storageKeyStore = serviceKeyStores.find(
      keyStore => keyStore.id === SERVICES.storage,
    )
    initStorage(storageKeyStore)
    initChat(serviceKeyStores.find(keyStore => keyStore.id === SERVICES.mail))

    const asymmetricKeyStores = await Promise.all(
      keyStores
        .filter(keyStore =>
          keyStore.keyContainers.psk.keyProtectors.find(
            keyProtector =>
              keyProtector.type === PROTECTOR_TYPES.asymmetric &&
              keyProtector.type !== PROTECTOR_TYPES.password,
          ),
        )
        .map(keyStore =>
          unlock(
            keyStore.id,
            keyStore.keyContainers,
            storageKeyStore.pdk.privateKey,
            PROTECTOR_TYPES.asymmetric,
          ),
        ),
    )
    // Todo: keep company keystore here or in separate file like other service key stores?
    serviceKeyStore.keyStores = asymmetricKeyStores
    Object.freeze(serviceKeyStore)
    return true
  } catch (e) {
    return Promise.reject(e)
  }
}

export async function unlockKeyStores(keyStores, password, type) {
  try {
    const serviceKeyStores = await Promise.all(
      Object.keys(keyStores)
        .filter(service =>
          keyStores[service].psk.keyProtectors.find(
            keyProtector => keyProtector.type === type,
          ),
        )
        .map(service => unlock(service, keyStores[service], password, type)),
    )
    return serviceKeyStores
  } catch (e) {
    return Promise.reject(e)
  }
}

export function lockKeyStores(keys, password, type) {
  return Object.values(keys).map(k => k.lock(password, type))
}

export function verifyKeyProtector(keys, password, type) {
  const promises = Object.values(keys).map(k =>
    k.verifyProtector(password, type),
  )
  return Promise.all(promises)
}

export function generateIdentityKeys(password) {
  return setupIdentityKeys('identity', password, ECDSA_ALGO)
}

export function setupKeyStore(
  service,
  protector,
  identityKeyStore,
  protectorType,
  rsa = true,
  protectorIdentifier,
) {
  if (rsa) {
    return setupKeys(
      service,
      protector,
      identityKeyStore,
      RSASSA_PKCS1_V1_5_ALGO,
      RSA_OAEP_ALGO,
      protectorType,
      protectorIdentifier,
    )
  }
  return setupKeys(
    service,
    protector,
    identityKeyStore,
    ECDSA_ALGO,
    ECDH_ALGO,
    protectorType,
    protectorIdentifier,
  )
}
