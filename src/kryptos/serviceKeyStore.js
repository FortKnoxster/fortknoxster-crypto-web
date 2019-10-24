import { setupIdentityKeys, setupKeys, unlock, init } from './keystore'
import {
  ECDSA_ALGO,
  ECDH_ALGO,
  RSASSA_PKCS1_V1_5_ALGO,
  RSA_OAEP_ALGO,
} from './algorithms'
import { SERVICES, PROTECTOR_TYPES } from './constants'

const serviceKeyStore = {
  keyStores: null,
}

export function getPublicKey(service, type) {
  return serviceKeyStore.keyStores[service].keyContainers[type]
}

export function getPrivateKey(service, type) {
  return serviceKeyStore.keyStores[service][type].privateKey
}

export async function initKeyStores(keyStores, type) {
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

    const storageKeyStore = serviceKeyStores.find(
      keyStore => keyStore.id === SERVICES.storage,
    )

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
    if (!Object.isFrozen(serviceKeyStore)) {
      serviceKeyStore.keyStores = [
        ...serviceKeyStores,
        ...asymmetricKeyStores,
      ].reduce(
        (acc, keyStore) => Object.assign(acc, { [keyStore.id]: keyStore }),
        {},
      )
      Object.freeze(serviceKeyStore)
      Object.freeze(serviceKeyStore.keyStores)
    }
    return true
  } catch (e) {
    return Promise.reject(e)
  }
}

export async function unlockKeyStores(keyStores, password, type) {
  try {
    const serviceKeyStores = await Promise.all(
      Object.keys(keyStores).map(service => {
        const isPasswordProtector = keyStores[service].psk.keyProtectors.find(
          keyProtector => keyProtector.type === type,
        )
        if (isPasswordProtector)
          return unlock(service, keyStores[service], password, type)
        return {
          id: service,
          keyContainers: keyStores[service],
        }
      }),
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
  return setupIdentityKeys(SERVICES.identity, password, ECDSA_ALGO)
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
