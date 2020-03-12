import { setupIdentityKeys, setupKeys, unlock, init, lock } from './keystore'
import {
  ECDSA_ALGO,
  ECDH_ALGO,
  RSASSA_PKCS1_V1_5_ALGO,
  RSA_OAEP_ALGO,
} from './algorithms'
import { SERVICES, PROTECTOR_TYPES, PDK } from './constants'

const serviceKeyStore = {
  keyStores: null,
}

export function getPublicKey(service, type) {
  return serviceKeyStore.keyStores[service].keyContainers[type]
}

export function getPrivateKey(service, type) {
  return serviceKeyStore.keyStores[service][type].privateKey
}

export async function initKeyStores(
  keyStores,
  type = PROTECTOR_TYPES.password,
) {
  try {
    const serviceKeyStores = await Promise.all(
      keyStores
        .filter(keyStore =>
          keyStore.keyContainers.psk.keyProtectors.find(
            keyProtector => keyProtector.type === type,
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
              keyProtector.type !== PROTECTOR_TYPES.password &&
              keyProtector.type !== PROTECTOR_TYPES.recover,
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

    serviceKeyStore.keyStores = [
      ...serviceKeyStores,
      ...asymmetricKeyStores,
    ].reduce(
      (acc, keyStore) => Object.assign(acc, { [keyStore.id]: keyStore }),
      {},
    )
    return true
  } catch (e) {
    return Promise.reject(e)
  }
}

export function getKeyStores(services) {
  return services
    .map(service => serviceKeyStore.keyStores[service])
    .reduce(
      (acc, keyStore) =>
        Object.assign(acc, { [keyStore.id]: keyStore.keyContainers }),
      {},
    )
}

export function freezeKeyStores() {
  if (!Object.isFrozen(serviceKeyStore)) {
    Object.freeze(serviceKeyStore)
    Object.freeze(serviceKeyStore.keyStores)
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

// Not used yet, but can support asymmetric unlock of keystores without a password protector.
export async function unlockAsymmetricKeyStores(keyStores, serviceName) {
  try {
    const privateKey = getPrivateKey(serviceName, PDK)
    const serviceKeyStores = await Promise.all(
      Object.keys(keyStores).map(service =>
        unlock(
          service,
          keyStores[service],
          privateKey,
          PROTECTOR_TYPES.asymmetric,
        ),
      ),
    )
    return serviceKeyStores
  } catch (e) {
    return Promise.reject(e)
  }
}

export async function lockKeyStores(
  keyStores,
  protector,
  type,
  newProtector,
  newType,
  protectorIdentifier,
) {
  try {
    const promises = Object.keys(keyStores).map(service =>
      lock(
        service,
        keyStores[service],
        protector,
        type,
        newProtector,
        newType,
        protectorIdentifier,
      ),
    )
    const serviceKeyStores = await Promise.all(promises)
    return serviceKeyStores.reduce(
      (acc, keyStore) =>
        Object.assign(acc, { [keyStore.id]: keyStore.keyContainers }),
      {},
    )
  } catch (e) {
    return Promise.reject(e)
  }
}

// Lock asymmetric protected keystores with a new protector
export function lockAsymmetricKeyStores(
  keyStores,
  serviceName,
  newProtector,
  newType,
  protectorIdentifier,
) {
  const privateKey = getPrivateKey(serviceName, PDK)
  return lockKeyStores(
    keyStores,
    privateKey,
    PROTECTOR_TYPES.asymmetric,
    newProtector,
    newType,
    protectorIdentifier,
  )
}

export async function lockKeyStore(
  service,
  protector,
  type,
  protectorIdentifier,
) {
  return lock(
    service,
    serviceKeyStore.keyStores[service].keyContainers,
    getPrivateKey(SERVICES.storage, PDK),
    type,
    protector,
    type,
    protectorIdentifier,
  )
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
