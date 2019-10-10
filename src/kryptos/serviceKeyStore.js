import { KeyStore } from './core/kryptos.keystore'
import { setupIdentityKeys, setupKeys } from './keystore'
import {
  ECDSA_ALGO,
  ECDH_ALGO,
  RSASSA_PKCS1_V1_5_ALGO,
  RSA_OAEP_ALGO,
} from './algorithms'

export function unlockKeyStores(keys, password, type) {
  return Object.keys(keys).map(key =>
    new KeyStore(key, keys[key].pdk, keys[key].psk).unlock(
      password,
      keys[key].pek,
      keys[key].pvk,
      keys[key].signature,
      type,
    ),
  )
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

export function newKeyStore(service, mode) {
  return new KeyStore(service, null, null, mode)
}

export function newKeyStores(serviceKeys) {
  return serviceKeys.map(serviceKey =>
    newKeyStore(serviceKey.service, serviceKey.mode),
  )
}

export function setupKeyStore(
  service,
  protector,
  identityKeyStore,
  protectorType,
  rsa = true,
) {
  if (rsa) {
    return setupKeys(
      service,
      protector,
      identityKeyStore,
      RSASSA_PKCS1_V1_5_ALGO,
      RSA_OAEP_ALGO,
      protectorType,
    )
  }
  return setupKeys(
    service,
    protector,
    identityKeyStore,
    ECDSA_ALGO,
    ECDH_ALGO,
    protectorType,
  )
}
