import { KeyStore } from './core/kryptos.keystore'
import { setupIdentityKeys } from './keystore'
import { ECDSA_ALGO } from './algorithms'

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
  // Todo: implement new from /core/keystore
  return setupIdentityKeys(password, ECDSA_ALGO)
  // return key.setupSignKeys(password)
}

export function newKeyStore(service, mode) {
  return new KeyStore(service, null, null, mode)
}

export function newKeyStores(serviceKeys) {
  return serviceKeys.map(serviceKey =>
    newKeyStore(serviceKey.service, serviceKey.mode),
  )
}

export function setupKeys(keys, password, identityKeyStore) {
  return keys.map(key => key.setupKeys(password, identityKeyStore))
}
