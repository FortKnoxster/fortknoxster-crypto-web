import { KeyStore } from '../legacy/kryptos.keystore'

export function unlockKeyStores(keys, password, type) {
  const promises = Object.keys(keys).map(key =>
    new KeyStore(key, keys[key].pdk, keys[key].psk).unlock(
      password,
      keys[key].pek,
      keys[key].pvk,
      keys[key].signature,
      type,
    ),
  )
  return Promise.all(promises)
}

export function lockKeyStores(keys, password, type) {
  const promises = Object.values(keys).map(k => k.lock(password, type))
  return Promise.all(promises)
}

export function verifyKeyProtector(keys, password, type) {
  const promises = Object.values(keys).map(k =>
    k.verifyProtector(password, type),
  )
  return Promise.all(promises)
}

export function generateSignKeys(key, password, mode) {
  return key.setupSignKeys(password, mode)
}

export function newKeyStore(service) {
  return new KeyStore(service, null, null)
}

export function setupKeys(service, password, mode, identityKeyStore) {
  return new KeyStore(service, null, null).setupKeys(
    password,
    mode,
    identityKeyStore,
  )
}

export function setupMultipleKeys(serviceKeys, password, identityKeyStore) {
  const promises = serviceKeys.map(serviceKey =>
    setupKeys(serviceKey.service, password, serviceKey.mode, identityKeyStore),
  )
  return Promise.all(promises)
}
