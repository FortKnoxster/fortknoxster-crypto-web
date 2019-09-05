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
