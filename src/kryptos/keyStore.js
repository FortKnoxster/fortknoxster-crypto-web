import { KeyStore } from '../legacy/kryptos.keystore'

export function unlockKeyStores(keys, password, type) {
  const json = typeof keys === 'object' ? keys : JSON.parse(keys)
  console.log('json', json)
  const promises = Object.keys(json).map(key =>
    new KeyStore(key, json[key].pdk, json[key].psk).unlock(
      password,
      json[key].pek,
      json[key].pvk,
      json[key].signature,
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
