import { KeyStore } from '../legacy/kryptos.keystore'

export function unlockKeyStores(keys, password) {
  const json = JSON.parse(keys)
  const promises = Object.keys(json).map(key =>
    new KeyStore(key, json[key].pdk, json[key].psk).unlock(
      password,
      json[key].pek,
      json[key].pvk,
      json[key].signature,
    ),
  )
  return Promise.all(promises)
}
