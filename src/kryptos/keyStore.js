import { KeyStore } from '../legacy/kryptos.keystore'

export async function unlockKeyStores(keys, password) {
  const json = JSON.parse(keys)
  const keyStores = []
  const promises = Object.keys(json).map(key => {
    const keyStore = new KeyStore(key, json[key].pdk, json[key].psk)
    keyStores.push(keyStore)
    return keyStore.unlock(
      password,
      json[key].pek,
      json[key].pvk,
      json[key].signature,
    )
  })
  await Promise.all(promises)
  return keyStores
}
