import { Encrypter } from './core/kryptos.encrypter'
import { Decrypter } from './core/kryptos.decrypter'
import { base64ToArrayBuffer } from './utils'

const storage = {
  keyStore: null,
}

export function addStoragePublicKeys(publicKeys) {
  storage.keyStore.setPublicKeys(publicKeys)
}

export function initStorage(keyStore) {
  storage.keyStore = keyStore
  Object.freeze(storage.keyStore)
  Object.freeze(storage)
}
/*
async function e() {
  const { keyStore } = storage
  try {
    const sessionKey = await generateSessionKey(algorithms.AES_CBC_ALGO)
    const privateKey = await keyStore.getPsk()
    return encryptSign(plainText, sessionKey, privateKey)
  } catch (error) {
    return Promise.reject(error)
  }
}
*/
export function encryptItems(items) {
  const { keyStore } = storage
  return items.map(item => {
    const encrypter = new Encrypter(keyStore, item.d, null)
    return encrypter.encryptNewItem(item.rid)
  })
}

export function encryptExistingItem(item) {
  const { keyStore } = storage
  const encrypter = new Encrypter(keyStore, item.d, null)
  return encrypter.encryptExistingItem(base64ToArrayBuffer(item.key))
}

export function encryptFilePart(filePart, partNo, itemId) {
  const { keyStore } = storage
  const encrypter = new Encrypter(keyStore, null, null, null)
  return encrypter.encryptFilePart(filePart, itemId, partNo)
}

export function encryptNewItemAssignment(item) {
  const { keyStore } = storage
  const encrypter = new Encrypter(keyStore, item.d, null)
  return encrypter.encryptNewItemAssignment()
}

export function encryptItemAssignment(item, usernames) {
  const { keyStore } = storage
  const encrypter = new Encrypter(keyStore, '', usernames)
  return encrypter.encryptItemAssignment(base64ToArrayBuffer(item.key))
}

export function decryptFilePart(itemId, partItem, filePart) {
  const { keyStore } = storage
  const { iv, k, p } = partItem
  const decrypter = new Decrypter(
    keyStore,
    base64ToArrayBuffer(k),
    base64ToArrayBuffer(iv),
    filePart,
  )
  return decrypter.decryptFilePart(itemId, p)
}

export function decryptItem(id, rid, key, metaData, publicKey) {
  const { keyStore } = storage
  const decrypter = new Decrypter(
    keyStore,
    base64ToArrayBuffer(key),
    new Uint8Array(base64ToArrayBuffer(metaData.iv)),
    base64ToArrayBuffer(metaData.d),
    base64ToArrayBuffer(metaData.s),
    publicKey || keyStore.getPvk(true),
  )
  return decrypter.decryptItem(id, rid)
}

export function decryptItemAssignment(data, publicKey) {
  const { keyStore } = storage
  const {
    item_key,
    item: { meta_data },
  } = data
  const metaData = JSON.parse(meta_data)
  const decrypter = new Decrypter(
    keyStore,
    base64ToArrayBuffer(item_key),
    new Uint8Array(base64ToArrayBuffer(metaData.iv)),
    base64ToArrayBuffer(metaData.d),
    base64ToArrayBuffer(metaData.s),
    publicKey || keyStore.getPvk(true),
  )
  return decrypter.decryptItemAssignment()
}
