import { Encrypter } from '../legacy/kryptos.encrypter'
import { Decrypter } from '../legacy/kryptos.decrypter'
import { base64ToArrayBuffer, dummyCB } from './utils'

const storage = {
  keyStore: null,
}

export function addStoragePublicKeys(publicKeys) {
  storage.keyStore.setPublicKeys(publicKeys)
}

export function initStorage(keyStore) {
  storage.keyStore = keyStore
}

// return [Promise]
export function encryptItems(items) {
  const { keyStore } = storage
  return items.map(item => {
    const encrypter = new Encrypter(keyStore, item.d, null, dummyCB)
    return encrypter.encryptNewItem(item.rid)
  })
}

export function encryptExistingItem(item) {
  const { keyStore } = storage
  const encrypter = new Encrypter(keyStore, item.d, null, dummyCB)
  return encrypter.encryptExistingItem(base64ToArrayBuffer(item.key))
}

export function encryptFilePart(filePart, partNo, itemId) {
  const { keyStore } = storage
  const encrypter = new Encrypter(keyStore, null, null, null)
  return encrypter.encryptFilePart(filePart, itemId, partNo, dummyCB)
}

// TODO come up with better name,
// return Promise
export function encryptNewItemAssignment(item) {
  const { keyStore } = storage
  const encrypter = new Encrypter(keyStore, item.d, null, dummyCB)
  return encrypter.encryptNewItemAssignment()
}

export function decryptItem(id, rid, key, metaData) {
  const { keyStore } = storage
  const decrypter = new Decrypter(
    keyStore,
    base64ToArrayBuffer(key),
    new Uint8Array(base64ToArrayBuffer(metaData.iv)),
    base64ToArrayBuffer(metaData.d),
    base64ToArrayBuffer(metaData.s),
    keyStore.getPvk(true),
    null,
    dummyCB,
  )
  return decrypter.decryptItem(id, rid)
}

export function decryptChildItems(items, parent) {
  const { ch } = parent.d
  return ch.map(child => {
    const { id, key, rid } = child
    const { meta_data } = items.find(item => item.reference_id === rid)
    const metaData = JSON.parse(meta_data)
    return decryptItem(id, rid, key, metaData)
  })
}

export function decryptItemAssignment(data) {
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
    keyStore.getPvk(true),
    null,
    dummyCB,
  )
  return decrypter.decryptItemAssignment()
}
