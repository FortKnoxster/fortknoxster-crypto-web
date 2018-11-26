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
  return encrypter.encryptExistingItem(
    base64ToArrayBuffer(item.key),
    new Uint8Array(base64ToArrayBuffer(item.iv)),
  )
}

export function encryptFilePart(filePart, partNo, itemId) {
  const { keyStore } = storage
  const encrypter = new Encrypter(keyStore, null, null, null)
  return encrypter.encryptFilePart(filePart, itemId, partNo, dummyCB)
}

export function encryptNewItemAssignment(item) {
  const { keyStore } = storage
  const encrypter = new Encrypter(keyStore, item.d, null, dummyCB)
  return encrypter.encryptNewItemAssignment()
}

export function encryptItemAssignment(item, usernames) {
  const { keyStore } = storage
  const encrypter = new Encrypter(keyStore, '', usernames, dummyCB)
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
    null,
    null,
    null,
    dummyCB,
  )
  return decrypter.decryptFilePart(itemId, p)
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
  return ch.reduce((array, child) => {
    const { id, key, rid } = child
    const item = items.find(obj => obj.reference_id === rid)
    if (item) {
      array.push(decryptItem(id, rid, key, JSON.parse(item.meta_data)))
    }
    return array
  }, [])
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
