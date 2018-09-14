import { Encrypter } from '../legacy/kryptos.encrypter'
import { Decrypter } from '../legacy/kryptos.decrypter'
import { base64ToArrayBuffer, dummyCB, generateId } from './utils'

const storage = {
  keyStore: null,
  partSize: 4194304,
  owner: null,
  idLength: 32,
}

function fileItem(file) {
  const { partSize } = storage
  return {
    t: 'file', // type
    n: encodeURIComponent(file.name), // name
    c: new Date().getTime(), // created
    m: file.lastModified || new Date().getTime(), // modified
    s: file.size, // size
    mt: file.type, // mimetype
    ps: partSize, // partsize
    p: [], // parts
  }
}

function directoryItem(folder) {
  return {
    t: 'directory', // type
    n: encodeURIComponent(folder.name), // name
    c: new Date().getTime(), // created
    m: new Date().getTime(), // modified
    ch: [], // childs
  }
}

export function itemFromJson(data, decryptedData) {
  const { id, meta_data, reference_id: referenceId } = data
  const { json, key, plain } = decryptedData
  const metaData = JSON.parse(meta_data)
  return {
    ...metaData,
    id,
    referenceId,
    d: json || plain,
    key,
  }
}

export function createItem(item, type = 'file') {
  const { idLength, owner, partSize } = storage
  const isFile = type === 'file'
  return {
    s: null, // signature
    so: owner, // signature_owner (username)
    iv: null,
    v: 1, // version
    referenceId: generateId(idLength),
    partCount: isFile ? Math.ceil(item.size / partSize) : 0,
    d: isFile ? fileItem(item) : directoryItem(item),
  }
}

export function childItem(item, key) {
  const { id, reference_id: rid, type } = item
  return { id, key, rid, type }
}

export function addStoragePublicKeys(publicKeys) {
  storage.keyStore.setPublicKeys(publicKeys)
}

export function initStorage(keyStore, owner) {
  storage.keyStore = keyStore
  storage.owner = owner
}

// return [Promise]
export function encryptItems(items) {
  const { keyStore } = storage
  return items.map(item => {
    const encrypter = new Encrypter(keyStore, item.d, null, dummyCB)
    return encrypter.encryptNewItem()
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
  return encrypter.encryptFilePart(filePart, itemId, partNo)
}

// TODO come up with better name,
// return Promise
export function setupStorage(item) {
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
