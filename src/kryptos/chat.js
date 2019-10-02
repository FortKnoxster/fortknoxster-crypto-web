import { Encrypter } from './core/kryptos.encrypter'
import { Decrypter } from './core/kryptos.decrypter'
import { base64ToArrayBuffer } from './utils'

const chat = {
  keyStore: null,
}

export function initChat(keyStore) {
  chat.keyStore = keyStore
}

export function encryptChatMessage(plainText, recipients) {
  const { keyStore } = chat
  const encrypter = new Encrypter(keyStore, plainText, recipients)
  return encrypter.encryptChatMessage()
}

export function decryptItem(id, rid, key, metaData, publicKey) {
  const { keyStore } = chat
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
