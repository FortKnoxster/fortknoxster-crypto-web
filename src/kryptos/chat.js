/* eslint-disable no-async-promise-executor */
import { encryptSign } from './encrypter'
import { generateSessionKey } from './keys'
import * as algorithms from './algorithms'

const chat = {
  keyStore: null,
}

export function initChat(keyStore) {
  chat.keyStore = keyStore
}

export async function encryptChatMessage(plainText, publicKeys) {
  const { keyStore } = chat
  try {
    const sessionKey = await generateSessionKey(algorithms.AES_CBC_ALGO)
    const privateKey = await keyStore.getPsk()
    return encryptSign(plainText, sessionKey, privateKey, publicKeys)
  } catch (error) {
    return Promise.reject(error)
  }
}

export async function encryptGroupChatMessage(plainText, sessionKey) {
  const { keyStore } = chat
  try {
    const privateKey = await keyStore.getPsk()
    return encryptSign(plainText, sessionKey, privateKey)
  } catch (error) {
    return Promise.reject(error)
  }
}
