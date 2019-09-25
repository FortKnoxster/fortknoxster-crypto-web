/* eslint-disable no-async-promise-executor */
import { encryptSign } from './core/encrypter'
import { generateSessionKey } from './core/keys'
import * as algorithms from './algorithms'

const chat = {
  keyStore: null,
}

export function initChat(keyStore) {
  chat.keyStore = keyStore
}

export function encryptChatMessage(plainText, publicKeys) {
  return new Promise(async (resolve, reject) => {
    const { keyStore } = chat
    try {
      const sessionKey = await generateSessionKey(algorithms.AES_CBC_ALGO)
      const privateKey = await keyStore.getPsk()
      const result = encryptSign(plainText, sessionKey, privateKey, publicKeys)
      resolve(result)
    } catch (error) {
      reject(error)
    }
  })
}

export function encryptGroupChatMessage(plainText, sessionKey) {
  return new Promise(async (resolve, reject) => {
    const { keyStore } = chat
    try {
      const privateKey = await keyStore.getPsk()
      const result = encryptSign(plainText, sessionKey, privateKey)
      resolve(result)
    } catch (error) {
      reject(error)
    }
  })
}
