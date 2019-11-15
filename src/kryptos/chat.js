import { getPrivateKey, getPublicKey } from './serviceKeyStore'
import { encryptSign } from './encrypter'
import { decryptSessionKey, verifyDecrypt } from './decrypter'
import { generateSessionKey, unwrapKey, getSessionKey } from './keys'
import { base64ToArrayBuffer } from './utils'
import { PSK, PVK, PDK, SERVICES } from './constants'
import { AES_CBC_ALGO, AES_GCM_ALGO } from './algorithms'

export async function encryptChatMessage(plainText, publicKeys) {
  try {
    const sessionKey = await generateSessionKey(AES_CBC_ALGO)
    const privateKey = getPrivateKey(SERVICES.mail, PSK)
    return encryptSign(plainText, sessionKey, privateKey, publicKeys)
  } catch (error) {
    return Promise.reject(error)
  }
}

export async function encryptGroupChatMessage(plainText, sessionKey) {
  try {
    const privateKey = getPrivateKey(SERVICES.mail, PSK)
    return encryptSign(plainText, sessionKey, privateKey)
  } catch (error) {
    return Promise.reject(error)
  }
}

export async function decryptChatMessage(message, key, publicKey) {
  try {
    const sessionKey = await getSessionKey(AES_CBC_ALGO, key)
    return verifyDecrypt(
      message.m,
      sessionKey,
      message.iv,
      message.s,
      publicKey || getPublicKey(SERVICES.mail, PVK),
    )
  } catch (error) {
    return Promise.reject(error)
  }
}

export function decryptGroupChatMessage(message, sessionKey, publicKey) {
  return verifyDecrypt(
    message.decryptChatMessage,
    sessionKey,
    message.iv,
    message.s,
    publicKey || getPublicKey(SERVICES.mail, PVK),
  )
}

export async function encryptGroupChatKey(key, publicKeys) {
  const sessionKey = await getSessionKey(AES_GCM_ALGO, key)
  return { sessionKey, publicKeys }
}

export function decryptGroupChatKey(key, raw) {
  try {
    const privateKey = getPrivateKey(SERVICES.mail, PDK)
    const rawKey = base64ToArrayBuffer(key)
    if (raw) {
      return decryptSessionKey(rawKey, privateKey)
    }
    return unwrapKey(rawKey, privateKey, AES_GCM_ALGO)
  } catch (error) {
    return Promise.reject(error)
  }
}
