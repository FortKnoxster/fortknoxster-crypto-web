import { getPrivateKey, getPublicKey } from './serviceKeyStore'
import { encryptSign } from './encrypter'
import { decryptSessionKey, verifyDecrypt } from './decrypter'
import { generateSessionKey, unwrapKey, getSessionKey } from './keys'
import { base64ToArrayBuffer, arrayBufferToBase64 } from './utils'
import { PSK, PVK, PDK, SERVICES } from './constants'
import { AES_CBC_ALGO, AES_GCM_ALGO } from './algorithms'

export async function encryptChatMessage(plainText, publicKeys) {
  try {
    const sessionKey = await generateSessionKey(AES_CBC_ALGO)
    const privateKey = getPrivateKey(SERVICES.mail, PSK)
    const result = await encryptSign(
      plainText,
      sessionKey,
      privateKey,
      publicKeys,
    )
    const { iv, s, m, keys } = result
    const formattedKeys = keys.map(key => arrayBufferToBase64(key))
    return { iv, s, m, keys: formattedKeys }
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
    const rawKey = base64ToArrayBuffer(key)
    const privateKey = getPrivateKey(SERVICES.mail, PDK)
    const sessionKey = await unwrapKey(rawKey, privateKey, AES_CBC_ALGO)
    return verifyDecrypt(
      base64ToArrayBuffer(message.m),
      sessionKey,
      base64ToArrayBuffer(message.iv),
      base64ToArrayBuffer(message.s),
      publicKey || getPublicKey(SERVICES.mail, PVK),
    )
  } catch (error) {
    return Promise.reject(error)
  }
}

export function decryptGroupChatMessage(message, sessionKey, publicKey) {
  return verifyDecrypt(
    base64ToArrayBuffer(message.m),
    sessionKey,
    base64ToArrayBuffer(message.iv),
    base64ToArrayBuffer(message.s),
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
