import { getPrivateKey } from './serviceKeyStore'
import { encryptSign } from './encrypter'
import { decryptSessionKey } from './decrypter'
import { generateSessionKey, unwrapKey, getSessionKey } from './keys'
import { base64ToArrayBuffer } from './utils'
import { PSK, PDK, SERVICES } from './constants'
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
