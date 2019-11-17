import { getPrivateKey, getPublicKey } from './serviceKeyStore'
import { encryptSign } from './encrypter'
import { verifyDecrypt } from './decrypter'
import { generateSessionKey, unwrapKey } from './keys'
import { base64ToArrayBuffer, extractMessage } from './utils'
import { PSK, PVK, PDK, SERVICES } from './constants'
import { AES_CBC_ALGO } from './algorithms'

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
    const rawKey = base64ToArrayBuffer(key)
    const privateKey = getPrivateKey(SERVICES.mail, PDK)
    const sessionKey = await unwrapKey(rawKey, privateKey, AES_CBC_ALGO)
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
    message.m,
    sessionKey,
    message.iv,
    message.s,
    publicKey || getPublicKey(SERVICES.mail, PVK),
  )
}

export async function decryptMessage(message, publicKey) {
  try {
    const { encryptedKey, iv, cipherText, signature } = extractMessage(
      base64ToArrayBuffer(message),
    )
    const privateKey = getPrivateKey(SERVICES.mail, PDK)
    const sessionKey = await unwrapKey(encryptedKey, privateKey, AES_CBC_ALGO)
    return verifyDecrypt(
      cipherText,
      sessionKey,
      iv,
      signature,
      publicKey || getPublicKey(SERVICES.mail, PVK),
    )
  } catch (error) {
    return Promise.reject(error)
  }
}
