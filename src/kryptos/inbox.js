import { getPrivateKey, getPublicKey } from './serviceKeyStore'
import { verifyDecrypt } from './decrypter'
import { unwrapKey } from './keys'
import { base64ToArrayBuffer, extractMessage } from './utils'
import { PVK, PDK, SERVICES } from './constants'
import { AES_CBC_ALGO } from './algorithms'

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
