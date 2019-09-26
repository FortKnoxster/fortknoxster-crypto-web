import { kryptos } from './kryptos'
import { stringToArrayBuffer, arrayBufferToHex } from './utils'
import { AES_KW_ALGO, PBKDF2, deriveKeyPBKDF2 } from './algorithms'
import { DERIVE, WRAP } from './usages'
import { RAW } from './formats'
import { EXTRACTABLE, NONEXTRACTABLE } from './constants'

export async function deriveAccountPassword(username, password, domain) {
  try {
    const salt = stringToArrayBuffer(`${username.toLowerCase()}@${domain}`)
    const bufferedPassword = stringToArrayBuffer(password)

    const key = await kryptos.subtle.importKey(
      RAW,
      bufferedPassword,
      PBKDF2,
      NONEXTRACTABLE,
      DERIVE,
    )
    const derivedKey = await kryptos.subtle.deriveKey(
      deriveKeyPBKDF2(salt),
      key,
      AES_KW_ALGO,
      EXTRACTABLE,
      WRAP,
    )
    const exportedKey = await kryptos.subtle.exportKey(RAW, derivedKey)

    return arrayBufferToHex(exportedKey)
  } catch (e) {
    return e
  }
}

export async function deriveKeyFromPassword(password, salt, iterations) {
  try {
    const bufferedPassword = stringToArrayBuffer(password)

    const key = await kryptos.subtle.importKey(
      RAW,
      bufferedPassword,
      PBKDF2,
      NONEXTRACTABLE,
      DERIVE,
    )
    return kryptos.subtle.deriveKey(
      deriveKeyPBKDF2(salt, iterations),
      key,
      AES_KW_ALGO,
      NONEXTRACTABLE,
      WRAP,
    )
  } catch (e) {
    return Promise.reject(e)
  }
}
