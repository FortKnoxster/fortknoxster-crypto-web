import { kryptos } from './kryptos'
import { stringToArrayBuffer, arrayBufferToHex, randomValue } from './utils'
import {
  AES_KW_ALGO,
  AES_GCM_ALGO,
  PBKDF2,
  HKDF,
  ECDH_ALGO,
  deriveKeyPBKDF2,
  deriveKeyHKDF,
} from './algorithms'
import { DERIVE, WRAP, ENCRYPT } from './usages'
import { RAW } from './formats'
import { EXTRACTABLE, NONEXTRACTABLE, LENGTH_32 } from './constants'

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
    return Promise.reject(e)
  }
}

export async function deriveKeyFromPassword(
  password,
  salt,
  iterations,
  extractable = EXTRACTABLE,
) {
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
      extractable,
      WRAP,
    )
  } catch (e) {
    return Promise.reject(e)
  }
}

export async function deriveSessionKeyFromPassword(password, salt, iterations) {
  try {
    const bufferedPassword = stringToArrayBuffer(password)

    const bufferedSalt = stringToArrayBuffer(salt)

    const key = await kryptos.subtle.importKey(
      RAW,
      bufferedPassword,
      PBKDF2,
      NONEXTRACTABLE,
      DERIVE,
    )
    return kryptos.subtle.deriveKey(
      deriveKeyPBKDF2(bufferedSalt, iterations),
      key,
      AES_GCM_ALGO,
      NONEXTRACTABLE,
      ENCRYPT,
    )
  } catch (e) {
    return Promise.reject(e)
  }
}

export function deriveSessionKey(algorithm, privateKey, publicKey) {
  return kryptos.subtle.deriveKey(
    {
      name: ECDH_ALGO.name,
      namedCurve: ECDH_ALGO.namedCurve,
      public: publicKey,
    },
    privateKey,
    algorithm,
    NONEXTRACTABLE,
    ENCRYPT,
  )
}

export async function deriveSessionKeyFromMasterKey(
  masterKey,
  extractable = EXTRACTABLE,
) {
  try {
    const bufferedKey = stringToArrayBuffer(masterKey)

    const bufferedSalt = randomValue(LENGTH_32)

    const key = await kryptos.subtle.importKey(
      RAW,
      bufferedKey,
      HKDF,
      NONEXTRACTABLE,
      DERIVE,
    )
    return kryptos.subtle.deriveKey(
      deriveKeyHKDF(bufferedSalt),
      key,
      AES_GCM_ALGO,
      extractable,
      ENCRYPT,
    )
  } catch (e) {
    return Promise.reject(e)
  }
}
