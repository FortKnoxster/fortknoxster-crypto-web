import { kryptos } from './kryptos.js'
import { stringToArrayBuffer, arrayBufferToHex, randomValue } from './utils.js'
import {
  AES_KW_ALGO,
  AES_GCM_ALGO,
  SHA_256,
  SHA_512,
  PBKDF2,
  HKDF,
  ECDH_ALGO,
  deriveKeyPBKDF2,
  deriveKeyHKDF,
} from './algorithms.js'
import {
  DERIVE,
  WRAP,
  ENCRYPT,
  DECRYPT_UNWRAP,
  ENCRYPT_WRAP,
} from './usages.js'
import { RAW } from './formats.js'
import {
  EXTRACTABLE,
  NONEXTRACTABLE,
  PROTECTOR_ITERATIONS,
  LENGTH_32,
} from './constants.js'

export async function deriveAccountPassword(
  username,
  password,
  domain,
  iterations = 50000,
  hash = SHA_256.name,
) {
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

    let length = 256
    if (hash === SHA_512.name) {
      length = 512
    }
    const derivedKey = await kryptos.subtle.deriveBits(
      deriveKeyPBKDF2(salt, iterations, hash),
      key,
      length,
    )

    return arrayBufferToHex(derivedKey)
  } catch (e) {
    return Promise.reject(e)
  }
}

// For password protector
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

// For symmetric protector
export async function deriveKeyFromSymmetric(
  bufferedKey,
  bufferedSalt,
  extractable = EXTRACTABLE,
) {
  try {
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

export async function deriveFromBufferedKey(
  bufferedKey,
  bufferedSalt,
  extractable = EXTRACTABLE,
) {
  try {
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
      DECRYPT_UNWRAP.concat(ENCRYPT_WRAP),
    )
  } catch (e) {
    return Promise.reject(e)
  }
}

export function deriveSessionKeyFromMasterKey(
  masterKey,
  extractable = EXTRACTABLE,
) {
  const bufferedKey = stringToArrayBuffer(masterKey)

  const bufferedSalt = randomValue(LENGTH_32)

  return deriveFromBufferedKey(bufferedKey, bufferedSalt, extractable)
}

export async function deriveSessionKeyWithInput(
  masterKey,
  input,
  extractable = EXTRACTABLE,
) {
  try {
    const bufferedKey = stringToArrayBuffer(masterKey)

    const bufferedSalt = randomValue(LENGTH_32)

    const iterations = PROTECTOR_ITERATIONS
    const derivedKey = await deriveKeyFromPassword(
      input,
      bufferedSalt,
      iterations,
    )

    const exportedKey = await kryptos.subtle.exportKey(RAW, derivedKey)

    return deriveFromBufferedKey(bufferedKey, exportedKey, extractable)
  } catch (e) {
    return Promise.reject(e)
  }
}
