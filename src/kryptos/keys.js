/* eslint-disable max-lines */
/**
 * Copyright 2020 FortKnoxster Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @name Kryptos
 * @file keys.js
 * @copyright Copyright © FortKnoxster Ltd. 2020.
 * @license Apache License, Version 2.0 http://www.apache.org/licenses/LICENSE-2.0
 * @author Mickey Johnnysson <mj@fortknoxster.com>
 * @author Christian Zwergius <cz@fortknoxster.com>
 * @version 2.0
 * @description Kryptos is a cryptographic library wrapping and implementing the
 * Web Cryptography API. Kryptos supports symmetric keys and asymmetric key pair
 * generation, key derivation, key wrap/unwrap, encryption, decryption, signing and verification.
 */
import { kryptos } from './kryptos.js'
import * as algorithms from './algorithms.js'
import * as formats from './formats.js'
import * as usage from './usages.js'
import {
  base64ToArrayBuffer,
  arrayBufferToObject,
  publicPemToDerArrayBuffer,
  privatePemToDerArrayBuffer,
} from './utils.js'
import { NONEXTRACTABLE, EXTRACTABLE } from './constants.js'

export function importSessionKey(keyBytes, algorithm) {
  return kryptos.subtle.importKey(
    formats.RAW,
    keyBytes,
    algorithm || algorithms.AES_CBC_ALGO,
    EXTRACTABLE,
    usage.ENCRYPT,
  )
}

export function importEncryptionKey(keyBytes, algorithm) {
  return kryptos.subtle.importKey(
    formats.RAW,
    keyBytes,
    algorithm || algorithms.AES_CBC_ALGO,
    NONEXTRACTABLE,
    usage.ENCRYPT,
  )
}

export function importWrapKey(key) {
  const algorithm = algorithms.getAlgorithm(key.alg)
  return kryptos.subtle.importKey(
    formats.JWK,
    key,
    algorithm,
    EXTRACTABLE,
    key.key_ops,
  )
}

export function importPublicVerifyKey(publicKey) {
  const clonedPublicKey = { ...publicKey }
  if (clonedPublicKey.kty === algorithms.EC) {
    const algorithm = algorithms.getAlgorithm(algorithms.ECDSA_ALGO.name)
    delete clonedPublicKey.alg
    return kryptos.subtle.importKey(
      formats.JWK,
      clonedPublicKey,
      algorithm,
      NONEXTRACTABLE,
      usage.VERIFY_ONLY,
    )
  }
  const algorithm = algorithms.getAlgorithm(publicKey.alg)
  return kryptos.subtle.importKey(
    formats.JWK,
    publicKey,
    algorithm,
    NONEXTRACTABLE,
    usage.VERIFY_ONLY,
  )
}

export function importPublicEncryptKey(publicKey, usages) {
  const clonedPublicKey = { ...publicKey }
  if (clonedPublicKey.kty === algorithms.EC) {
    const algorithm = algorithms.getAlgorithm(algorithms.ECDH_ALGO.name)
    delete clonedPublicKey.alg
    delete clonedPublicKey.key_ops
    return kryptos.subtle.importKey(
      formats.JWK,
      clonedPublicKey,
      algorithm,
      NONEXTRACTABLE,
      usages || usage.ENCRYPT_ONLY, // EC import key requires []
    )
  }
  const algorithm = algorithms.getAlgorithm(publicKey.alg)
  return kryptos.subtle.importKey(
    formats.JWK,
    publicKey,
    algorithm,
    NONEXTRACTABLE,
    usage.ENCRYPT_ONLY,
  )
}

export function importPublicKeyPem(publicKey, algorithm = algorithms.RSA_OAEP) {
  return kryptos.subtle.importKey(
    formats.SPKI,
    publicPemToDerArrayBuffer(publicKey),
    algorithm,
    NONEXTRACTABLE,
    usage.ENCRYPT_WRAP,
  )
}

export function importPrivateKeyPem(
  privateKey,
  algorithm = algorithms.RSA_OAEP,
) {
  return kryptos.subtle.importKey(
    formats.PKSC8,
    privatePemToDerArrayBuffer(privateKey),
    algorithm,
    NONEXTRACTABLE,
    usage.DECRYPT_UNWRAP,
  )
}

export async function unwrapPrivateKeyPem(
  wrappedPrivateKey,
  unwrappingKey,
  wrappedKeyAlgorithm,
  unwrappedKeyAlgorithm,
  usages,
) {
  return kryptos.subtle.unwrapKey(
    formats.PKSC8,
    wrappedPrivateKey,
    unwrappingKey,
    wrappedKeyAlgorithm,
    unwrappedKeyAlgorithm,
    NONEXTRACTABLE,
    usages,
  )
}

/**
 * Generate a new symmetric key.
 * Change: Used to be EXTRACTABLE
 *
 * @param {Object} algorithm
 */
export function generateSessionKey(algorithm) {
  return kryptos.subtle.generateKey(algorithm, EXTRACTABLE, usage.ENCRYPT)
}

export function generateWrapKey() {
  return kryptos.subtle.generateKey(
    algorithms.AES_GCM_ALGO,
    EXTRACTABLE,
    usage.ENCRYPT_WRAP,
  )
}

export function wrapKey(key, wrappingKey) {
  return kryptos.subtle.wrapKey(formats.RAW, key, wrappingKey, {
    name: wrappingKey.algorithm.name,
  })
}

export function unwrapKey(
  wrappedKey,
  unwrappingKey,
  wrappedKeyAlgorithm,
  extractable = NONEXTRACTABLE,
) {
  return kryptos.subtle.unwrapKey(
    formats.RAW,
    wrappedKey,
    unwrappingKey,
    unwrappingKey.algorithm.name,
    wrappedKeyAlgorithm,
    extractable,
    usage.ENCRYPT_WRAP,
  )
}

export function wrapPrivateKey(privateKey, iv, wrappingKey) {
  return kryptos.subtle.wrapKey(formats.JWK, privateKey, wrappingKey, {
    name: algorithms.AES_GCM.name,
    iv,
  })
}

export async function unwrapPrivateKey(
  wrappedPrivateKey,
  unwrappingKey,
  wrappedKeyAlgorithm,
  unwrappedKeyAlgorithm,
  usages,
) {
  if (algorithms.isEllipticCurve(unwrappedKeyAlgorithm)) {
    // Use decrypt/import as unwrapKey for EC private keys not supported in Firefox
    const decryptedKey = await kryptos.subtle.decrypt(
      wrappedKeyAlgorithm,
      unwrappingKey,
      wrappedPrivateKey,
    )
    return kryptos.subtle.importKey(
      formats.JWK,
      arrayBufferToObject(decryptedKey),
      unwrappedKeyAlgorithm,
      NONEXTRACTABLE,
      usages,
    )
  }
  return kryptos.subtle.unwrapKey(
    formats.JWK,
    wrappedPrivateKey,
    unwrappingKey,
    wrappedKeyAlgorithm,
    unwrappedKeyAlgorithm,
    NONEXTRACTABLE,
    usages,
  )
}

/**
 * Generate the signing key pair using the given algorithm.
 *
 * @param {Object} algorithm
 */
export function generateSigningKeyPair(algorithm) {
  return kryptos.subtle.generateKey(algorithm, EXTRACTABLE, usage.SIGN)
}

/**
 * Generate the encrypting key pair using the given algorithm.
 *
 * @param {Object} algorithm
 */
export function generateEncryptionKeyPair(algorithm) {
  return kryptos.subtle.generateKey(algorithm, EXTRACTABLE, [
    ...usage.ENCRYPT,
    ...usage.WRAP,
  ])
}

/**
 * Generate the encrypting key pair using the given algorithm.
 *
 * @param {Object} algorithm
 */
export function generateDerivationKeyPair(algorithm) {
  return kryptos.subtle.generateKey(algorithm, EXTRACTABLE, usage.DERIVE)
}

export async function exportPublicKey(publicKey) {
  const exportedPublicKey = await kryptos.subtle.exportKey(
    formats.JWK,
    publicKey,
  )
  if (exportedPublicKey.kty === algorithms.EC) {
    // EC fix
    delete exportedPublicKey.ext
  }
  return Promise.resolve(exportedPublicKey)
}

export function exportKey(key) {
  return kryptos.subtle.exportKey(formats.JWK, key)
}

export function exportRawKey(key) {
  return kryptos.subtle.exportKey(formats.RAW, key)
}

export function generateKeyPair(algorithm) {
  switch (algorithm.name) {
    case algorithms.RSASSA_PKCS1_V1_5_ALGO.name:
    case algorithms.ECDSA_ALGO.name:
      return generateSigningKeyPair(algorithm)
    case algorithms.RSA_OAEP_ALGO.name:
      return generateEncryptionKeyPair(algorithm)
    case algorithms.ECDH_ALGO.name:
      return generateDerivationKeyPair(algorithm)
    default:
      break
  }
  throw new Error('Invalid key pair algorithm.')
}

export function getSessionKey(algorithm, key) {
  if (!key) {
    return generateSessionKey(algorithm)
  }
  if (typeof key === 'string') {
    return importSessionKey(base64ToArrayBuffer(key), algorithm)
  }
  if (key instanceof ArrayBuffer) {
    return importSessionKey(key, algorithm)
  }
  throw new Error('Invalid session key.')
}

export function importHmacKey(raw) {
  return kryptos.subtle.importKey(
    formats.RAW,
    raw,
    algorithms.HMAC_ALGO,
    NONEXTRACTABLE,
    usage.SIGN,
  )
}
