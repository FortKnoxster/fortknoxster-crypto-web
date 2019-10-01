/**
 * Copyright 2019 FortKnoxster Ltd.
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
 * @copyright Copyright © FortKnoxster Ltd. 2019.
 * @license Apache License, Version 2.0 http://www.apache.org/licenses/LICENSE-2.0
 * @author Mickey Johnnysson <mj@fortknoxster.com>
 * @author Christian Zwergius <cz@fortknoxster.com>
 * @version 2.0
 * @description Kryptos is a cryptographic library wrapping and implementing the
 * Web Cryptography API. Kryptos supports symmetric keys and asymmetric key pair
 * generation, key derivation, key wrap/unwrap, encryption, decryption, signing and verification.
 */
import { kryptos } from './kryptos'
import * as algorithms from './algorithms'
import * as formats from './formats'
import * as usage from './usages'
import { objectToArrayBuffer } from './utils'
import { NONEXTRACTABLE, EXTRACTABLE } from './constants'

export function importSessionKey(keyBytes, algorithm) {
  return kryptos.subtle.importKey(
    formats.RAW,
    keyBytes,
    algorithm || algorithms.AES_CBC_ALGO,
    NONEXTRACTABLE,
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

export function importPublicEncryptKey(publicKey) {
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
      usage.ENCRYPT_ONLY,
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

/**
 * Generate a new symmetric key.
 * Change: Used to be EXTRACTABLE
 *
 * @param {Object} algorithm
 */
export function generateSessionKey(algorithm) {
  return kryptos.subtle.generateKey(algorithm, NONEXTRACTABLE, usage.ENCRYPT)
}

export function generateWrapKey() {
  return kryptos.subtle.generateKey(
    algorithms.AES_GCM_ALGO,
    EXTRACTABLE,
    usage.WRAP.concat(usage.ENCRYPT),
  )
}

export function wrapKey(key, wrappingKey) {
  return kryptos.subtle.wrapKey(formats.RAW, key, wrappingKey, {
    name: wrappingKey.algorithm.name,
  })
}

export function unwrapKey(wrappedKey, unwrappingKey, wrappedKeyAlgorithm) {
  return kryptos.subtle.unwrapKey(
    formats.RAW,
    wrappedKey,
    unwrappingKey,
    unwrappingKey.algorithm.name,
    wrappedKeyAlgorithm,
    EXTRACTABLE,
    usage.WRAP.concat(usage.ENCRYPT),
  )
}

export function wrapPrivateKey(privateKey, iv, wrappingKey) {
  return kryptos.subtle.wrapKey(formats.JWK, privateKey, wrappingKey, {
    name: algorithms.AES_GCM.name,
    iv,
  })
}

export function unwrapPrivateKey(
  wrappedPrivateKey,
  unwrappingKey,
  wrappedKeyAlgorithm,
  unwrappedKeyAlgorithm,
  usages,
) {
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
/**
 *
 * @param {*} key
 */
export function fingerprint(key) {
  return kryptos.subtle.digest(
    algorithms.SHA_256.name,
    objectToArrayBuffer(key),
  )
}
