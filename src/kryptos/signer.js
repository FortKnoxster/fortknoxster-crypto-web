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
 * @file signer.js
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
import { importHmacKey } from './keys.js'
import { stringToArrayBuffer, arrayBufferToBase64, toJwk } from './utils.js'
import { getSignAlgorithm } from './algorithms.js'

/**
 * Sign binary with a signing key. Returns binary signature.
 *
 * @param {ArrayBuffer} arrayBuffer
 * @param {CryptoKey} signKey
 */
export function sign(arrayBuffer, signKey) {
  return kryptos.subtle.sign(
    getSignAlgorithm(signKey.algorithm.name),
    signKey,
    new Uint8Array(arrayBuffer),
  )
}

/**
 * Sign plain text with a private key. Returns base64 encoded signature.
 *
 * @param {String} plainText
 * @param {CryptoKey} privateKey
 */
export async function signIt(plainText, privateKey) {
  try {
    const data = stringToArrayBuffer(JSON.stringify(plainText))
    const signature = await sign(data, privateKey)
    return arrayBufferToBase64(signature)
  } catch (error) {
    return Promise.reject(error)
  }
}

/**
 * Sign binary cipher text with given raw key as imported HMAC sign key.
 *
 * @param {ArrayBuffer} cipherText
 * @param {ArrayBuffer} rawKey
 */
export async function hmacBinarySignIt(cipherText, rawKey) {
  try {
    const signKey = await importHmacKey(rawKey)
    return sign(cipherText, signKey)
  } catch (error) {
    return Promise.reject(error)
  }
}

/**
 * Sign plain text with given raw key as imported HMAC sign key.
 *
 * @param {String} plainText
 * @param {ArrayBuffer} rawKey
 */
export async function hmacSignIt(plainText, rawKey) {
  try {
    const data = stringToArrayBuffer(plainText)
    const signature = await hmacBinarySignIt(data, stringToArrayBuffer(rawKey))
    return arrayBufferToBase64(signature)
  } catch (error) {
    return Promise.reject(error)
  }
}

/**
 * Sign public keys with exact JWK format.
 *
 * @param {CryptoKey} privateKey
 * @param {JWK} publicEncryptKey
 * @param {JWK} publicVerifyKey
 */
export function signPublicKeys(privateKey, publicEncryptKey, publicVerifyKey) {
  const publicKeys = {
    pek: toJwk(publicEncryptKey),
    pvk: toJwk(publicVerifyKey),
  }
  return signIt(publicKeys, privateKey)
}
