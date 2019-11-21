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
 * @file verifier.js
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
import { importHmacKey, importPublicVerifyKey } from './keys'
import {
  base64ToArrayBuffer,
  stringToArrayBuffer,
  formatPublicKeysToVerify,
} from './utils'
import { getSignAlgorithm } from './algorithms'
import { SERVICES } from './constants'

/**
 * Verify given signature and verified signature of the given cipher text.
 *
 * @param {CryptoKey} publicKey
 * @param {String} base64Signature
 * @param {ArrayBuffer} cipherText
 */
export async function verify(publicKey, signature, cipherText) {
  const result = await kryptos.subtle.verify(
    getSignAlgorithm(publicKey.algorithm.name),
    publicKey,
    signature,
    cipherText,
  )
  if (!result) {
    return Promise.reject()
  }
  return result
}

/**
 * Convert signature and verified signature of the given cipher text.
 *
 * @param {CryptoKey} publicKey
 * @param {String} base64Signature
 * @param {Object} data
 */
export function verifyIt(publicKey, base64Signature, data) {
  try {
    const signature = base64ToArrayBuffer(base64Signature)
    const cipherText = stringToArrayBuffer(JSON.stringify(data))
    return verify(publicKey, signature, cipherText)
  } catch (error) {
    return Promise.reject(error)
  }
}

export async function hmacVerifyIt(rawKey, signature, data) {
  try {
    const verifyKey = await importHmacKey(rawKey)
    return verify(verifyKey, signature, data)
  } catch (error) {
    return Promise.reject(error)
  }
}

export async function verifyPublicKeys(keys, publicKey) {
  try {
    const importedPublicKey = await importPublicVerifyKey(publicKey)
    return Object.keys(keys)
      .filter(key => key !== SERVICES.identity)
      .map(key => {
        const { signature } = keys[key]
        const keysToVerify = formatPublicKeysToVerify(keys[key])
        return verifyIt(importedPublicKey, signature, keysToVerify)
      })
  } catch (e) {
    return Promise.reject(e)
  }
}
