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
 * @file signer.js
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
import { importHmacKey } from './keys'
import { stringToArrayBuffer, arrayBufferToBase64 } from './utils'
import { getSignAlgorithm } from './algorithms'

export function sign(arrayBuffer, signKey) {
  return kryptos.subtle.sign(
    getSignAlgorithm(signKey.algorithm.name),
    signKey,
    new Uint8Array(arrayBuffer),
  )
}

export async function signIt(plainText, privateKey) {
  try {
    const data = stringToArrayBuffer(JSON.stringify(plainText))
    const signature = await sign(data, privateKey)
    return arrayBufferToBase64(signature)
  } catch (error) {
    return Promise.reject(error)
  }
}

export async function hmacBinarySignIt(cipherText, rawKey) {
  try {
    const signKey = await importHmacKey(stringToArrayBuffer(rawKey))
    return sign(cipherText, signKey)
  } catch (error) {
    return Promise.reject(error)
  }
}

export async function hmacSignIt(plainText, rawKey) {
  try {
    const data = stringToArrayBuffer(plainText)
    const signature = await hmacBinarySignIt(data, rawKey)
    return arrayBufferToBase64(signature)
  } catch (error) {
    return Promise.reject(error)
  }
}
