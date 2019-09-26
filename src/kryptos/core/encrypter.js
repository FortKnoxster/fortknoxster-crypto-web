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
 * @file enrypter.js
 * @copyright Copyright © FortKnoxster Ltd. 2019.
 * @license Apache License, Version 2.0 http://www.apache.org/licenses/LICENSE-2.0
 * @author Mickey Johnnysson <mj@fortknoxster.com>
 * @author Christian Zwergius <cz@fortknoxster.com>
 * @version 2.0
 * @description Kryptos is a cryptographic library wrapping and implementing the
 * Web Cryptography API. Kryptos supports symmetric keys and asymmetric key pair
 * generation, key derivation, key wrap/unwrap, encryption, decryption, signing and verification.
 */
import { kryptos } from '../kryptos'
import * as utils from '../utils'
import * as algorithms from '../algorithms'
import * as usage from '../usages'
import { sign } from './signer'
import { NONEXTRACTABLE, LENGTH_128 } from '../constants'

/**
 * Generate a new symmetric key.
 * Change: Used to be EXTRACTABLE
 *
 * @param {Object} algorithm
 */
export function generateSessionKey(algorithm) {
  return kryptos.subtle.generateKey(algorithm, NONEXTRACTABLE, usage.ENCRYPT)
}

/**
 * Encrypt a symmetric key with an asymmetric public key.
 * Todo: implement wrapKey as non-extractable
 *
 * @param {CryptoKey} sessionKey
 * @param {CryptoKey} publicKey
 */
export function encryptSessionKey(sessionKey, publicKey) {
  return kryptos.subtle.encrypt(algorithms.RSA_OAEP_ALGO, publicKey, sessionKey)
}

/**
 * Encrypt binary data with given iv and key.
 *
 * @param {ArrayBuffer} arrayBuffer
 * @param {ArrayBuffer} iv
 * @param {CryptoKey} key
 */
export function encrypt(arrayBuffer, iv, key) {
  const algorithm = { name: key.algorithm.name, iv }
  if (algorithm.name === algorithms.AES_GCM.name) {
    algorithm.tagLength = LENGTH_128
  }
  return kryptos.subtle.encrypt(algorithm, key, arrayBuffer)
}

/**
 * Encrypt message with symmetric sessionKey, sign encrypted message and wrap sessionKey with given publicKeys.
 *
 * @param {String} plainText
 * @param {CryptoKey} sessionKey
 * @param {CryptoKey} privateKey
 * @param {Array} publicKeys
 */
export async function encryptSign(
  plainText,
  sessionKey,
  privateKey,
  publicKeys = [],
) {
  try {
    const iv = utils.nonce()
    const data = utils.stringToArrayBuffer(JSON.stringify(plainText))
    const cipherText = await encrypt(data, iv, sessionKey)
    const signature = await sign(cipherText, privateKey)
    const promises = publicKeys.map(publicKey =>
      encryptSessionKey(sessionKey, publicKey),
    )
    const keys = await Promise.all(promises)
    return {
      iv: utils.arrayBufferToBase64(iv),
      m: utils.arrayBufferToBase64(cipherText),
      s: utils.arrayBufferToBase64(signature),
      keys,
    }
  } catch (error) {
    console.error(error)
    return Promise.reject(error)
  }
}
