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
 * @file decrypter.js
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
import { verifyIt } from './verifier'
import { LENGTH_128 } from '../constants'

/**
 * Decrypt given cipher text with the given symmetric key.
 * Determine decryption algorithm based on the CryptoKey object.
 *
 * @param {ArrayBuffer} arrayBuffer
 * @param {CryptoKey} key
 */
export function decrypt(arrayBuffer, key) {
  const algorithm = { name: key.name, length: key.length }
  if (key.name === algorithms.AES_GCM.name) {
    algorithm.tagLength = LENGTH_128
  }
  return kryptos.subtle.decrypt(algorithm, key, arrayBuffer)
}

/**
 * Verify the signature of the encrypted cipherText, then decrypt the cipherText
 *
 * @param {ArrayBuffer} cipherText
 * @param {String} iv
 * @param {String} signature
 * @param {CryptoKey} publicKey
 */
export async function verifyDecrypt(
  cipherText,
  base64Iv,
  base64Signature,
  publicKey,
) {
  await verifyIt(publicKey, base64Signature, cipherText)
  const iv = utils.base64ToArrayBuffer(base64Iv)
  const plainText = await decrypt(cipherText, iv)
  return utils.arrayBufferToObject(plainText)
}
