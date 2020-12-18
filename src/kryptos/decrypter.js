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
 * @file decrypter.js
 * @copyright Copyright © FortKnoxster Ltd. 2020.
 * @license Apache License, Version 2.0 http://www.apache.org/licenses/LICENSE-2.0
 * @author Mickey Johnnysson <mj@fortknoxster.com>
 * @author Christian Zwergius <cz@fortknoxster.com>
 * @version 2.0
 * @description Kryptos is a cryptographic library wrapping and implementing the
 * Web Cryptography API. Kryptos supports symmetric keys and asymmetric key pair
 * generation, key derivation, key wrap/unwrap, encryption, decryption, signing and verification.
 */
import { kryptos } from './kryptos'
import { importPublicVerifyKey } from './keys'
import { arrayBufferToObject, base64ToArrayBuffer } from './utils'
import { AES_GCM } from './algorithms'
import { verify } from './verifier'
import { LENGTH_128 } from './constants'

/**
 *  Decrypt sessionKey with private key.
 *
 * @param {ArrayBuffer} encryptedKey
 * @param {CryptoKey} privateKey
 */
export function decryptSessionKey(encryptedKey, privateKey) {
  return kryptos.subtle.decrypt(
    { name: privateKey.algorithm.name },
    privateKey,
    encryptedKey,
  )
}

/**
 *  Decrypt raw sessionKey with private key.
 *
 * @param {String} rawEncryptedKey
 * @param {CryptoKey} privateKey
 */
export function decryptRawSessionKey(rawEncryptedKey, privateKey) {
  const key = base64ToArrayBuffer(rawEncryptedKey)
  return decryptSessionKey(key, privateKey)
}

/**
 * Decrypt given cipher text with the given symmetric key.
 * Determine decryption algorithm based on the CryptoKey object.
 *
 * @param {ArrayBuffer} arrayBuffer
 * @param {ArrayBuffer} iv
 * @param {CryptoKey} key
 */
export function decrypt(arrayBuffer, iv, key) {
  const algorithm = { name: key.algorithm.name, iv }
  if (algorithm.name === AES_GCM.name) {
    algorithm.tagLength = LENGTH_128
  }
  return kryptos.subtle.decrypt(algorithm, key, arrayBuffer)
}

/**
 * Decrypt cipherText with given sessionKey and iv.
 *
 * @param {ArrayBuffer} cipherText
 * @param {CryptoKey} sessionKey
 * @param {ArrayBuffer} iv
 */
export async function decryptIt(cipherText, iv, sessionKey) {
  try {
    const plainText = await decrypt(cipherText, iv, sessionKey)
    return arrayBufferToObject(plainText)
  } catch (error) {
    return Promise.reject(error)
  }
}

/**
 * Verify the signature of the encrypted cipherText, then decrypt the cipherText
 *
 * @param {ArrayBuffer} cipherText
 * @param {CryptoKey} sessionKey
 * @param {ArrayBuffer} iv
 * @param {ArrayBuffer} signature
 * @param {CryptoKey} publicKey
 */
export async function verifyDecrypt(
  cipherText,
  sessionKey,
  iv,
  signature,
  publicKey,
) {
  try {
    const importedPvk = await importPublicVerifyKey(publicKey)
    await verify(importedPvk, signature, cipherText)
    return decryptIt(cipherText, iv, sessionKey)
  } catch (error) {
    return Promise.reject(error)
  }
}
