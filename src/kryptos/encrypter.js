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
import { kryptos } from './kryptos'
import { stringToArrayBuffer, arrayBufferToBase64, nonce } from './utils'
import { RSA_OAEP_ALGO, AES_GCM } from './algorithms'
import { sign } from './signer'
import { exportRawKey, importPublicEncryptKey } from './keys'
import { LENGTH_128 } from './constants'

/**
 * Encrypt a symmetric key with an asymmetric public key.
 * Todo: implement wrapKey as non-extractable
 *
 * @param {CryptoKey} sessionKey
 * @param {CryptoKey} publicKey
 */
export async function encryptSessionKey(sessionKey, publicKey) {
  try {
    const importedPek = await importPublicEncryptKey(publicKey)
    return kryptos.subtle.encrypt(RSA_OAEP_ALGO, importedPek, sessionKey)
  } catch (error) {
    return Promise.reject(error)
  }
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
  if (algorithm.name === AES_GCM.name) {
    algorithm.tagLength = LENGTH_128
  }
  return kryptos.subtle.encrypt(algorithm, key, arrayBuffer)
}

/**
 * Encrypt given plain text with given symmetric sessionKey.
 *
 * @param {Object} plainText
 * @param {CryptoKey} sessionKey
 */
export async function encryptIt(plainText, sessionKey) {
  try {
    const iv = nonce()
    const data = stringToArrayBuffer(JSON.stringify(plainText))
    const cipherText = await encrypt(data, iv, sessionKey)
    return {
      iv,
      cipherText,
    }
  } catch (error) {
    return Promise.reject(error)
  }
}

/**
 * Encrypt file binary with a given symmetric sessionKey.
 *
 * @param {ArrayBuffer} binary
 * @param {CryptoKey} sessionKey
 */
export async function encryptBinary(binary, sessionKey) {
  try {
    const iv = nonce()
    const cipherText = await encrypt(binary, iv, sessionKey)
    const exportedSessionKey = await exportRawKey(sessionKey)
    return {
      iv: arrayBufferToBase64(iv),
      key: arrayBufferToBase64(exportedSessionKey),
      encrypted: new Uint8Array(cipherText),
    }
  } catch (error) {
    return Promise.reject(error)
  }
}

/**
 * Encrypt given plain text with given symmetric sessionKey
 * and sign encrypted message with given private key.
 *
 * @param {Object} plainText
 * @param {CryptoKey} sessionKey
 * @param {CryptoKey} privateKey
 * @param {Array} publicKeys
 */
export async function encryptSign(plainText, sessionKey, privateKey) {
  try {
    const { iv, cipherText } = await encryptIt(plainText, sessionKey)
    const signature = await sign(cipherText, privateKey)
    return {
      m: arrayBufferToBase64(cipherText),
      iv: arrayBufferToBase64(iv),
      s: arrayBufferToBase64(signature),
    }
  } catch (error) {
    return Promise.reject(error)
  }
}

/**
 * Encrypt given plain text with given symmetric sessionKey,
 * sign encrypted message with given private key and wrap
 * sessionKey with given publicKeys.
 *
 * @param {Object} plainText
 * @param {CryptoKey} sessionKey
 * @param {CryptoKey} privateKey
 * @param {Array} publicKeys
 */
export async function encryptSignEncrypt(
  plainText,
  sessionKey,
  privateKey,
  publicKeys = [],
) {
  try {
    const { iv, m, s } = await encryptSign(plainText, sessionKey, privateKey)
    const exportedSessionKey = await exportRawKey(sessionKey)
    const promises = publicKeys.map(publicKey =>
      encryptSessionKey(exportedSessionKey, publicKey),
    )
    const keys = await Promise.all(promises)
    return {
      m,
      iv,
      s,
      key: arrayBufferToBase64(exportedSessionKey),
      keys,
    }
  } catch (error) {
    return Promise.reject(error)
  }
}
