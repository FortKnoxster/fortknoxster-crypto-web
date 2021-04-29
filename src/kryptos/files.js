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
 * @file files.js
 * @copyright Copyright © FortKnoxster Ltd. 2020.
 * @license Apache License, Version 2.0 http://www.apache.org/licenses/LICENSE-2.0
 * @author Mickey Johnnysson <mj@fortknoxster.com>
 * @author Christian Zwergius <cz@fortknoxster.com>
 * @version 2.0
 * @description Kryptos is a cryptographic library wrapping and implementing the
 * Web Cryptography API. Kryptos supports symmetric keys and asymmetric key pair
 * generation, key derivation, key wrap/unwrap, encryption, decryption, signing and verification.
 */
import { getSessionKey, exportRawKey } from './keys'
import { encrypt, encryptBinary } from './encrypter'
import { hmacBinarySignIt } from './signer'
import { hmacVerifyIt } from './verifier'
import { decrypt } from './decrypter'
import {
  base64ToArrayBuffer,
  arrayBufferToBase64,
  arrayBufferToHex,
  hexToArrayBuffer,
  extractFile,
} from './utils'
import { AES_CBC_ALGO, AES_GCM_ALGO } from './algorithms'

/**
 * Encrypts a file with a random AES encryption key. The encrypted file is then
 * HMAC signed with a derived sign key from the encryption key.
 * The iv, key and hmac signatures are returend as hexadecimal.
 *
 * @param {ArrayBuffer} file
 */
export async function encryptFile(file) {
  try {
    const sessionKey = await getSessionKey(AES_CBC_ALGO)
    const rawKey = await exportRawKey(sessionKey)
    const { iv, key, encrypted } = await encryptBinary(file, sessionKey)

    const hmac = await hmacBinarySignIt(encrypted, rawKey)

    return {
      key: arrayBufferToHex(key),
      hmac: arrayBufferToHex(hmac),
      encrypted: [iv, encrypted],
    }
  } catch (error) {
    return Promise.reject(error)
  }
}

/**
 * Decrypt the encrypted with the given key, after the HMAC signature is verified.
 *
 * @param {ArrayBuffer} cipherText
 * @param {String} key
 * @param {String} hmac
 */
export async function decryptFile(cipherText, key, hmac) {
  try {
    const { iv, encryptedFile } = extractFile(cipherText)
    const rawKey = hexToArrayBuffer(key)
    const signature = hexToArrayBuffer(hmac)
    await hmacVerifyIt(rawKey, signature, encryptedFile)
    const sessionKey = await getSessionKey(AES_CBC_ALGO, rawKey)
    return decrypt(encryptedFile, iv, sessionKey)
  } catch (error) {
    return Promise.reject(error)
  }
}

export async function encryptFilePartWithKey(filePart, sessionKey, iv) {
  try {
    const rawIv = hexToArrayBuffer(iv)
    const cipherText = await encrypt(filePart, rawIv, sessionKey)
    return [rawIv, new Uint8Array(cipherText)]
  } catch (error) {
    return Promise.reject(error)
  }
}

export async function decryptFilePartWithKey(cipherText, key) {
  try {
    const sessionKey = await getSessionKey(AES_GCM_ALGO, key)
    const { iv, encryptedFile } = extractFile(cipherText)
    return decrypt(encryptedFile, iv, sessionKey)
  } catch (error) {
    return Promise.reject(error)
  }
}

/**
 * Encrypt a file part to storage.
 *
 * @param {ArrayBuffer} filePart
 */
export async function encryptFilePart(filePart) {
  try {
    const sessionKey = await getSessionKey(AES_GCM_ALGO)
    const { iv, key, encrypted } = await encryptBinary(filePart, sessionKey)
    return {
      iv: arrayBufferToBase64(iv),
      key: arrayBufferToBase64(key),
      encrypted,
    }
  } catch (error) {
    return Promise.reject(error)
  }
}

/**
 * Decrypt a file part from storage.
 *
 * @param {Object} partItem
 * @param {ArrayBuffer} filePart
 */
export async function decryptFilePart(partItem, filePart) {
  const { iv, k } = partItem
  try {
    const sessionKey = await getSessionKey(AES_GCM_ALGO, base64ToArrayBuffer(k))
    return decrypt(filePart, base64ToArrayBuffer(iv), sessionKey)
  } catch (error) {
    return Promise.reject(error)
  }
}
