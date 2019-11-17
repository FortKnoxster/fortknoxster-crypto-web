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
 * @file storage.js
 * @copyright Copyright © FortKnoxster Ltd. 2019.
 * @license Apache License, Version 2.0 http://www.apache.org/licenses/LICENSE-2.0
 * @author Mickey Johnnysson <mj@fortknoxster.com>
 * @author Christian Zwergius <cz@fortknoxster.com>
 * @version 2.0
 * @description Kryptos is a cryptographic library wrapping and implementing the
 * Web Cryptography API. Kryptos supports symmetric keys and asymmetric key pair
 * generation, key derivation, key wrap/unwrap, encryption, decryption, signing and verification.
 */
import { getPrivateKey, getPublicKey } from './serviceKeyStore'
import { getSessionKey } from './keys'
import { encryptSign, encryptFile } from './encrypter'
import { verifyDecrypt, decryptSessionKey, decrypt } from './decrypter'
import { PSK, PEK, PVK, PDK, SERVICES } from './constants'
import { base64ToArrayBuffer, arrayBufferToBase64 } from './utils'
import { AES_CBC_ALGO, AES_GCM_ALGO } from './algorithms'

export async function encryptItem(data, key, publicKeys = []) {
  try {
    const sessionKey = await getSessionKey(AES_CBC_ALGO, key)
    return encryptSign(
      data,
      sessionKey,
      getPrivateKey(SERVICES.storage, PSK),
      publicKeys,
    )
  } catch (error) {
    return Promise.reject(error)
  }
}

export async function encryptNewItemAssignment(item) {
  const publicKey = getPublicKey(SERVICES.storage, PEK)
  return encryptItem(item, null, [publicKey])
}

export async function encryptFilePart(filePart) {
  try {
    const sessionKey = await getSessionKey(AES_GCM_ALGO)
    return encryptFile(filePart, sessionKey)
  } catch (error) {
    return Promise.reject(error)
  }
}

export async function decryptItem(metaData, key, publicKey) {
  try {
    const sessionKey = await getSessionKey(AES_CBC_ALGO, key)
    const json = await verifyDecrypt(
      base64ToArrayBuffer(metaData.d),
      sessionKey,
      base64ToArrayBuffer(metaData.iv),
      base64ToArrayBuffer(metaData.s),
      publicKey || getPublicKey(SERVICES.storage, PVK),
    )
    return { json }
  } catch (error) {
    return Promise.reject(error)
  }
}

export async function decryptItemAssignment(metaData, key, publicKey) {
  try {
    const rawKey = await decryptSessionKey(
      base64ToArrayBuffer(key),
      getPrivateKey(SERVICES.storage, PDK),
    )
    const { json } = await decryptItem(metaData, rawKey, publicKey)
    return {
      json,
      key: arrayBufferToBase64(rawKey),
    }
  } catch (error) {
    return Promise.reject(error)
  }
}

export async function decryptFilePart(partItem, filePart) {
  const { iv, k } = partItem
  try {
    const sessionKey = await getSessionKey(AES_GCM_ALGO, base64ToArrayBuffer(k))
    return decrypt(filePart, base64ToArrayBuffer(iv), sessionKey)
  } catch (error) {
    return Promise.reject(error)
  }
}
