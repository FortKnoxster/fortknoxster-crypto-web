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
import { encryptSign } from './encrypter'
import { verifyDecrypt, decryptSessionKey } from './decrypter'
import { PSK, PEK, PVK, PDK, SERVICES } from './constants'
import { Encrypter } from './core/kryptos.encrypter'
import { Decrypter } from './core/kryptos.decrypter'
import { base64ToArrayBuffer, arrayBufferToBase64 } from './utils'
import { AES_CBC_ALGO } from './algorithms'

const storage = {
  keyStore: null,
}

// TODO: Move to React
function formatItem(encryptedItem, item) {
  const { iv, m, s, key, keys } = encryptedItem
  return {
    d: m,
    iv,
    s,
    ...(key && { key }),
    ...(keys[0] && {
      // eslint-disable-next-line camelcase
      encrypted_key: new window.Blob([keys[0]], {
        type: 'application/octet-stream',
      }),
    }),
    ...(item && { rid: item.rid }),
  }
}

// TODO: Don't depende on item
export async function encryptItem(item, key, publicKeys = []) {
  try {
    const sessionKey = await getSessionKey(AES_CBC_ALGO, key)
    const result = await encryptSign(
      item.d,
      sessionKey,
      getPrivateKey(SERVICES.storage, PSK),
      publicKeys,
    )
    return formatItem(result, item)
  } catch (error) {
    return Promise.reject(error)
  }
}

export async function encryptNewItemAssignment(item) {
  const publicKey = getPublicKey(SERVICES.storage, PEK)
  return encryptItem(item, null, [publicKey])
}

export function encryptItems(items) {
  return items.map(item => encryptItem(item))
}

export function encryptExistingItem(item, key) {
  return encryptItem(item, key)
}

// TODO: Don't depende on item
export function encryptFilePart(filePart, partNo, itemId) {
  const { keyStore } = storage
  const encrypter = new Encrypter(keyStore, null, null, null)
  return encrypter.encryptFilePart(filePart, itemId, partNo)
}

export function encryptItemAssignment(item, key, publicKeys) {
  return encryptItem(item, key, publicKeys)
}

export async function decryptItem(metaData, key, publicKey) {
  try {
    const sessionKey = await getSessionKey(AES_CBC_ALGO, key)
    const json = await verifyDecrypt(
      metaData.d,
      sessionKey,
      metaData.iv,
      metaData.s,
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

// TODO: Don't depende on item
export function decryptFilePart(itemId, partItem, filePart) {
  const { keyStore } = storage
  const { iv, k, p } = partItem
  const decrypter = new Decrypter(
    keyStore,
    base64ToArrayBuffer(k),
    base64ToArrayBuffer(iv),
    filePart,
  )
  return decrypter.decryptFilePart(itemId, p)
}
