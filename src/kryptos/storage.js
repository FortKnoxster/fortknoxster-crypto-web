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
import { importPublicVerifyKey, getSessionKey } from './keys'
import { encryptSign } from './encrypter'
import { verifyDecrypt } from './decrypter'
import { PSK, PEK, PVK, SERVICES } from './constants'
import { Encrypter } from './core/kryptos.encrypter'
import { Decrypter } from './core/kryptos.decrypter'
import { base64ToArrayBuffer } from './utils'
import { AES_CBC_ALGO } from './algorithms'

const storage = {
  keyStore: null,
}

function formatItem(encryptedItem, item) {
  const { iv, m, s, key, keys } = encryptedItem
  return {
    d: m,
    iv,
    s,
    ...(key && { key }),
    ...(keys[0] && {
      // eslint-disable-next-line camelcase
      encrypted_key: new window.Blob([key[0]], {
        type: 'application/octet-stream',
      }),
    }),
    ...(item && { rid: item.rid }),
  }
}

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

export async function decryptItemAssignment(data, publicKey) {
  try {
    const {
      item_key,
      item: { meta_data },
    } = data
    const metaData = JSON.parse(meta_data)
    const importedPvk = await importPublicVerifyKey(
      publicKey || getPublicKey(SERVICES.storage, PVK),
    )

    const sessionKey = await getSessionKey(AES_CBC_ALGO, item_key)

    const result = await verifyDecrypt(
      metaData.d,
      sessionKey,
      metaData.iv,
      metaData.s,
      importedPvk,
    )
    return result
  } catch (error) {
    return Promise.reject(error)
  }
}

export function encryptItems(items) {
  return items.map(item => encryptItem(item))
}

export function encryptExistingItem(item) {
  const { keyStore } = storage
  const encrypter = new Encrypter(keyStore, item.d, null)
  return encrypter.encryptExistingItem(base64ToArrayBuffer(item.key))
}

export function encryptFilePart(filePart, partNo, itemId) {
  const { keyStore } = storage
  const encrypter = new Encrypter(keyStore, null, null, null)
  return encrypter.encryptFilePart(filePart, itemId, partNo)
}

export function encryptItemAssignment(item, usernames) {
  const { keyStore } = storage
  const encrypter = new Encrypter(keyStore, '', usernames)
  return encrypter.encryptItemAssignment(base64ToArrayBuffer(item.key))
}

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

export function decryptItem(id, rid, key, metaData, publicKey) {
  const { keyStore } = storage
  const decrypter = new Decrypter(
    keyStore,
    base64ToArrayBuffer(key),
    new Uint8Array(base64ToArrayBuffer(metaData.iv)),
    base64ToArrayBuffer(metaData.d),
    base64ToArrayBuffer(metaData.s),
    publicKey || keyStore.getPvk(true),
  )
  return decrypter.decryptItem(id, rid)
}
