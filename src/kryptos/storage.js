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
import { generateSessionKey, importPublicEncryptKey } from './keys'
import { encryptSign } from './encrypter'
import { PSK, PEK, SERVICES } from './constants'
import { Encrypter } from './core/kryptos.encrypter'
import { Decrypter } from './core/kryptos.decrypter'
import { base64ToArrayBuffer } from './utils'
import { AES_CBC_ALGO } from './algorithms'

const storage = {
  keyStore: null,
}

export function addStoragePublicKeys(publicKeys) {
  storage.keyStore.setPublicKeys(publicKeys)
}

function formatItem(encryptedItem) {
  const { iv, m, s, key, keys } = encryptedItem
  return {
    message: m,
    iv,
    signature: s,
    ...(key && { key }),
    ...(keys[0] && {
      // eslint-disable-next-line camelcase
      encrypted_key: new window.Blob([key[0]], {
        type: 'application/octet-stream',
      }),
    }),
  }
}

export function encryptItems(items) {
  const { keyStore } = storage
  return items.map(item => {
    const encrypter = new Encrypter(keyStore, item.d, null)
    return encrypter.encryptNewItem(item.rid)
  })
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

export async function encryptNewItemAssignment(itemData) {
  try {
    const sessionKey = await generateSessionKey(AES_CBC_ALGO)

    const importedPek = await importPublicEncryptKey(
      getPublicKey(SERVICES.storage, PEK),
    )

    const result = await encryptSign(
      itemData,
      sessionKey,
      getPrivateKey(SERVICES.storage, PSK),
      [importedPek],
    )
    const encryptedItem = formatItem(result)
    return encryptedItem
  } catch (error) {
    return Promise.reject(error)
  }
  /*
    const { keyStore } = storage
    const encrypter = new Encrypter(keyStore, item.d, null)
    return encrypter.encryptNewItemAssignment()
    */
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

export function decryptItemAssignment(data, publicKey) {
  const { keyStore } = storage
  const {
    item_key,
    item: { meta_data },
  } = data
  const metaData = JSON.parse(meta_data)
  const decrypter = new Decrypter(
    keyStore,
    base64ToArrayBuffer(item_key),
    new Uint8Array(base64ToArrayBuffer(metaData.iv)),
    base64ToArrayBuffer(metaData.d),
    base64ToArrayBuffer(metaData.s),
    publicKey || keyStore.getPvk(true),
  )
  return decrypter.decryptItemAssignment()
}
