/**
 * Copyright 2021 FortKnoxster Ltd.
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
 * @file keyContainer.js
 * @copyright Copyright © FortKnoxster Ltd. 2020.
 * @license Apache License, Version 2.0 http://www.apache.org/licenses/LICENSE-2.0
 * @author Mickey Johnnysson <mj@fortknoxster.com>
 * @author Christian Zwergius <cz@fortknoxster.com>
 * @version 2.0
 * @description Kryptos is a cryptographic library wrapping and implementing the
 * Web Cryptography API. Kryptos supports symmetric keys and asymmetric key pair
 * generation, key derivation, key wrap/unwrap, encryption, decryption, signing and verification.
 */
import { kryptos } from './kryptos.js'
import {
  arrayBufferToBase64,
  base64ToArrayBuffer,
  objectToArrayBuffer,
  arrayBufferToObject,
  nonce,
} from './utils.js'
import {
  generateWrapKey,
  wrapKey,
  unwrapKey,
  wrapPrivateKey,
  unwrapPrivateKey,
} from './keys.js'
import { encrypt } from './encrypter.js'
import * as algorithms from './algorithms.js'
import { getUsage } from './usages.js'
import { getProtector, packProtector } from './protector.js'
import { EXTRACTABLE } from './constants.js'

function newKeyContainer(wrappedKey, iv, keyType) {
  return {
    encryptedKey: arrayBufferToBase64(wrappedKey),
    iv: arrayBufferToBase64(iv),
    keyType,
    protectType: algorithms.AES_GCM_256,
    keyProtectors: [],
  }
}

function wrapKeyContainerKey(keyToEncrypt, iv, intermediateKey) {
  if (keyToEncrypt.privateKey || keyToEncrypt.extractable) {
    // private key or secret key

    return wrapPrivateKey(
      keyToEncrypt.privateKey || keyToEncrypt,
      iv,
      intermediateKey,
    )
  }
  const arrayBuffer = objectToArrayBuffer(keyToEncrypt)
  return encrypt(arrayBuffer, iv, intermediateKey)
}

export function unlockIntermediateKey(
  encryptedKey,
  protectorKey,
  protectAlgorithm,
) {
  return unwrapKey(
    base64ToArrayBuffer(encryptedKey),
    protectorKey,
    protectAlgorithm,
    EXTRACTABLE,
  )
}

async function unwrapKeyContainerKey(
  wrappedPrivateKey,
  unwrappingKey,
  wrappedKeyAlgorithm,
  unwrappedKeyAlgorithm,
  usages,
) {
  return unwrapPrivateKey(
    wrappedPrivateKey,
    unwrappingKey,
    wrappedKeyAlgorithm,
    unwrappedKeyAlgorithm,
    usages,
  )
}

async function unwrapKeyContainerKeyAsObject(
  wrappedPrivateKey,
  unwrappingKey,
  wrappedKeyAlgorithm,
) {
  try {
    const privatekeyBuffer = await kryptos.subtle.decrypt(
      wrappedKeyAlgorithm,
      unwrappingKey,
      wrappedPrivateKey,
    )
    return arrayBufferToObject(privatekeyBuffer)
  } catch (e) {
    return Promise.reject(e)
  }
}

export async function setupKeyContainer(
  derivedKey,
  keyType,
  keyToEncrypt,
  protectorAlgorithm,
  protectorType,
  protectorIdentifier,
) {
  try {
    const intermediateKey = await generateWrapKey()
    const wrappedIntermediateKey = await wrapKey(intermediateKey, derivedKey)
    const iv = nonce()
    // console.log('keyToEncrypt', keyToEncrypt)
    const wrappedKey = await wrapKeyContainerKey(
      keyToEncrypt,
      iv,
      intermediateKey,
    )
    const keyContainer = newKeyContainer(wrappedKey, iv, keyType)
    const passwordProtector = packProtector(
      wrappedIntermediateKey,
      protectorAlgorithm,
      protectorType,
      protectorIdentifier,
    )
    keyContainer.keyProtectors.push(passwordProtector)
    return keyContainer
  } catch (e) {
    return Promise.reject(e)
  }
}

export async function lockKeyContainer(
  protectorKey,
  keyType,
  keyToEncrypt,
  protectorType,
  protectorIdentifier,
) {
  try {
    const protector = await getProtector(protectorKey)
    return setupKeyContainer(
      protector.key,
      keyType,
      keyToEncrypt,
      protector.algorithm,
      protectorType,
      protectorIdentifier,
    )
  } catch (e) {
    return Promise.reject(e)
  }
}

export async function unlockKeyContainer(
  keyContainer,
  protectorKey,
  type,
  includeProtector,
) {
  try {
    const keyProtector = keyContainer.keyProtectors.find(
      (protector) => protector.type === type,
    )
    const { salt, iterations } = keyProtector
    const protector = await getProtector(protectorKey, salt, iterations)
    const protectAlgorithm = algorithms.getAlgorithm(keyContainer.protectType)
    const encryptedKey = base64ToArrayBuffer(keyContainer.encryptedKey)
    const iv = base64ToArrayBuffer(keyContainer.iv)
    const intermediateKey = await unlockIntermediateKey(
      keyProtector.encryptedKey,
      protector.key,
      protectAlgorithm,
    )
    const unwrappedKeyAlgorithm = algorithms.getAlgorithm(keyContainer.keyType)
    const usages = getUsage(keyContainer.keyType)
    let privateKey
    if (usages) {
      privateKey = await unwrapKeyContainerKey(
        encryptedKey,
        intermediateKey,
        { name: protectAlgorithm.name, iv },
        unwrappedKeyAlgorithm,
        usages,
      )
    } else {
      privateKey = await unwrapKeyContainerKeyAsObject(
        encryptedKey,
        intermediateKey,
        { name: protectAlgorithm.name, iv },
      )
    }
    if (includeProtector) {
      return { privateKey, protectorKey: protector.key }
    }
    return { privateKey }
  } catch (e) {
    return Promise.reject(e)
  }
}

/**
 * Unlock the intermediate key of a key container with given protector, then re-wrap the interrmediate key
 * with a new protector. If any existing protector type equals the new protector type, it will be replaced,
 * else the new protector will be added to the list of jey protectors.
 *
 * @param {String} keyType key type of unlocking protector
 * @param {Object} keyContainer given key container
 * @param {CryptoKey} protector protector to unlock with key protector
 * @param {Object} keyProtector key protector to unlock protector
 * @param {CryptoKey} newProtectorKey new key protector to lock key container
 * @param {String} newType new key protector type
 * @param {String} protectorIdentifier optional identifier of key protector
 * @return {Object} return new key container
 */
export async function replaceOrAddProtector(
  keyType,
  keyContainer,
  protector,
  keyProtector,
  newProtectorKey,
  newType,
  protectorIdentifier,
) {
  try {
    const clonedKeyContainer = { ...keyContainer }
    const protectAlgorithm = algorithms.getAlgorithm(
      clonedKeyContainer.protectType,
    )
    const intermediateKey = await unlockIntermediateKey(
      keyProtector.encryptedKey,
      protector.key,
      protectAlgorithm,
    )
    const newProtector = await getProtector(newProtectorKey)
    const wrappedIntermediateKey = await wrapKey(
      intermediateKey,
      newProtector.key,
    )
    const replaceProtector = packProtector(
      wrappedIntermediateKey,
      newProtector.algorithm,
      newType,
      protectorIdentifier,
    )
    // Clone keyProtectors
    const clonedKeyProtectors = [...clonedKeyContainer.keyProtectors]
    // If type and identifier match (if identifier present) or just type match if no identifier present
    const index = clonedKeyProtectors.findIndex(
      (p) =>
        (p.type === newType &&
          p.identifier &&
          p.identifier === protectorIdentifier) ||
        (p.type === newType && !p.identifier),
    )
    if (index !== -1) {
      clonedKeyProtectors[index] = replaceProtector
    } else {
      clonedKeyProtectors.push(replaceProtector)
    }
    clonedKeyContainer.keyProtectors = clonedKeyProtectors
    return { [keyType]: clonedKeyContainer }
  } catch (e) {
    return Promise.reject(e)
  }
}
