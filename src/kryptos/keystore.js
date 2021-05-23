/* eslint-disable max-lines */
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
 * @file enrypter.js
 * @copyright Copyright © FortKnoxster Ltd. 2020.
 * @license Apache License, Version 2.0 http://www.apache.org/licenses/LICENSE-2.0
 * @author Mickey Johnnysson <mj@fortknoxster.com>
 * @author Christian Zwergius <cz@fortknoxster.com>
 * @version 2.0
 * @description Kryptos is a cryptographic library wrapping and implementing the
 * Web Cryptography API. Kryptos supports symmetric keys and asymmetric key pair
 * generation, key derivation, key wrap/unwrap, encryption, decryption, signing and verification.
 */
import * as utils from './utils'
import {
  generateWrapKey,
  wrapKey,
  generateKeyPair,
  wrapPrivateKey,
  exportPublicKey,
  unwrapKey,
  unwrapPrivateKey,
  exportKey,
} from './keys'
import * as algorithms from './algorithms'
import { getUsage } from './usages'
import { signPublicKeys } from './signer'
import { fingerprint } from './digest'
import { getProtector, packProtector } from './protector'
import { PROTECTOR_TYPES, EXTRACTABLE } from './constants'

function newKeyContainer(wrappedKey, iv, keyType) {
  return {
    encryptedKey: utils.arrayBufferToBase64(wrappedKey),
    iv: utils.arrayBufferToBase64(iv),
    keyType,
    protectType: algorithms.AES_GCM_256,
    keyProtectors: [],
  }
}

export async function setupKeyPair(
  derivedKey,
  algorithm,
  protectorAlgorithm,
  protectorType,
  protectorIdentifier,
) {
  try {
    const intermediateKey = await generateWrapKey()
    const wrappedIntermediateKey = await wrapKey(intermediateKey, derivedKey)
    const keyPair = await generateKeyPair(algorithm)
    const iv = utils.nonce()
    const wrappedPrivateKey = await wrapPrivateKey(
      keyPair.privateKey,
      iv,
      intermediateKey,
    )
    const exportedPublicKey = await exportPublicKey(keyPair.publicKey)
    const keyContainer = newKeyContainer(
      wrappedPrivateKey,
      iv,
      algorithms.keyContainerType(algorithm),
    )
    const passwordProtector = packProtector(
      wrappedIntermediateKey,
      protectorAlgorithm,
      protectorType,
      protectorIdentifier,
    )
    keyContainer.keyProtectors.push(passwordProtector)
    return {
      keyContainer,
      publicKey: exportedPublicKey,
      privateKey: keyPair.privateKey,
    }
  } catch (e) {
    return Promise.reject(e)
  }
}

export async function setupIdentityKeys(
  id,
  protectorKey,
  algorithm,
  protectorType = PROTECTOR_TYPES.password,
  protectorIdentifier,
) {
  try {
    const protector = await getProtector(protectorKey)

    const container = await setupKeyPair(
      protector.key,
      algorithm,
      protector.algorithm,
      protectorType,
      protectorIdentifier,
    )
    const keyFingerprint = await fingerprint(container.publicKey)
    const exportedDerivedKey = await exportKey(protector.key)
    return {
      id,
      keyContainers: {
        psk: container.keyContainer,
        pvk: container.publicKey,
        fingerprint: utils.arrayBufferToHex(keyFingerprint),
      },
      psk: {
        privateKey: container.privateKey,
        protector: exportedDerivedKey,
      },
      publicKeys: {
        verify: container.publicKey,
      },
    }
  } catch (e) {
    return Promise.reject(e)
  }
}

export async function setupKeys(
  id,
  protectorKey,
  identityKey,
  signAlgorithm,
  encryptAlgorithm,
  protectorType = PROTECTOR_TYPES.password,
  protectorIdentifier,
) {
  try {
    const protector = await getProtector(protectorKey)
    const signContainer = await setupKeyPair(
      protector.key,
      signAlgorithm,
      protector.algorithm,
      protectorType,
      protectorIdentifier,
    )
    const encryptContainer = await setupKeyPair(
      protector.key,
      encryptAlgorithm,
      protector.algorithm,
      protectorType,
      protectorIdentifier,
    )
    const signature = await signPublicKeys(
      identityKey,
      encryptContainer.publicKey,
      signContainer.publicKey,
    )
    const exportedDerivedKey = await exportKey(protector.key)
    return {
      id,
      keyContainers: {
        pdk: encryptContainer.keyContainer,
        psk: signContainer.keyContainer,
        pek: encryptContainer.publicKey,
        pvk: signContainer.publicKey,
        signature,
      },
      psk: {
        privateKey: signContainer.privateKey,
        protector: exportedDerivedKey,
      },
      pdk: {
        privateKey: encryptContainer.privateKey,
        protector: exportedDerivedKey,
      },
      publicKeys: {
        encrypt: encryptContainer.publicKey,
        verify: signContainer.publicKey,
        signature,
      },
    }
  } catch (e) {
    return Promise.reject(e)
  }
}

export function unlockIntermediateKey(
  encryptedKey,
  protectorKey,
  protectAlgorithm,
) {
  return unwrapKey(
    utils.base64ToArrayBuffer(encryptedKey),
    protectorKey,
    protectAlgorithm,
    EXTRACTABLE,
  )
}

export async function unlockPrivateKey(
  keyType,
  keyContainer,
  protector,
  protectorKey,
  includeProtector = false,
) {
  try {
    const protectAlgorithm = algorithms.getAlgorithm(keyContainer.protectType)
    const encryptedKey = utils.base64ToArrayBuffer(keyContainer.encryptedKey)
    const iv = utils.base64ToArrayBuffer(keyContainer.iv)
    const intermediateKey = await unlockIntermediateKey(
      protector.encryptedKey,
      protectorKey.key,
      protectAlgorithm,
    )
    const unwrappedKeyAlgorithm = algorithms.getAlgorithm(keyContainer.keyType)
    const usages = getUsage(keyContainer.keyType)

    const privateKey = await unwrapPrivateKey(
      encryptedKey,
      intermediateKey,
      { name: protectAlgorithm.name, iv },
      unwrappedKeyAlgorithm,
      usages,
    )
    if (includeProtector) {
      const exportedDerivedKey = await exportKey(protectorKey.key)
      return {
        [keyType]: {
          privateKey,
          protector: exportedDerivedKey,
        },
      }
    }
    return {
      [keyType]: {
        privateKey,
      },
    }
  } catch (e) {
    return Promise.reject(e)
  }
}

export async function unlock(
  id,
  keyContainers,
  protectorKey,
  type = PROTECTOR_TYPES.password,
) {
  try {
    const promises = Object.keys(keyContainers)
      .filter((key) => ['pdk', 'psk'].includes(key) && keyContainers[key])
      .map(async (key) => {
        const keyProtector = keyContainers[key].keyProtectors.find(
          (protector) => protector.type === type,
        )
        const { salt, iterations } = keyProtector
        const protector = await getProtector(protectorKey, salt, iterations)
        return unlockPrivateKey(
          key,
          keyContainers[key],
          keyProtector,
          protector,
          type !== PROTECTOR_TYPES.asymmetric,
        )
      })
    const privateKeys = await Promise.all(promises)
    return Object.assign(
      {
        id,
        keyContainers,
      },
      ...privateKeys,
    )
  } catch (e) {
    return Promise.reject(e)
  }
}

export async function init(id, keyStore, type = PROTECTOR_TYPES.password) {
  try {
    const promises = Object.keys(keyStore.keyContainers)
      .filter(
        (key) => ['pdk', 'psk'].includes(key) && keyStore.keyContainers[key],
      )
      .map(async (key) => {
        const keyProtector = keyStore.keyContainers[key].keyProtectors.find(
          (protector) => protector.type === type,
        )
        const protector = await getProtector(keyStore[key].protector)
        return unlockPrivateKey(
          key,
          keyStore.keyContainers[key],
          keyProtector,
          protector,
          false,
        )
      })
    const privateKeys = await Promise.all(promises)
    return Object.assign(
      {
        id,
        keyContainers: keyStore.keyContainers,
      },
      ...privateKeys,
    )
  } catch (e) {
    return Promise.reject(e)
  }
}

/**
 * Unlock the intermediate key of a key container with given protector, then re-wrap the interrmediate key
 * with a new protector. If any existing protector type equals the new protector type, it will be replaced,
 * else the new protector will be added to the list of jey protectors.
 *
 * @param {String} keyType
 * @param {Object} keyContainer
 * @param {CryptoKey} protector
 * @param {Object} keyProtector
 * @param {CryptoKey} newProtectorKey
 * @param {String} newType
 */
async function replaceOrAddProtector(
  keyType,
  keyContainer,
  protector,
  keyProtector,
  newProtectorKey,
  newType,
  protectorIdentifier,
) {
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
  // Todo: handler (type, identifier) as distinct protectors
  const index = clonedKeyProtectors.findIndex((p) => p.type === newType)
  if (index !== -1) {
    clonedKeyProtectors[index] = replaceProtector
  } else {
    clonedKeyProtectors.push(replaceProtector)
  }
  clonedKeyContainer.keyProtectors = clonedKeyProtectors
  return { [keyType]: clonedKeyContainer }
}

/**
 * Lock key containers with a new protector. Key containers must first unlock the intermediate key
 * with current password protector. The new key protecter will replace an existing key protector
 * of the same time, or be added as a new key protector.
 * Used for change password, account recovery and reset password operations.
 *
 * @param {Array} keyContainers
 * @param {String} password
 * @param {String} newProtector
 * @param {String} type
 */
export async function lock(
  service,
  keyContainers,
  protectorKey,
  type = PROTECTOR_TYPES.password,
  newProtectorKey,
  newType = PROTECTOR_TYPES.password,
  protectorIdentifier,
) {
  try {
    const clonedKeyContainers = { ...keyContainers }
    const promises = Object.keys(clonedKeyContainers)
      .filter((key) => ['pdk', 'psk'].includes(key) && clonedKeyContainers[key])
      .map(async (key) => {
        const keyProtector = clonedKeyContainers[key].keyProtectors.find(
          (protector) => protector.type === type,
        )
        const { salt, iterations } = keyProtector
        const protector = await getProtector(protectorKey, salt, iterations)

        return replaceOrAddProtector(
          key,
          clonedKeyContainers[key],
          protector,
          keyProtector,
          newProtectorKey,
          newType,
          protectorIdentifier,
        )
      })

    const updatedKeyContainers = await Promise.all(promises)
    return {
      id: service,
      keyContainers: {
        ...clonedKeyContainers,
        ...updatedKeyContainers.reduce(
          (acc, container) => Object.assign(acc, container),
          {},
        ),
      },
    }
  } catch (e) {
    return Promise.reject(e)
  }
}
