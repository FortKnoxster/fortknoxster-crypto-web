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
 * @file keystore.js
 * @copyright Copyright © FortKnoxster Ltd. 2020.
 * @license Apache License, Version 2.0 http://www.apache.org/licenses/LICENSE-2.0
 * @author Mickey Johnnysson <mj@fortknoxster.com>
 * @author Christian Zwergius <cz@fortknoxster.com>
 * @version 2.0
 * @description Kryptos is a cryptographic library wrapping and implementing the
 * Web Cryptography API. Kryptos supports symmetric keys and asymmetric key pair
 * generation, key derivation, key wrap/unwrap, encryption, decryption, signing and verification.
 */
import * as utils from './utils.js'
import {
  generateKeyPair,
  exportPublicKey,
  unwrapKey,
  exportKey,
} from './keys.js'
import * as algorithms from './algorithms.js'
import { signPublicKeys } from './signer.js'
import { fingerprint } from './digest.js'
import {
  setupKeyContainer,
  unlockKeyContainer,
  replaceOrAddProtector,
} from './keyContainer.js'
import { getProtector } from './protector.js'
import { PROTECTOR_TYPES, EXTRACTABLE } from './constants.js'

export async function setupKeyPair(
  derivedKey,
  algorithm,
  protectorAlgorithm,
  protectorType,
  protectorIdentifier,
) {
  try {
    const keyPair = await generateKeyPair(algorithm)

    const keyContainer = await setupKeyContainer(
      derivedKey,
      algorithms.keyContainerType(algorithm),
      keyPair,
      protectorAlgorithm,
      protectorType,
      protectorIdentifier,
    )

    const exportedPublicKey = await exportPublicKey(keyPair.publicKey)

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
  protectorType,
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
  protectorType,
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
      identityKey, // === null ? signContainer.privateKey : identityKey, // Self-sign if no identity key provided
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
  protectorKey,
  type,
  includeProtector = false,
) {
  try {
    const unlockedKeyContainer = await unlockKeyContainer(
      keyContainer,
      protectorKey,
      type,
      includeProtector,
    )

    if (includeProtector) {
      const exportedDerivedKey = await exportKey(
        unlockedKeyContainer.protectorKey,
      )
      return {
        [keyType]: {
          privateKey: unlockedKeyContainer.privateKey,
          protector: exportedDerivedKey,
        },
      }
    }
    return {
      [keyType]: {
        privateKey: unlockedKeyContainer.privateKey,
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
        return unlockPrivateKey(
          key,
          keyContainers[key],
          protectorKey,
          type,
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
        const protector = await getProtector(keyStore[key].protector)
        return unlockPrivateKey(
          key,
          keyStore.keyContainers[key],
          protector,
          type,
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
  type,
  newProtectorKey,
  newType,
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
