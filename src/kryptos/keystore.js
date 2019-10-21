/* eslint-disable max-lines */
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
import * as utils from './utils'
import { deriveKeyFromPassword } from './derive'
import {
  generateWrapKey,
  wrapKey,
  generateKeyPair,
  wrapPrivateKey,
  exportPublicKey,
  fingerprint,
  unwrapKey,
  unwrapPrivateKey,
  exportKey,
} from './keys'
import * as algorithms from './algorithms'
import { getUsage } from './usages'
import { signIt } from './signer'
import { getProtector, packProtector } from './protector'
import { PROTECTOR_TYPES, PROTECTOR_ITERATIONS, LENGTH_32 } from './constants'

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

export function signPublicKeys(identity, publicEncryptKey, publicVerifyKey) {
  const publicKeys = {
    pek: utils.toJwk(publicEncryptKey),
    pvk: utils.toJwk(publicVerifyKey),
  }
  return signIt(publicKeys, identity)
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
        pdk: signContainer.keyContainer,
        psk: encryptContainer.keyContainer,
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
      },
    }
  } catch (e) {
    return Promise.reject(e)
  }
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
    const intermediateKey = await unwrapKey(
      utils.base64ToArrayBuffer(protector.encryptedKey),
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
      .filter(key => ['pdk', 'psk'].includes(key) && keyContainers[key])
      .map(async key => {
        const keyProtector = keyContainers[key].keyProtectors.find(
          protector => protector.type === type,
        )
        const salt = utils.base64ToArrayBuffer(keyProtector.salt)
        const { iterations } = keyProtector
        const protector = await getProtector(protectorKey, salt, iterations)
        return unlockPrivateKey(
          key,
          keyContainers[key],
          keyProtector,
          protector,
          true,
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
        key => ['pdk', 'psk'].includes(key) && keyStore.keyContainers[key],
      )
      .map(async key => {
        const keyProtector = keyStore.keyContainers[key].keyProtectors.find(
          protector => protector.type === type,
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
 * Todo: implement
 * Lock key containers with a new protector. Key containers must unlock the intermediate key
 * with the password protector.
 *
 * @param {Array} keyContainers
 * @param {String} password
 * @param {String} newProtector
 * @param {String} type
 */
export async function lock(
  keyContainers,
  password,
  newProtector,
  type = PROTECTOR_TYPES.password,
) {
  try {
    const salt = utils.randomValue(LENGTH_32)
    const iterations = PROTECTOR_ITERATIONS
    const PBKDF2 = algorithms.deriveKeyPBKDF2(salt, iterations)
    const derivedKey = await deriveKeyFromPassword(password, salt, iterations)

    return { keyContainers, newProtector, type, PBKDF2, derivedKey }
  } catch (e) {
    return Promise.reject(e)
  }
}
