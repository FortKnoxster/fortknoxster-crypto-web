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
} from './keys'
import * as algorithms from './algorithms'
import { getUsage } from './usages'
import { signIt } from './signer'
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

function newKeyProtector(wrappedKey, algorithm, type) {
  return {
    encryptedKey: utils.arrayBufferToBase64(wrappedKey),
    type,
    name: algorithm.name,
    salt: utils.arrayBufferToBase64(algorithm.salt),
    iterations: algorithm.iterations,
    hash: algorithm.hash,
  }
}

export async function setupKeyPair(derivedKey, algorithm, protectorAlgorithm) {
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
    const passwordProtector = newKeyProtector(
      wrappedIntermediateKey,
      protectorAlgorithm,
      PROTECTOR_TYPES.password,
    )
    keyContainer.keyProtectors.push(passwordProtector)
    return {
      keyContainer,
      publicKey: exportedPublicKey,
    }
  } catch (e) {
    return Promise.reject(e)
  }
}

export async function setupIdentityKeys(password, algorithm) {
  try {
    const salt = utils.randomValue(LENGTH_32)
    const iterations = PROTECTOR_ITERATIONS
    const PBKDF2 = algorithms.deriveKeyPBKDF2(salt, iterations)
    const derivedKey = await deriveKeyFromPassword(password, salt, iterations)
    const container = await setupKeyPair(derivedKey, algorithm, PBKDF2)
    const keyFingerprint = await fingerprint(container.publicKey)
    return {
      psk: container.keyContainer,
      pvk: container.publicKey,
      fingerprint: utils.arrayBufferToHex(keyFingerprint),
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
  password,
  identityKey,
  signAlgorithm,
  encryptAlgorithm,
) {
  try {
    const salt = utils.randomValue(LENGTH_32)
    const iterations = PROTECTOR_ITERATIONS
    const PBKDF2 = algorithms.deriveKeyPBKDF2(salt, iterations)
    const derivedKey = await deriveKeyFromPassword(password, salt, iterations)
    const signContainer = await setupKeyPair(derivedKey, signAlgorithm, PBKDF2)
    const encryptContainer = await setupKeyPair(
      derivedKey,
      encryptAlgorithm,
      PBKDF2,
    )
    const signature = await signPublicKeys(
      identityKey,
      encryptContainer.publicKey,
      signContainer.publicKey,
    )
    return {
      pdk: signContainer.keyContainer,
      psk: encryptContainer.keyContainer,
      pek: encryptContainer.publicKey,
      pvk: signContainer.publicKey,
      signature,
    }
  } catch (e) {
    return Promise.reject(e)
  }
}

export async function unlockPrivateKey(keyContainer, protector, protectorKey) {
  try {
    const protectAlgorithm = algorithms.getAlgorithm(keyContainer.protectType)
    const encryptedKey = utils.base64ToArrayBuffer(keyContainer.encryptedKey)
    const iv = utils.base64ToArrayBuffer(keyContainer.iv)
    const intermediateKey = await unwrapKey(
      utils.base64ToArrayBuffer(protector.encryptedKey),
      protectorKey,
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
    return privateKey
  } catch (e) {
    return Promise.reject(e)
  }
}

export async function unlock(
  keyContainers,
  password,
  type = PROTECTOR_TYPES.password,
) {
  try {
    const promises = keyContainers.map(async keyContainer => {
      const keyProtector = keyContainer.keyProtectors.find(
        protector => protector.type === type,
      )
      const salt = utils.base64ToArrayBuffer(keyProtector.salt)
      const { iterations } = keyProtector
      const derivedKey = await deriveKeyFromPassword(password, salt, iterations)
      return unlockPrivateKey(keyContainer, keyProtector, derivedKey)
    })
    return Promise.all(promises)
  } catch (e) {
    return Promise.reject(e)
  }
}

export async function lock(
  keyStore,
  password,
  type = PROTECTOR_TYPES.password,
) {
  try {
    const signKeyProtector = keyStore.psk.keyProtectors.find(
      protector => protector.type === type,
    )

    const salt = utils.base64ToArrayBuffer(signKeyProtector.salt)
    const { iterations } = signKeyProtector
    const derivedKey = await deriveKeyFromPassword(password, salt, iterations)

    return derivedKey
  } catch (e) {
    return Promise.reject(e)
  }
}
