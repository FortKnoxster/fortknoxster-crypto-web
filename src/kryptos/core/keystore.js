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
import * as utils from '../utils'
import { deriveKeyFromPassword } from '../derive'
import {
  generateWrapKey,
  wrapKey,
  generateSigningKeyPair,
  wrapPrivateKey,
  exportPublicKey,
  fingerprint,
} from './keys'
import * as algorithms from '../algorithms'
// import { sign } from './signer'
import { PROTECTOR_TYPES, PROTECTOR_ITERATIONS, LENGTH_32 } from '../constants'

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

export async function setupIdentityKeys(password, algorithm) {
  try {
    const salt = utils.randomValue(LENGTH_32)
    const iterations = PROTECTOR_ITERATIONS
    const derivedKey = await deriveKeyFromPassword(password, salt, iterations)
    const intermediateKey = await generateWrapKey()
    const wrappedIntermediateKey = await wrapKey(intermediateKey, derivedKey)
    const signingKeyPair = await generateSigningKeyPair(algorithm)
    const iv = utils.nonce()
    const wrappedPrivateKey = await wrapPrivateKey(
      signingKeyPair.privateKey,
      iv,
      intermediateKey,
    )
    const exportedPublicKey = await exportPublicKey(signingKeyPair.publicKey)
    delete exportedPublicKey.ext
    const keyFingerprint = await fingerprint(exportedPublicKey)
    const keyContainer = newKeyContainer(
      wrappedPrivateKey,
      iv,
      algorithms.keyContainerType(algorithm),
    )
    const passwordProtector = newKeyProtector(
      wrappedIntermediateKey,
      algorithms.deriveKeyPBKDF2(salt, iterations),
      PROTECTOR_TYPES.password,
    )

    keyContainer.keyProtectors.push(passwordProtector)
    return {
      psk: keyContainer,
      pvk: exportedPublicKey,
      fingerprint: utils.arrayBufferToHex(keyFingerprint),
    }
  } catch (e) {
    return Promise.reject(e)
  }
}
