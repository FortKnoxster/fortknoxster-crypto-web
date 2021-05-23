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
 * @file protector.js
 * @copyright Copyright © FortKnoxster Ltd. 2020.
 * @license Apache License, Version 2.0 http://www.apache.org/licenses/LICENSE-2.0
 * @author Mickey Johnnysson <mj@fortknoxster.com>
 * @author Christian Zwergius <cz@fortknoxster.com>
 * @version 2.0
 * @description Kryptos is a cryptographic library wrapping and implementing the
 * Web Cryptography API. Kryptos supports symmetric keys and asymmetric key pair
 * generation, key derivation, key wrap/unwrap, encryption, decryption, signing and verification.
 */
import { getAlgorithm, deriveKeyPBKDF2 } from './algorithms.js'
import {
  randomValue,
  arrayBufferToBase64,
  base64ToArrayBuffer,
} from './utils.js'
import { deriveKeyFromPassword } from './derive.js'
import { importWrapKey } from './keys.js'
import { PROTECTOR_ITERATIONS, LENGTH_32 } from './constants.js'

export function packProtector(wrappedKey, algorithm, type, identifier) {
  return {
    encryptedKey: arrayBufferToBase64(wrappedKey),
    type,
    name: algorithm.name,
    ...(algorithm.salt && { salt: arrayBufferToBase64(algorithm.salt) }),
    ...(algorithm.iterations && { iterations: algorithm.iterations }),
    hash: algorithm.hash.name || algorithm.hash,
    ...(identifier && { identifier }),
  }
}

export async function getSymmetricProtector(
  password,
  givenSalt,
  givenIterations,
) {
  const salt = givenSalt
    ? base64ToArrayBuffer(givenSalt)
    : randomValue(LENGTH_32)
  const iterations = givenIterations || PROTECTOR_ITERATIONS
  const algorithm = deriveKeyPBKDF2(salt, iterations)
  const key = await deriveKeyFromPassword(password, salt, iterations)
  return {
    algorithm,
    key,
  }
}

export async function importProtector(protector) {
  const key = await importWrapKey(protector)
  const algorithm = getAlgorithm(protector.alg)
  return {
    algorithm,
    key,
  }
}

export function getProtector(protector, salt, iterations) {
  if (typeof protector === 'string') {
    return getSymmetricProtector(protector, salt, iterations)
  }
  if (typeof protector === 'object' && protector.algorithm) {
    return {
      algorithm: getAlgorithm(protector.algorithm.name),
      key: protector,
    }
  }
  if (typeof protector === 'object') {
    return importProtector(protector)
  }

  throw new Error('Invalid protector.')
}
