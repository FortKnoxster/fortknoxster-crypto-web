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
 * @file keys.js
 * @copyright Copyright © FortKnoxster Ltd. 2019.
 * @license Apache License, Version 2.0 http://www.apache.org/licenses/LICENSE-2.0
 * @author Mickey Johnnysson <mj@fortknoxster.com>
 * @author Christian Zwergius <cz@fortknoxster.com>
 * @version 2.0
 * @description Kryptos is a cryptographic library wrapping and implementing the
 * Web Cryptography API. Kryptos supports symmetric keys and asymmetric key pair
 * generation, key derivation, key wrap/unwrap, encryption, decryption, signing and verification.
 */
import { kryptos } from '../kryptos'
import * as algorithms from '../algorithms'
import * as formats from '../formats'
import * as usage from '../usages'
import { NONEXTRACTABLE } from '../constants'

export function importSessionKey(keyBytes, algorithm) {
  return kryptos.subtle.importKey(
    formats.RAW,
    keyBytes,
    algorithm || algorithms.AES_CBC_ALGO,
    NONEXTRACTABLE,
    usage.ENCRYPT,
  )
}

export function importEncryptionKey(keyBytes, algorithm) {
  return kryptos.subtle.importKey(
    formats.RAW,
    keyBytes,
    algorithm || algorithms.AES_CBC_ALGO,
    NONEXTRACTABLE,
    usage.ENCRYPT,
  )
}

export function importPublicVerifyKey(publicKey) {
  if (publicKey.kty === algorithms.EC) {
    const algorithm = algorithms.getAlgorithm(algorithms.ECDSA_ALGO.name)
    // eslint-disable-next-line no-param-reassign
    delete publicKey.alg
    return kryptos.subtle.importKey(
      formats.JWK,
      publicKey,
      algorithm,
      NONEXTRACTABLE,
      usage.VERIFY_ONLY,
    )
  }
  const algorithm = algorithms.getAlgorithm(publicKey.alg)
  return kryptos.subtle.importKey(
    formats.JWK,
    publicKey,
    algorithm,
    NONEXTRACTABLE,
    usage.VERIFY_ONLY,
  )
}

export function importPublicEncryptKey(publicKey) {
  if (publicKey.kty === algorithms.EC) {
    const algorithm = algorithms.getAlgorithm(algorithms.ECDH_ALGO.name)
    // eslint-disable-next-line no-param-reassign
    delete publicKey.alg
    // eslint-disable-next-line no-param-reassign
    delete publicKey.key_ops
    return kryptos.subtle.importKey(
      formats.JWK,
      publicKey,
      algorithm,
      NONEXTRACTABLE,
      usage.ENCRYPT_ONLY,
    )
  }
  const algorithm = algorithms.getAlgorithm(publicKey.alg)
  return kryptos.subtle.importKey(
    formats.JWK,
    publicKey,
    algorithm,
    NONEXTRACTABLE,
    usage.ENCRYPT_ONLY,
  )
}
