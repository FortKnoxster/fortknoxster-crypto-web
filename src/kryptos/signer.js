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
 * @file signer.js
 * @copyright Copyright © FortKnoxster Ltd. 2019.
 * @license Apache License, Version 2.0 http://www.apache.org/licenses/LICENSE-2.0
 * @author Mickey Johnnysson <mj@fortknoxster.com>
 * @author Christian Zwergius <cz@fortknoxster.com>
 * @version 2.0
 * @description Kryptos is a cryptographic library wrapping and implementing the
 * Web Cryptography API. Kryptos supports symmetric keys and asymmetric key pair
 * generation, key derivation, key wrap/unwrap, encryption, decryption, signing and verification.
 */
import { kryptos } from './kryptos'
import * as utils from './utils'
import * as algorithms from './algorithms'
import * as formats from './formats'
import * as usage from './usages'
import { NONEXTRACTABLE } from './constants'

export function sign(arrayBuffer, privateKey) {
  return kryptos.subtle.sign(
    algorithms.getSignAlgorithm(privateKey.algorithm.name),
    privateKey,
    new Uint8Array(arrayBuffer),
  )
}

export async function signIt(plainText, privateKey) {
  try {
    const data = utils.stringToArrayBuffer(JSON.stringify(plainText))
    const signature = await sign(data, privateKey)
    return utils.arrayBufferToBase64(signature)
  } catch (error) {
    return Promise.reject(error)
  }
}

export function importHmacKey(raw) {
  return kryptos.subtle.importKey(
    formats.RAW,
    raw,
    algorithms.HMAC_ALGO,
    NONEXTRACTABLE,
    usage.SIGN,
  )
}

export async function hmacSignIt(plainText, rawKey) {
  try {
    const data = utils.stringToArrayBuffer(plainText)
    const signKey = await importHmacKey(utils.stringToArrayBuffer(rawKey))
    const signature = await sign(data, signKey)
    return utils.arrayBufferToBase64(signature)
  } catch (error) {
    return Promise.reject(error)
  }
}
