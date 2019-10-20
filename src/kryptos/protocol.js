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
 * @file protocol.js
 * @copyright Copyright © FortKnoxster Ltd. 2019.
 * @license Apache License, Version 2.0 http://www.apache.org/licenses/LICENSE-2.0
 * @author Mickey Johnnysson <mj@fortknoxster.com>
 * @author Christian Zwergius <cz@fortknoxster.com>
 * @version 2.0
 * @description Kryptos is a cryptographic library wrapping and implementing the
 * Web Cryptography API. Kryptos supports symmetric keys and asymmetric key pair
 * generation, key derivation, key wrap/unwrap, encryption, decryption, signing and verification.
 */
import { EC_AES_GCM_256, AES_GCM_ALGO } from './algorithms'
import {
  base64ToArrayBuffer,
  stringToArrayBuffer,
  arrayBufferToBase64,
} from './utils'
import { importPublicEncryptKey, importPublicVerifyKey } from './keys'
import { deriveSessionKey } from './derive'
import { encryptIt } from './encrypter'
import { decryptIt } from './decrypter'
import { signIt } from './signer'
import { verifyIt } from './verifier'

const protocol = {
  keyStore: null,
  nodeId: null,
  userId: null,
}

export function initProtocol(keyStore, nodeId, userId) {
  protocol.keyStore = keyStore
  protocol.nodeId = nodeId
  protocol.userId = userId
  Object.freeze(protocol.keyStore)
  Object.freeze(protocol)
}

/**
 * Standard Communication Protocol format.
 *
 * @param {String} type
 * @param {JSON} data
 * @returns {JSON}
 */
function protocolMessage(type, data) {
  const { nodeId, userId } = protocol
  return {
    From: `${userId}@${nodeId}`,
    To: nodeId,
    ServiceType: type,
    ServiceData: data,
    Flags: 0,
    Timestamp: new Date().getTime(),
    Sign: null,
  }
}

/**
 * Standard Encryption Envelope format used in the Standard Communication
 * Protocol.
 *
 * @param {type} algo
 * @param {type} data
 * @returns {JSON}
 */
function messageEnvelope(algo, data) {
  return {
    name: algo || null,
    iv: null,
    encryptedKey: null,
    data: JSON.stringify(data) || null,
  }
}

// TODO move to utils
function tryParseResult(result) {
  try {
    const o = JSON.parse(result)
    if (o && typeof o === 'object') {
      return o
    }
  } catch (e) {
    return result
  }
  return result
}

async function getSessionKey(nodePek) {
  const { keyStore } = protocol
  const importedPek = await importPublicEncryptKey(nodePek, []) // EC import public key requires empty usages
  return deriveSessionKey(AES_GCM_ALGO, keyStore.pdk.privateKey, importedPek)
}

/**
 * Standard Communication Protocol used for encryption.
 *
 * @param {String} type
 * @param {Object} data
 * @param {Object} nodePek
 * @returns {Promise}
 */
export async function encryptProtocol(type, data, nodePek) {
  try {
    const { keyStore } = protocol

    const message = protocolMessage(type)
    const envelope = messageEnvelope(EC_AES_GCM_256)
    const sessionKey = await getSessionKey(nodePek)
    const { iv, cipherText } = await encryptIt(data, sessionKey)

    envelope.iv = arrayBufferToBase64(iv)
    envelope.data = arrayBufferToBase64(cipherText)
    message.ServiceData = envelope

    const signature = await signIt(message, keyStore.psk.privateKey)
    message.Sign = signature
    return message
  } catch (error) {
    return Promise.reject(error)
  }
}

/**
 * Standard Communication Protocol used for decryption.
 *
 * @param {Object} result
 * @param {bool} isError
 * @param {bool} verifyOnly
 * @param {Object} nodePek
 * @param {Object} nodePvk
 * @returns {void}
 */
export async function decryptProtocol(
  result,
  isError,
  verifyOnly,
  nodePek,
  nodePvk,
) {
  try {
    const data = isError
      ? JSON.parse(result.errors.message)
      : tryParseResult(result)
    const { Sign } = data
    const message = data.ServiceData
    data.Sign = null // TODO handle this in decrypter
    const cipherText = stringToArrayBuffer(JSON.stringify(data))
    const importedPvk = await importPublicVerifyKey(nodePvk)

    await verifyIt(importedPvk, Sign, cipherText)
    if (verifyOnly) {
      return message
    }

    const sessionKey = await getSessionKey(nodePek)
    return decryptIt(base64ToArrayBuffer(message.data), sessionKey, message.iv)
  } catch (error) {
    return Promise.reject(error)
  }
}
