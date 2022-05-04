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
 * @file inbox.js
 * @copyright Copyright © FortKnoxster Ltd. 2022.
 * @license Apache License, Version 2.0 http://www.apache.org/licenses/LICENSE-2.0
 * @author Mickey Johnnysson <mj@fortknoxster.com>
 * @author Christian Zwergius <cz@fortknoxster.com>
 * @version 2.0
 * @description Kryptos is a cryptographic library wrapping and implementing the
 * Web Cryptography API. Kryptos supports symmetric keys and asymmetric key pair
 * generation, key derivation, key wrap/unwrap, encryption, decryption, signing and verification.
 */
import { getPrivateKey, getPublicKey } from './serviceKeyStore.js'
import {
  importPublicVerifyKey,
  generateSessionKey,
  exportRawKey,
} from './keys.js'
import { PVK, PEK, PDK, PSK } from './constants.js'
import { AES_GCM_ALGO } from './algorithms.js'
import { arrayBufferToHex } from './utils.js'
import { lockKeyContainer, unlockKeyContainer } from './keyContainer.js'
import { signIt } from './signer.js'
import { verifyIt } from './verifier.js'

export async function encryptDetails(wallet, service, protectType, dataType) {
  try {
    const publicKey = getPublicKey(service, PEK)
    const privateKey = getPrivateKey(service, PSK)
    const keyContainer = await lockKeyContainer(
      publicKey,
      dataType,
      wallet,
      protectType,
    )
    const signature = await signIt(keyContainer, privateKey)
    keyContainer.signature = signature
    return keyContainer
  } catch (e) {
    return Promise.reject(e)
  }
}

export async function encryptWallet(wallet, service, type) {
  return encryptDetails(wallet, service, type, 'wallet')
}

export async function decryptWallet(encryptedWallet, service, type) {
  try {
    const publicKey = await importPublicVerifyKey(getPublicKey(service, PVK))
    const privateKey = await getPrivateKey(service, PDK)
    const { signature } = encryptedWallet
    const clonedKeyContainer = { ...encryptedWallet }
    delete clonedKeyContainer.signature

    await verifyIt(publicKey, signature, clonedKeyContainer)

    const { privateKey: unlockedWallet } = await unlockKeyContainer(
      clonedKeyContainer,
      privateKey,
      type,
    )
    return unlockedWallet
  } catch (e) {
    return Promise.reject(e)
  }
}

export async function encryptBeneficiary(beneficiary, service, type) {
  try {
    const sessionKey = await generateSessionKey(AES_GCM_ALGO) // unique beneficiary key
    const exportedSessionKey = await exportRawKey(sessionKey)
    const clonedBeneficiary = { ...beneficiary }
    clonedBeneficiary.algorithm = AES_GCM_ALGO
    clonedBeneficiary.key = arrayBufferToHex(exportedSessionKey)
    const encryptedData = await encryptDetails(
      clonedBeneficiary,
      service,
      type,
      'beneficiary',
    )
    return encryptedData
  } catch (e) {
    return Promise.reject(e)
  }
}
