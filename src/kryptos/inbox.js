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
 * @file inbox.js
 * @copyright Copyright © FortKnoxster Ltd. 2019.
 * @license Apache License, Version 2.0 http://www.apache.org/licenses/LICENSE-2.0
 * @author Mickey Johnnysson <mj@fortknoxster.com>
 * @author Christian Zwergius <cz@fortknoxster.com>
 * @version 2.0
 * @description Kryptos is a cryptographic library wrapping and implementing the
 * Web Cryptography API. Kryptos supports symmetric keys and asymmetric key pair
 * generation, key derivation, key wrap/unwrap, encryption, decryption, signing and verification.
 */
import { getPrivateKey, getPublicKey } from './serviceKeyStore'
import { encryptSignBinary, encryptSessionKeys } from './encrypter'
import { verifyDecrypt } from './decrypter'
import { unwrapKey, getSessionKey, exportRawKey } from './keys'
import { base64ToArrayBuffer, extractMessage, packMessage } from './utils'
import { PVK, PDK, PSK, SERVICES } from './constants'
import { AES_CBC_ALGO } from './algorithms'

export async function encryptMessage(plainText, publicKeys) {
  try {
    const privateKey = getPrivateKey(SERVICES.mail, PSK)
    const sessionKey = await getSessionKey(AES_CBC_ALGO)
    const rawKey = await exportRawKey(sessionKey)
    const { m, iv, s } = await encryptSignBinary(
      plainText,
      sessionKey,
      privateKey,
    )
    const keys = await encryptSessionKeys(rawKey, publicKeys)
    return {
      message: packMessage(iv, s, m),
      keys,
    }
  } catch (error) {
    return Promise.reject(error)
  }
}

export async function decryptMessage(message, publicKey) {
  try {
    const { encryptedKey, iv, cipherText, signature } = extractMessage(
      base64ToArrayBuffer(message),
    )
    const privateKey = getPrivateKey(SERVICES.mail, PDK)
    const sessionKey = await unwrapKey(encryptedKey, privateKey, AES_CBC_ALGO)
    return verifyDecrypt(
      cipherText,
      sessionKey,
      iv,
      signature,
      publicKey || getPublicKey(SERVICES.mail, PVK),
    )
  } catch (error) {
    return Promise.reject(error)
  }
}
