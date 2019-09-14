/* eslint-disable max-lines */
/* eslint-disable camelcase */
/* eslint-disable no-param-reassign */
import { kryptos } from '../kryptos'
import * as utils from '../utils'
import * as algorithms from '../algorithms'
import * as formats from '../formats'
import * as usage from '../usages'
import { LENGTH_128, EXTRACTABLE, NONEXTRACTABLE } from '../constants'

/**
 * Kryptos is a cryptographic library wrapping and implementing the
 * Web Cryptography API. It supports both symmetric keys and asymmetric key pair
 * generation, encryption, decryption, signing and verification.
 *
 *
 * @name Kryptos
 * @copyright Copyright © FortKnoxster Ltd. 2014 - 2019.
 * @license Apache License, Version 2.0 http://www.apache.org/licenses/LICENSE-2.0
 * @author MJ <mj@fortknoxster.com>
 * @version 4.0
 */

/**
 * The Kryptos Decrypter module.
 *
 * @param {kryptos.KeyStore} serviceKeyStore
 * @param {ByteArray} encryptedKey
 * @param {ByteArray} iv
 * @param {ByteArray} cipherText
 * @param {ByteArray} signature
 * @param {CryptoKey} theirPublicKey
 * @returns {void}
 */
export const Decrypter = function Decrypter(
  serviceKeyStore,
  encryptedKey,
  iVector,
  cipher,
  signature,
  theirPublicKey,
) {
  const keyStore = serviceKeyStore
  let iv = iVector
  let cipherText = cipher
  let publicKey = theirPublicKey
  let sessionKey = null

  const deriveSessionKey = (algorithm, pdk, pek) =>
    kryptos.subtle.deriveKey(
      {
        name: algorithms.ECDH_ALGO.name,
        namedCurve: algorithms.ECDH_ALGO.namedCurve,
        public: pek,
      },
      pdk,
      algorithm,
      EXTRACTABLE,
      usage.ENCRYPT,
    )

  const verifyEncryptedMessage = () =>
    kryptos.subtle.verify(
      algorithms.getSignAlgorithm(publicKey.algorithm.name),
      publicKey,
      signature,
      cipherText,
    )

  const verifyEncryptedFile = verifyKey =>
    kryptos.subtle.verify(algorithms.HMAC, verifyKey, signature, cipherText)

  const handleMessageVerification = successful => {
    if (successful !== true) {
      throw new Error(
        'Verification Error: The sender could not be verified. Decryption of this message has been cancelled.',
      )
    }
  }

  const handleFileVerification = successful => {
    if (successful !== true) {
      throw new Error(
        'Verification Error: The file integrity could not be verified. File corrupted.',
      )
    }
  }

  const decryptKey = pdk =>
    kryptos.subtle.decrypt(
      { name: algorithms.RSA_OAEP.name },
      pdk,
      encryptedKey,
    )

  const unwrapKey = pdk =>
    kryptos.subtle.unwrapKey(
      formats.RAW,
      encryptedKey,
      pdk,
      { name: algorithms.RSA_OAEP.name },
      { name: algorithms.AES_GCM.name },
      NONEXTRACTABLE,
      usage.ENCRYPT,
    )

  const importSessionKey = (keyBytes, algo) => {
    if (!keyBytes) {
      keyBytes = encryptedKey
    }
    if (keyBytes instanceof CryptoKey) {
      return new Promise(resolve => {
        resolve(encryptedKey)
      })
    }
    if (!algo) {
      algo = algorithms.AES_CBC_ALGO
    }
    return kryptos.subtle.importKey(
      formats.RAW,
      keyBytes,
      algo,
      NONEXTRACTABLE,
      usage.ENCRYPT,
    )
  }

  const saveSessionKey = key => {
    sessionKey = key
    return sessionKey
  }

  const savePublicKey = key => {
    publicKey = key
    return publicKey
  }

  const decryptCipherText = (key, algorithm) => {
    let algo = {}
    if (algorithm && algorithm.indexOf(algorithms.AES_GCM.name) !== -1) {
      algo = { name: algorithms.AES_GCM.name, iv, tagLength: LENGTH_128 }
    } else {
      algo = { name: algorithms.AES_CBC.name, iv }
    }
    return kryptos.subtle.decrypt(algo, key, cipherText)
  }

  const handlePlainText = plainText => {
    const json = utils.arrayBufferToObject(plainText)
    return json
  }

  const importVerifyKey = () =>
    kryptos.subtle.importKey(
      formats.RAW,
      encryptedKey,
      algorithms.HMAC_ALGO,
      NONEXTRACTABLE,
      usage.SIGN,
    )

  const importPublicVerifyKey = () =>
    kryptos.subtle.importKey(
      formats.JWK,
      publicKey,
      algorithms.getImportAlgorithm(publicKey.kty),
      false,
      ['verify'],
    )

  const saveImportedPublicVerifyKey = publicVerifyKey => {
    publicKey = publicVerifyKey
  }

  const protocol = (data, pvk, pek, verifyOnly) => {
    cipherText = utils.stringToArrayBuffer(JSON.stringify(data))
    let nodePek = null
    return keyStore
      .importPvk(pvk, ['verify'])
      .then(saveImportedPublicVerifyKey)
      .then(verifyEncryptedMessage)
      .then(handleMessageVerification)
      .then(() => {
        if (verifyOnly) {
          return true
        }
        const message = data.ServiceData
        iv = utils.base64ToArrayBuffer(message.iv)
        cipherText = utils.base64ToArrayBuffer(message.data)
        return keyStore
          .importPek(pek, [])
          .then(importedPek => {
            nodePek = importedPek
          })
          .then(keyStore.getPdk)
          .then(pdk => deriveSessionKey(algorithms.AES_GCM_ALGO, pdk, nodePek))
          .then(key => decryptCipherText(key, algorithms.AES_GCM.name))
          .then(plainText => handlePlainText(plainText))
          .catch(error => {
            console.error(error)
            return error
          })
      })
      .catch(error => {
        console.error(error)
        return error
      })
  }

  const justDecryptIt = (id, algo, key) => {
    sessionKey = key
    return new Promise(resolve => {
      if (!key) {
        return keyStore
          .getPdk()
          .then(decryptKey)
          .then(saveSessionKey)
          .then(() => {
            resolve(sessionKey)
          })
      }
      return resolve(sessionKey)
    })
      .then(resolvedKey =>
        importSessionKey(resolvedKey, algorithms.getAlgorithm(algo)),
      )
      .then(resolvedKey => decryptCipherText(resolvedKey, algo))
      .then(plainText => {
        const data = {
          id,
          plain: utils.arrayBufferToObject(plainText),
          failed: false,
          key: utils.arrayBufferToBase64(sessionKey),
        }
        return new Promise(resolve => {
          resolve(data)
        })
      })
      .catch(error => {
        console.error(error)
        return new Promise(resolve => {
          resolve(error)
        })
      })
  }

  const decryptIt = (from, id, algo, key) => {
    sessionKey = key
    return keyStore
      .getPublicKey(from, 'verify')
      .then(savePublicKey)
      .then(importPublicVerifyKey)
      .then(saveImportedPublicVerifyKey)
      .then(verifyEncryptedMessage)
      .then(handleMessageVerification)
      .then(() => justDecryptIt(id, algo, key))
      .catch(error => {
        console.error(error)
        return error
      })
  }

  const verifyIt = (from, id) =>
    keyStore
      .getPublicKey(from, 'verify')
      .then(savePublicKey)
      .then(keyStore.importPvk)
      .then(saveImportedPublicVerifyKey)
      .then(verifyEncryptedMessage)
      .then(handleMessageVerification)
      .then(() => {
        const data = {
          id,
        }
        return new Promise(resolve => {
          resolve(data)
        })
      })
      .catch(error => {
        console.error(error)
        return new Promise(resolve => {
          resolve(error)
        })
      })

  const decrypt = () =>
    importPublicVerifyKey()
      .then(saveImportedPublicVerifyKey)
      .then(verifyEncryptedMessage)
      .then(handleMessageVerification)
      .then(keyStore.getPdk)
      .then(decryptKey)
      .then(importSessionKey)
      .then(decryptCipherText)
      .then(handlePlainText)
      .catch(error => {
        console.error(error)
      })

  const decryptGroupKey = raw => {
    if (raw) {
      return keyStore
        .getPdk()
        .then(decryptKey)
        .then(result => result)
        .catch(error => {
          console.error(error)
          return error
        })
    }
    return keyStore
      .getPdk()
      .then(unwrapKey)
      .then(result => result)
      .catch(error => {
        console.error(error)
        return error
      })
  }

  const decryptGroupMessage = (from, id) =>
    decryptIt(from, id, algorithms.AES_GCM.name, encryptedKey)

  const decryptFile = () =>
    importVerifyKey()
      .then(verifyEncryptedFile)
      .then(handleFileVerification)
      .then(importSessionKey)
      .then(decryptCipherText)
      .then(result => result)
      .catch(error => {
        console.error(error)
        return error
      })

  // Todo: Rewrite, still used in legacy inbox
  const decrypt2 = (from, uuid) =>
    new Promise(resolve =>
      keyStore
        .getPublicKey(from, 'verify')
        .then(savePublicKey)
        .then(importPublicVerifyKey)
        .then(saveImportedPublicVerifyKey)
        .then(verifyEncryptedMessage)
        .catch(error => {
          console.error(error)
          resolve({
            uuid,
            failed: true,
            plain: { subject: 'Could not verify sender' },
          })
        })
        .then(handleMessageVerification)
        .then(keyStore.getPdk)
        .then(decryptKey)
        .catch(error => {
          console.error(error)
          resolve({ uuid, failed: true, plain: { subject: 'Invalid key!' } })
        })
        .then(importSessionKey)
        .then(decryptCipherText)
        .catch(error => {
          console.error(error)
          resolve({
            uuid,
            failed: true,
            plain: { subject: 'Could not decrypt message!!' },
          })
        })
        .then(plainText => {
          if (plainText) {
            const plain = utils.arrayBufferToObject(plainText)
            resolve({ uuid, failed: false, plain })
          }
        })
        .catch(error => {
          console.error(error)
          resolve({
            uuid,
            failed: true,
            plain: { subject: 'Something went wrong!!' },
          })
        }),
    )

  const decryptItemAssignment = () =>
    importPublicVerifyKey()
      .then(saveImportedPublicVerifyKey)
      .then(verifyEncryptedMessage)
      .then(handleMessageVerification)
      .then(keyStore.getPdk)
      .then(decryptKey)
      .then(saveSessionKey)
      .then(importSessionKey)
      .then(decryptCipherText)
      .then(plainText => {
        const result = {
          json: utils.arrayBufferToObject(plainText),
          key: utils.arrayBufferToBase64(sessionKey),
        }
        return result
      })
      .catch(error => {
        console.error(error)
        return error
      })

  const decryptItem = (itemId, referenceId) =>
    importPublicVerifyKey()
      .then(saveImportedPublicVerifyKey)
      .then(verifyEncryptedMessage)
      .then(handleMessageVerification)
      .then(() => encryptedKey)
      .then(importSessionKey)
      .then(decryptCipherText)
      .then(plainText => {
        const result = {
          plain: utils.arrayBufferToObject(plainText),
          id: itemId,
          rid: referenceId,
        }
        return result
      })
      .catch(error => {
        console.error(error)
        return error
      })

  const decryptFilePart = (id, partNumber) => {
    const algo = algorithms.AES_GCM_ALGO
    return importSessionKey(null, algo)
      .then(key => decryptCipherText(key, algorithms.AES_GCM.name))
      .then(plainFile => {
        const result = {
          id,
          part: partNumber,
          file: plainFile,
        }
        return result
      })
      .catch(error => {
        console.error(error)
        return Promise.reject(error)
      })
  }

  return {
    decrypt,
    decryptGroupKey,
    decryptGroupMessage,
    decryptFile,
    decrypt2,
    decryptItemAssignment,
    decryptItem,
    decryptFilePart,
    protocol,
    decryptIt,
    verifyIt,
    justDecryptIt,
  }
}
