/* eslint-disable max-lines */
/* eslint-disable camelcase */
/* eslint-disable no-param-reassign */
import { kryptos } from '../kryptos/kryptos'
import * as utils from '../kryptos/utils'
import * as algorithms from '../kryptos/algorithms'
import * as formats from '../kryptos/formats'
import * as usage from '../kryptos/usages'
import { LENGTH_256, EXTRACTABLE, NONEXTRACTABLE } from '../kryptos/constants'
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
 * The Kryptos Encrypter module.
 *
 * @param {Kryptos.KeyStore} serviceKeyStore
 * @param {String} plainText
 * @param {Array} recipients
 * @param {function} callback
 * @returns {Kryptos.Encrypter} the public methods
 */
export const Encrypter = function Encrypter(
  serviceKeyStore,
  plainText,
  recipients,
  callback,
) {
  const keyStore = serviceKeyStore
  const plain = plainText
  let sessionKey = null
  let exportedSessionKey = null
  let encryptedPlainText = null
  let signature = null
  const encrypterCallback = callback

  const deriveSessionKey = (algorithm, pdk, pek) =>
    kryptos.subtle.deriveKey(
      { name: 'ECDH', namedCurve: 'P-521', public: pek },
      pdk,
      algorithm,
      EXTRACTABLE,
      usage.ENCRYPT,
    )

  const importSessionKey = (keyBytes, algo) =>
    kryptos.subtle.importKey(
      formats.RAW,
      keyBytes,
      algo || algorithms.AES_CBC_ALGO,
      NONEXTRACTABLE,
      usage.ENCRYPT,
    )

  const generateSessionKey = (usages, algorithm) =>
    kryptos.subtle.generateKey(
      algorithm || algorithms.AES_CBC_ALGO,
      EXTRACTABLE,
      usages || usage.ENCRYPT,
    )

  const getSessionKey = (usages, algo, key) => {
    if (key) {
      if (key instanceof CryptoKey) {
        return new Promise(resolve => {
          resolve(key)
        })
      }
      return importSessionKey(key, algo)
    }
    return generateSessionKey(usages, algo)
  }

  const saveSessionKey = generatedSessionKey => {
    sessionKey = generatedSessionKey
    return sessionKey
  }

  const importHmacKey = raw =>
    kryptos.subtle.importKey(
      formats.RAW,
      raw,
      algorithms.HMAC_ALGO,
      NONEXTRACTABLE,
      usage.SIGN,
    )

  const encryptPlainText = key => {
    const iv = utils.nonce()
    const algo = { name: key.algorithm.name, iv }
    if (algo.name === 'AES-GCM') {
      algo.tagLength = 128
    }
    return kryptos.subtle
      .encrypt(algo, key, utils.stringToArrayBuffer(JSON.stringify(plain)))
      .then(cipherText => [iv, new Uint8Array(cipherText)])
  }

  const saveEncryptedPlainText = ivAndCiphertext => {
    encryptedPlainText = ivAndCiphertext
    return sessionKey
  }

  const exportSessionKey = key => {
    if (exportedSessionKey) {
      return exportedSessionKey
    }
    return kryptos.subtle.exportKey(formats.RAW, key || sessionKey)
  }

  const saveExportedSessionKey = exportedKey => {
    exportedSessionKey = exportedKey
  }

  const signEncryptedPlainText = psk => {
    if (!psk) {
      return ''
    }
    return kryptos.subtle.sign(
      algorithms.getSignAlgo(psk.algorithm.name),
      psk,
      new Uint8Array(encryptedPlainText[1]),
    )
  }

  const hmacSign = signKey =>
    kryptos.subtle.sign(algorithms.HMAC_ALGO, signKey, encryptedPlainText[1])

  const saveSignature = fileSignature => {
    signature = fileSignature
  }

  const encryptSessionKey = publicEncryptKey =>
    kryptos.subtle.encrypt(
      algorithms.RSA_OAEP_ALGO,
      publicEncryptKey,
      exportedSessionKey,
    )

  /**
   * Encrypt Session Key Promise, encrypts the message session key with the
   * recipients public encrypt key.
   *
   * @param {String} recipient
   * @returns {Promise}
   */
  const encryptRecipientSessionKey = recipient =>
    new Promise((resolve, reject) =>
      keyStore.getPublicKey(recipient, 'encrypt').then(pek =>
        keyStore
          .importPek(pek, ['encrypt'])
          .then(publicKey => encryptSessionKey(publicKey))
          .then(encryptedSessionKey => {
            resolve({
              u: recipient,
              k: utils.arrayBufferToBase64(encryptedSessionKey),
            })
          })
          .catch(error => {
            console.error(error)
            reject(
              new Error(
                `encrypt key error: Something went wrong encrypting key ${
                  error.message
                }\n${error.stack}`,
              ),
            )
          }),
      ),
    )

  const encryptSessionKeys = () => {
    const promises = Object.values(recipients)
      .flat()
      .map(key => encryptRecipientSessionKey(key))
    return Promise.all(promises)
  }

  const packageResults = keys => {
    const signatureLength = new Uint16Array([signature.byteLength])
    return {
      blob: new Blob(
        [
          new Uint16Array([LENGTH_256]), // keyLength, // 2 bytes
          signatureLength, // 2 bytes
          new ArrayBuffer(LENGTH_256), // encryptedKey, // 256 bytes
          signature, // 256 bytes
          encryptedPlainText[0],
          encryptedPlainText[1],
        ],
        { type: 'application/octet-stream' },
      ),
      keys,
    }
  }

  const encryptMessage = () =>
    generateSessionKey()
      .then(saveSessionKey)
      .then(encryptPlainText)
      .then(saveEncryptedPlainText)
      .then(exportSessionKey)
      .then(saveExportedSessionKey)
      .then(keyStore.getPsk)
      .then(signEncryptedPlainText)
      .then(saveSignature)
      .then(encryptSessionKeys)
      .then(packageResults)
      .then(result => {
        encrypterCallback(true, result)
      })
      .catch(error => {
        console.error(error)
        if (encrypterCallback) {
          encrypterCallback(false, error.message ? error.message : error)
        }
      })

  /**
   * Encrypt File Promise, encrypts an individual file/attachment
   * belonging to a message.
   *
   * @param {ArrayBuffer} file
   * @param {string} id
   * @returns {Promise}
   */
  const encryptFile = (file, id) => {
    let fileSessionKey = null
    let exportedFileSessionKey = null
    let encryptedFile = null
    const result = []
    result.id = id
    return new Promise((resolve, reject) =>
      generateSessionKey()
        // Save raw file session and export it
        .then(key => {
          fileSessionKey = key

          return kryptos.subtle.exportKey(formats.RAW, key)
        })
        // Save File Session Key
        .then(exportedKey => {
          result.key = utils.arrayBufferToHex(exportedKey)
          exportedFileSessionKey = exportedKey
        })
        // Encrypt File
        .then(() => {
          const iv = utils.nonce()
          return kryptos.subtle
            .encrypt({ name: 'AES-CBC', iv }, fileSessionKey, file)
            .then(cipherText => {
              encryptedFile = [iv, new Uint8Array(cipherText)]
            })
        })
        // Import sign key
        .then(() =>
          kryptos.subtle.importKey(
            formats.RAW,
            exportedFileSessionKey,
            algorithms.HMAC_ALGO,
            NONEXTRACTABLE,
            usage.SIGN,
          ),
        )
        // Sign File
        .then(signKey =>
          kryptos.subtle.sign(algorithms.HMAC_ALGO, signKey, encryptedFile[1]),
        )
        // Save HMAC signaure
        .then(sig => {
          result.hmac = utils.arrayBufferToHex(sig)
        })
        // Blob it up
        .then(() => {
          // eslint-disable-next-line camelcase
          result.file_transfer = new Blob(encryptedFile, {
            type: 'application/octet-stream',
          })
          resolve(result)
        })
        .catch(error => {
          console.error(error)
          reject(
            new Error(
              `encryptFile: Something went wrong encrypting file ${
                error.message
              }\n${error.stack}`,
            ),
          )
        }),
    )
  }

  /*
  * 1. AES Key: Get HMAC of plain file part with 32 0 bytes key
  * 2. Encrypt file part with HMAC -> AES key
  * 2. HMAC: Get HMAC of encrypted file part
  * 3. partsize = 4194304
  */
  const encryptFilePart = (file, id, partNumber) => {
    const iv = utils.nonce()
    let aesKey = null
    let encryptedFile = null

    return new Promise((resolve, reject) =>
      generateSessionKey(usage.ENCRYPT, algorithms.AES_GCM_ALGO)
        .then(key => {
          aesKey = key
          return aesKey
        })
        // Encrypt file part
        .then(key =>
          kryptos.subtle.encrypt(
            { name: 'AES-GCM', iv, tagLength: 128 },
            key,
            file,
          ),
        )
        // Save encrypted file part
        .then(cipherText => {
          encryptedFile = new Uint8Array(cipherText)
          return aesKey
        })
        .then(exportSessionKey)
        .then(rawAesKey => {
          const result = {
            id,
            part: partNumber,
            encrypted: new Blob([encryptedFile], {
              type: 'application/octet-stream',
            }),
            key: utils.arrayBufferToBase64(rawAesKey),
            iv: utils.arrayBufferToBase64(iv),
            enctype: 'AES-GCM-256',
          }
          return resolve(result)
        })
        .catch(error => {
          console.error(error)
          reject(
            new Error(
              `encryptFilePart: Something went wrong encrypting file ${
                error.message
              }\n${error.stack}`,
            ),
          )
          return error
        }),
    )
  }

  /**
   * Encrypt Session Key Promise, encrypts the message session key with the
   * recipients public encrypt key.
   *
   * @param {String} recipient
   * @returns {Promise}
   */
  const encryptRecipientAssignmentKey = recipient => {
    const username = recipient
    return new Promise((resolve, reject) => {
      keyStore.getPublicKey(username, 'encrypt', pek =>
        keyStore
          .importPek(pek, ['encrypt'])
          .then(publicKey => encryptSessionKey(publicKey))
          .then(encryptedSessionKey =>
            resolve({
              username: recipient.username ? recipient.username : username,
              key: utils.arrayBufferToBase64(encryptedSessionKey),
            }),
          )
          .catch(error => {
            console.error(error)
            reject(
              new Error(
                `encrypt key error: Something went wrong encrypting key ${
                  error.message
                }\n${error.stack}`,
              ),
            )
          }),
      )
    })
  }

  const encryptAssignmentKey = () => {
    const promises = []

    for (let i = 0; i < recipients.length; i += 1) {
      promises.push(encryptRecipientAssignmentKey(recipients[i]))
    }

    return Promise.all(promises)
  }

  const protocol = (message, envelope, pek) => {
    let nodePek = null
    return keyStore
      .importPek(pek, [])
      .then(importedPek => {
        nodePek = importedPek
      })
      .then(keyStore.getPdk)
      .then(pdk => deriveSessionKey(algorithms.AES_GCM_ALGO, pdk, nodePek))
      .then(saveSessionKey)
      .then(encryptPlainText)
      .then(saveEncryptedPlainText)
      .then(exportSessionKey)
      .then(() => {
        envelope.iv = utils.arrayBufferToBase64(encryptedPlainText[0])
        envelope.data = utils.arrayBufferToBase64(encryptedPlainText[1])
        message.ServiceData = envelope
        encryptedPlainText[1] = utils.stringToArrayBuffer(
          JSON.stringify(message),
        )
      })
      .then(keyStore.getPsk)
      .then(signEncryptedPlainText)
      .then(sig => {
        message.Sign = utils.arrayBufferToBase64(sig)
        encrypterCallback(true, message)
        return message
      })
      .catch(error => {
        console.error(error)
        if (encrypterCallback) {
          encrypterCallback(false, error.message ? error.message : error)
        }
      })
  }

  const encryptIt = (algo, key) => {
    exportedSessionKey = key
    return getSessionKey(usage.ENCRYPT, algo, key)
      .then(saveSessionKey)
      .then(encryptPlainText)
      .then(saveEncryptedPlainText)
      .then(exportSessionKey)
      .then(saveExportedSessionKey)
      .then(keyStore.getPsk)
      .then(signEncryptedPlainText)
      .then(saveSignature)
      .then(encryptSessionKeys)
      .then(sessionKeys => {
        encrypterCallback(true, {
          m: utils.arrayBufferToBase64(encryptedPlainText[1]),
          iv: utils.arrayBufferToBase64(encryptedPlainText[0]),
          s: utils.arrayBufferToBase64(signature),
          keys: sessionKeys,
        })
      })
      .catch(error => {
        console.error(error)
        if (encrypterCallback) {
          encrypterCallback(false, error.message ? error.message : error)
        }
      })
  }

  const signIt = (data, includeSignature, base64Url) => {
    encryptedPlainText = []
    encryptedPlainText[1] = utils.stringToArrayBuffer(JSON.stringify(data))
    return keyStore
      .getPsk()
      .then(signEncryptedPlainText)
      .then(sig => {
        const s = utils.arrayBufferToBase64(sig, base64Url)
        if (includeSignature) {
          data.signature = s
        } else {
          data = { data, signature: s }
        }
        encrypterCallback(true, data)
        return data
      })
      .catch(error => {
        console.error(error)
        if (encrypterCallback) {
          encrypterCallback(false, error.message ? error.message : error)
        }
        return error
      })
  }

  const macSignIt = (data, key) => {
    encryptedPlainText = []
    encryptedPlainText[1] = utils.stringToArrayBuffer(data)
    return importHmacKey(utils.stringToArrayBuffer(key))
      .then(hmacSign)
      .then(sig => {
        const result = { data, signature: utils.arrayBufferToBase64(sig) }
        encrypterCallback(true, result)
        return result
      })
      .catch(error => {
        console.error(error)
        if (encrypterCallback) {
          encrypterCallback(false, error.message ? error.message : error)
        }
        return error
      })
  }

  const encryptChatMessage = algo => encryptIt(algo || algorithms.AES_CBC_ALGO)

  const encryptGroupChatMessage = key => encryptIt(algorithms.AES_GCM_ALGO, key)

  const encryptGroupChatKey = () =>
    generateSessionKey(usage.ENCRYPT, algorithms.AES_GCM_ALGO)
      .then(saveSessionKey)
      .then(exportSessionKey)
      .then(saveExportedSessionKey)
      .then(encryptSessionKeys)
      .then(sessionKeys => {
        encrypterCallback(true, {
          members_keys: sessionKeys,
        })
      })
      .catch(error => {
        console.error(error)
        if (encrypterCallback) {
          encrypterCallback(false, error.message)
        }
      })

  const encryptExistingGroupChatKey = key => {
    saveExportedSessionKey(key)
    return importSessionKey(key)
      .then(saveSessionKey)
      .then(encryptSessionKeys)
      .then(sessionKeys => {
        encrypterCallback(true, {
          members_keys: sessionKeys,
        })
      })
      .catch(error => {
        console.error(error)
        if (encrypterCallback) {
          encrypterCallback(false, error.message)
        }
      })
  }

  const encryptNewItemAssignment = () =>
    generateSessionKey()
      .then(saveSessionKey)
      .then(encryptPlainText)
      .then(saveEncryptedPlainText)
      .then(exportSessionKey)
      .then(saveExportedSessionKey)
      .then(keyStore.getPsk)
      .then(signEncryptedPlainText)
      .then(saveSignature)
      .then(keyStore.getPek)
      .then(encryptSessionKey)
      .then(key => {
        const result = {
          message: utils.arrayBufferToBase64(encryptedPlainText[1]),
          iv: utils.arrayBufferToBase64(encryptedPlainText[0]),
          signature: utils.arrayBufferToBase64(signature),
          key: utils.arrayBufferToBase64(exportedSessionKey),
          // ask Mickey, Key never used, correct ?
          // only diff between encryptNewItem is below encrypted_key
          encrypted_key: new Blob([key], {
            type: 'application/octet-stream',
          }),
        }
        encrypterCallback(true, result)
        return result
      })
      .catch(error => {
        console.error(error)
        if (encrypterCallback) {
          encrypterCallback(false, error)
        }
        return error
      })

  const encryptItemAssignment = existingKey => {
    saveExportedSessionKey(existingKey)
    return encryptAssignmentKey()
      .then(result => {
        encrypterCallback(true, result)
        return result
      })
      .catch(error => {
        console.error(error)
        if (encrypterCallback) {
          encrypterCallback(false, error)
        }
        return error
      })
  }

  const encryptNewItem = rid =>
    generateSessionKey()
      .then(saveSessionKey)
      .then(encryptPlainText)
      .then(saveEncryptedPlainText)
      .then(exportSessionKey)
      .then(saveExportedSessionKey)
      .then(keyStore.getPsk)
      .then(signEncryptedPlainText)
      .then(saveSignature)
      .then(() => {
        const result = {
          message: utils.arrayBufferToBase64(encryptedPlainText[1]),
          iv: utils.arrayBufferToBase64(encryptedPlainText[0]),
          signature: utils.arrayBufferToBase64(signature),
          key: utils.arrayBufferToBase64(exportedSessionKey),
          rid,
        }
        encrypterCallback(true, result)
        return result
      })
      .catch(error => {
        console.error(error)
        if (encrypterCallback) {
          encrypterCallback(false, error)
        }
        return error
      })

  const encryptExistingItem = existingKey =>
    importSessionKey(existingKey)
      .then(encryptPlainText)
      .then(saveEncryptedPlainText)
      .then(keyStore.getPsk)
      .then(signEncryptedPlainText)
      .then(saveSignature)
      .then(() => {
        const result = {
          message: utils.arrayBufferToBase64(encryptedPlainText[1]),
          iv: utils.arrayBufferToBase64(encryptedPlainText[0]),
          signature: utils.arrayBufferToBase64(signature),
        }
        encrypterCallback(true, result)
        return result
      })
      .catch(error => {
        console.error(error)
        if (encrypterCallback) {
          encrypterCallback(false, error)
        }
        return error
      })

  return {
    encrypt: encryptMessage,
    encryptFile,
    encryptChatMessage,
    encryptGroupChatMessage,
    encryptGroupChatKey,
    encryptExistingGroupChatKey,
    encryptNewItemAssignment,
    encryptItemAssignment,
    encryptNewItem,
    encryptExistingItem,
    encryptFilePart,
    protocol,
    encryptIt,
    signIt,
    macSignIt,
  }
}
