import { KRYPTOS } from './kryptos.core'
/* global KRYPTOS, CryptoKey */

/**
 * KRYPTOS is a cryptographic library wrapping and implementing the
 * Web Cryptography API. It supports both symmetric keys and asymmetric key pair
 * generation, encryption, decryption, signing and verification.
 *
 *
 * @name KRYPTOS
 * @copyright Copyright © FortKnoxster Ltd. 2014 - 2018.
 * @license Apache License, Version 2.0 http://www.apache.org/licenses/LICENSE-2.0
 * @author MJ <mj@fortknoxster.com>
 * @version 4.0
 */

/**
 * The KRYPTOS Decrypter module.
 *
 * @param {KRYPTOS.KeyStore} serviceKeyStore
 * @param {ByteArray} encryptedKey
 * @param {ByteArray} iv
 * @param {ByteArray} cipherText
 * @param {ByteArray} signature
 * @param {CryptoKey} theirPublicKey
 * @param {CryptoKey} privateKey
 * @param {type} callback
 * @returns {void}
 */
export const Decrypter = function(
  serviceKeyStore,
  encryptedKey,
  iv,
  cipherText,
  signature,
  theirPublicKey,
  privateKey,
  callback,
) {
  const keyStore = serviceKeyStore
  const key = encryptedKey
  var iv = iv
  var cipherText = cipherText
  let publicKey = theirPublicKey
  var privateKey = privateKey
  var signature = signature
  var callback = callback
  let sessionKey = null
  let hmacKey = null

  const deriveSessionKey = function(algorithm, pdk, pek) {
    return KRYPTOS.cryptoSubtle.deriveKey(
      { name: 'ECDH', namedCurve: 'P-521', public: pek },
      pdk,
      algorithm,
      KRYPTOS.EXTRACTABLE,
      KRYPTOS.ENCRYPT_USAGE,
    )
  }

  const verifyEncryptedMessage = function() {
    return KRYPTOS.cryptoSubtle.verify(
      KRYPTOS.getSignAlgo(publicKey.algorithm.name),
      publicKey,
      signature,
      cipherText,
    ) // cipherText

    // return true;
  }

  const verifyEncryptedFile = function(verifyKey) {
    hmacKey = verifyKey
    return KRYPTOS.cryptoSubtle.verify(
      KRYPTOS.HMAC,
      verifyKey,
      signature,
      cipherText,
    ) // cipherText
  }

  const handleMessageVerification = function(successful) {
    if (successful !== true) {
      throw 'Verification Error: The sender could not be verified. Decryption of this message has been cancelled.'
    }
  }

  const handleFileVerification = function(successful) {
    if (successful !== true) {
      throw 'Verification Error: The file integrity could not be verified. File corrupted.'
    }
  }

  const decryptKey = function(pdk) {
    return KRYPTOS.cryptoSubtle.decrypt(
      { name: 'RSA-OAEP' },
      pdk || privateKey,
      key,
    )
  }

  const unwrapKey = function(pdk) {
    return KRYPTOS.cryptoSubtle.unwrapKey(
      'raw',
      key,
      pdk,
      { name: 'RSA-OAEP' },
      { name: 'AES-GCM' },
      KRYPTOS.NONEXTRACTABLE,
      KRYPTOS.ENCRYPT_USAGE,
    )
    // return KRYPTOS.cryptoSubtle.decrypt({name: "RSA-OAEP"}, pdk, key);
  }

  const importSessionKey = function(keyBytes, algo) {
    if (!keyBytes) {
      keyBytes = key
    }
    if (keyBytes instanceof CryptoKey) {
      log('CryptoKey')
      return new KRYPTOS.Promise((resolve, reject) => {
        resolve(key)
      })
    }
    if (!algo) {
      algo = KRYPTOS.AES_CBC_ALGO
    }
    return KRYPTOS.cryptoSubtle.importKey(
      'raw',
      keyBytes,
      algo,
      KRYPTOS.NONEXTRACTABLE,
      KRYPTOS.ENCRYPT_USAGE,
    )
  }

  const saveSessionKey = function(key) {
    sessionKey = key
    return sessionKey
  }

  const savePublicKey = function(key) {
    publicKey = key
    return publicKey
  }

  const decryptCipherText = function(sessionKey, algorithm) {
    let algo = {}
    if (algorithm && algorithm.indexOf('AES-GCM') !== -1) {
      algo = { name: 'AES-GCM', iv, tagLength: 128 }
    } else {
      algo = { name: 'AES-CBC', iv }
    }
    return KRYPTOS.cryptoSubtle.decrypt(algo, sessionKey, cipherText)
  }

  const handlePlainText = function(plainText) {
    const json = KRYPTOS.utils.ab2json(plainText)
    callback(json)
  }

  const handlePlainFile = function(plainFile) {
    callback(true, plainFile)
  }

  const importVerifyKey = function() {
    return KRYPTOS.cryptoSubtle.importKey(
      'raw',
      key,
      KRYPTOS.HMAC_ALGO,
      KRYPTOS.NONEXTRACTABLE,
      ['sign', 'verify'],
    )
  }

  const importPublicVerifyKey = function() {
    return KRYPTOS.cryptoSubtle.importKey(
      'jwk',
      publicKey,
      KRYPTOS.getImportAlgo(publicKey.kty),
      false,
      ['verify'],
    )
  }

  const saveImportedPublicVerifyKey = function(publicVerifyKey) {
    publicKey = publicVerifyKey
  }

  //    var extractData = function(data) {
  //        var signatureLength = KRYPTOS.utils.byteLength(publicKey);
  //        signature = new Uint8Array(data, 0, signatureLength);
  //        plain = new Uint8Array(data, signatureLength);
  //        return publicKey;
  //    };

  const protocol = function(data, pvk, pek, verifyOnly) {
    cipherText = KRYPTOS.utils.str2ab(JSON.stringify(data))
    let nodePek = null
    log(cipherText)
    return keyStore
      .importPvk(pvk, ['verify'])
      .then(saveImportedPublicVerifyKey)
      .then(verifyEncryptedMessage)
      .then(handleMessageVerification)
      .then(() => {
        if (verifyOnly) {
          callback(true)
        } else var message = data.ServiceData
        iv = KRYPTOS.utils.b642ab(message.iv)
        cipherText = KRYPTOS.utils.b642ab(message.data)
        keyStore
          .importPek(pek, [])
          .then(importedPek => {
            nodePek = importedPek
          })
          .then(keyStore.getPdk)
          .then(pdk => {
            log('pdk ---------------------------')
            log(pdk)
            return deriveSessionKey(KRYPTOS.AES_GCM_ALGO, pdk, nodePek)
          })
          .then(key => {
            log('deriveSessionKey key done!')
            log(key)
            return decryptCipherText(key, 'AES-GCM')
          })
          .then(handlePlainText)
          .catch(error => {
            KRYPTOS.utils.log(error)
            callback(false, error)
          })
      })
      .catch(error => {
        KRYPTOS.utils.log(error)
        callback(false, error)
      })
  }

  const justDecryptIt = function(id, algo, key) {
    sessionKey = key
    return new KRYPTOS.Promise((resolve, reject) => {
      if (!key) {
        return keyStore
          .getPdk()
          .then(decryptKey)
          .then(saveSessionKey)
          .then(() => {
            resolve(sessionKey)
          })
      }
      //                return sessionKey;
      resolve(sessionKey)
    })
      .then(sessionKey => importSessionKey(sessionKey, KRYPTOS.getAlgo(algo)))
      .then(key => decryptCipherText(key, algo))
      .then(plainText => {
        const data = {
          id,
          plain: KRYPTOS.utils.ab2json(plainText),
          failed: false,
          key: KRYPTOS.utils.ab2b64(sessionKey),
        }
        if (callback) {
          callback(data)
        } else {
          return new KRYPTOS.Promise((resolve, reject) => {
            resolve(data)
          })
        }
      })
      .catch(error => {
        KRYPTOS.utils.log(error)
        if (callback) {
          callback(false, error)
        } else {
          return new KRYPTOS.Promise((resolve, reject) => {
            resolve(error)
          })
        }
      })
  }

  const decryptIt = function(from, id, algo, key) {
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
        KRYPTOS.utils.log(error)
        if (callback) {
          callback(false, error)
        }
      })
  }

  const verifyIt = function(from, id) {
    return (
      keyStore
        .getPublicKey(from, 'verify')
        .then(savePublicKey)
        .then(keyStore.importPvk)
        .then(saveImportedPublicVerifyKey)
        .then(verifyEncryptedMessage)
        .then(handleMessageVerification)
        //                        .catch(function (error) {
        // //                            alert('ERROR! Check console!');
        //                        })
        .then(() => {
          const data = {
            id,
          }
          if (callback) {
            callback(data)
          } else {
            return new KRYPTOS.Promise((resolve, reject) => {
              resolve(data)
            })
          }
        })
        .catch(error => {
          KRYPTOS.utils.log(error)
          if (callback) {
            callback(false, error)
          } else {
            return new KRYPTOS.Promise((resolve, reject) => {
              resolve(error)
            })
          }
        })
    )
  }

  var log = function(msg) {
    return false
  }

  return {
    decrypt() {
      return importPublicVerifyKey()
        .then(saveImportedPublicVerifyKey)
        .then(verifyEncryptedMessage)
        .then(handleMessageVerification)
        .then(keyStore.getPdk)
        .then(decryptKey)
        .then(importSessionKey)
        .then(decryptCipherText)
        .then(handlePlainText)
        .catch(error => {
          KRYPTOS.utils.log(error)
          callback(false, error)
        })
    },
    decrypt3() {
      return decryptKey()
        .then(importSessionKey)
        .then(decryptCipherText)
        .then(handlePlainText)
        .catch(error => {
          KRYPTOS.utils.log(error)
          callback(false, error)
        })
    },
    decryptGroupKey(raw) {
      if (raw) {
        return keyStore
          .getPdk()
          .then(decryptKey)
          .then(result => {
            callback(true, result)
          })
          .catch(error => {
            KRYPTOS.utils.log(error)
            callback(false, error)
          })
      }
      return (
        keyStore
          .getPdk()
          .then(unwrapKey)
          //                    .then(decryptKey)
          //                    .then(importGroupSessionKey)
          .then(result => {
            callback(true, result)
          })
          .catch(error => {
            KRYPTOS.utils.log(error)
            callback(false, error)
          })
      )
    },
    decryptGroupMessage(from, id) {
      return decryptIt(from, id, 'AES-GCM', key)
    },
    decryptFile() {
      return (
        importVerifyKey()
          //                    .then(saveExportedFileSessionKey)
          //                    .then(importVerifyKey)
          .then(verifyEncryptedFile)
          .then(handleFileVerification)
          .then(importSessionKey)
          .then(decryptCipherText)
          .then(handlePlainFile)
          .catch(error => {
            KRYPTOS.utils.log(error)
            callback(false, error.message ? error.message : error)
          })
      )
    },
    decrypt2(from, uuid) {
      return new KRYPTOS.Promise((resolve, reject) =>
        //                return importPublicVerifyKey().catch(function (error) {log('a'); log(error); KRYPTOS.utils.log(error);})
        keyStore
          .getPublicKey(from, 'verify')
          .then(savePublicKey)
          .then(importPublicVerifyKey)
          .then(saveImportedPublicVerifyKey)
          .then(verifyEncryptedMessage)
          .catch(error => {
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
            resolve({ uuid, failed: true, plain: { subject: 'Error!' } }) // Incorrect key!!
          })
          .then(importSessionKey)
          .then(decryptCipherText)
          .catch(error => {
            KRYPTOS.utils.log(error)
            resolve({
              uuid,
              failed: true,
              plain: { subject: 'Could not decrypt message!!' },
            })
          })
          .then(plainText => {
            if (plainText) {
              const plain = KRYPTOS.utils.ab2json(plainText)
              resolve({ uuid, failed: false, plain })
            }
          })
          .catch(error => {
            KRYPTOS.utils.log(error)
            resolve({
              uuid,
              failed: true,
              plain: { subject: 'Something went wrong!!' },
            })
            // reject("DECRYPT 2: Something went wrong decrypting message " + error.message + "\n" + error.stack);
          }),
      )
    },
    decryptItemAssignment() {
      return importPublicVerifyKey()
        .catch(error => {
          log('a')
          log(error)
          KRYPTOS.utils.log(error)
        })
        .then(saveImportedPublicVerifyKey)
        .then(verifyEncryptedMessage)
        .catch(error => {
          log('b')
          log(error)
          KRYPTOS.utils.log(error)
        })
        .then(handleMessageVerification)
        .catch(error => {
          KRYPTOS.utils.log('decryptItemAssignment')
          KRYPTOS.utils.log(error)
          KRYPTOS.utils.log(error)
        })
        .then(keyStore.getPdk)
        .catch(error => {
          log('b2')
          log(error)
          KRYPTOS.utils.log(error)
        })
        .then(decryptKey)
        .catch(error => {
          log('c')
          log(error)
          KRYPTOS.utils.log(error)
        })
        .then(saveSessionKey)
        .then(importSessionKey)
        .catch(error => {
          log('d')
          log(error)
          KRYPTOS.utils.log(error)
        })
        .then(decryptCipherText)
        .catch(error => {
          log('e')
          log(error)
          KRYPTOS.utils.log(error)
        })
        .then(plainText => {
          callback({
            json: KRYPTOS.utils.ab2json(plainText),
            key: KRYPTOS.utils.ab2b64(sessionKey),
          })
        })
        .catch(error => {
          KRYPTOS.utils.log(error)
          callback(false, error)
        })
    },
    decryptItem(itemId, referenceId) {
      return (
        importPublicVerifyKey()
          .then(saveImportedPublicVerifyKey)
          .then(verifyEncryptedMessage)
          .then(handleMessageVerification)
          .catch(error => {
            KRYPTOS.utils.log('decryptItem')
            KRYPTOS.utils.log(error)
            KRYPTOS.utils.log(error)
          })
          //                    .then(decryptKey)
          .then(() => key)
          .then(importSessionKey)
          .catch(error => {
            KRYPTOS.utils.log(error)
            //                        resolve({uuid: uuid, failed: true, plain: {subject: "Incorrect key!!"}});
          })
          .then(decryptCipherText)
          .catch(error => {
            KRYPTOS.utils.log(error)
            //                        resolve({uuid: uuid, failed: true, plain: {subject: "Incorrect key!!"}});
          })
          .then(plainText => {
            callback({
              plain: KRYPTOS.utils.ab2json(plainText),
              id: itemId,
              rid: referenceId,
            })
          })
          .catch(error => {
            KRYPTOS.utils.log(error)
            callback(false, error)
          })
      )
    },
    decryptFilePart(id, partNumber) {
      //            return importVerifyKey()
      //                    .then(verifyEncryptedFile)
      //                    .then(handleFileVerification)
      //                    .then(importSessionKey)
      const algo = KRYPTOS.AES_GCM_ALGO
      return importSessionKey(null, algo)
        .then(key => {
          log(key)
          return decryptCipherText(key, 'AES-GCM')
        })
        .then(plainFile => {
          callback({
            id,
            part: partNumber,
            file: plainFile,
          })
        })
        .catch(error => {
          KRYPTOS.utils.log(error)
          callback(false, error.message ? error.message : error)
        })
    },
    protocol,
    decryptIt,
    verifyIt,
    justDecryptIt,
  }
}
