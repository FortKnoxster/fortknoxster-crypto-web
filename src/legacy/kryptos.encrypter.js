import { KRYPTOS } from './kryptos.core'
/* global Promise, CryptoKey */

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
 * The KRYPTOS Encrypter module.
 *
 * @param {KRYPTOS.KeyStore} serviceKeyStore
 * @param {String} plainText
 * @param {Array} recipients
 * @param {function} callback
 * @returns {KRYPTOS.Encrypter} the public methods
 */
export const Encrypter = function(
  serviceKeyStore,
  plainText,
  recipients,
  callback,
) {
  const KU = KRYPTOS.utils
  const keyStore = serviceKeyStore
  const plain = plainText
  let sessionKey = null
  let exportedSessionKey = null
  let encryptedPlainText = null
  let signature = null
  const encrypterCallback = callback
  const sendData = []
  const method = 'message'

  const deriveSessionKey = function(algorithm, pdk, pek) {
    return KRYPTOS.cryptoSubtle.deriveKey(
      { name: 'ECDH', namedCurve: 'P-521', public: pek },
      pdk,
      algorithm,
      KRYPTOS.EXTRACTABLE,
      KRYPTOS.ENCRYPT_USAGE,
    )
  }

  const getSessionKey = function(usage, algo, key) {
    if (key) {
      if (key instanceof CryptoKey) {
        return new KRYPTOS.Promise((resolve, reject) => {
          resolve(key)
        })
      }
      return importSessionKey(key, algo)
    }
    return generateSessionKey(usage, algo)
  }

  var generateSessionKey = function(usage, algorithm) {
    if (!usage) {
      usage = KRYPTOS.ENCRYPT_USAGE
    }
    if (!algorithm) {
      algorithm = KRYPTOS.AES_CBC_ALGO
    }
    return KRYPTOS.cryptoSubtle.generateKey(
      algorithm,
      KRYPTOS.EXTRACTABLE,
      usage,
    )
  }

  const saveSessionKey = function(generatedSessionKey, skip) {
    sessionKey = generatedSessionKey
    return sessionKey
  }

  var importSessionKey = function(keyBytes, algo) {
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

  const importHmacKey = function(raw) {
    return KRYPTOS.cryptoSubtle.importKey(
      'raw',
      raw,
      KRYPTOS.HMAC_ALGO,
      KRYPTOS.NONEXTRACTABLE,
      ['sign', 'verify'],
    )
  }

  const encryptPlainText = function(sessionKey) {
    const iv = KRYPTOS.nonce()
    const algo = { name: sessionKey.algorithm.name, iv }
    if (algo.name === 'AES-GCM') {
      algo.tagLength = 128
    }
    return KRYPTOS.cryptoSubtle
      .encrypt(algo, sessionKey, KU.str2ab(JSON.stringify(plain)))
      .then(cipherText => [iv, new Uint8Array(cipherText)])
  }

  const saveEncryptedPlainText = function(ivAndCiphertext) {
    encryptedPlainText = ivAndCiphertext
    return sessionKey
  }

  const exportSessionKey = function(key) {
    if (!key) {
      key = sessionKey
    }
    if (exportedSessionKey) {
      return exportedSessionKey
    }
    return KRYPTOS.cryptoSubtle.exportKey('raw', key)
  }

  const saveExportedSessionKey = function(exportedKey) {
    exportedSessionKey = exportedKey
    // return exportedSessionKey;
  }

  const signEncryptedPlainText = function(psk) {
    if (!psk) {
      return ''
    }
    return KRYPTOS.cryptoSubtle.sign(
      KRYPTOS.getSignAlgo(psk.algorithm.name),
      psk,
      new Uint8Array(encryptedPlainText[1]),
    )
  }

  const hmacSign = function(signKey) {
    return KRYPTOS.cryptoSubtle.sign(
      KRYPTOS.HMAC_ALGO,
      signKey,
      encryptedPlainText[1],
    )
  }

  const saveSignature = function(fileSignature) {
    signature = fileSignature
  }

  const encryptSessionKey = function(publicEncryptKey) {
    return KRYPTOS.cryptoSubtle.encrypt(
      KRYPTOS.RSA_OAEP_ALGO,
      publicEncryptKey,
      exportedSessionKey,
    )
  }

  const encryptSessionKeys = function() {
    const promises = []
    for (const prop in recipients) {
      if (recipients.hasOwnProperty(prop)) {
        for (let i = 0; i < recipients[prop].length; i++) {
          promises.push(encryptRecipientSessionKey(recipients[prop][i]))
        }
        KRYPTOS.Promise.all(promises).then(result => {
          sendData.keys = JSON.stringify(result)
        })
      }
    }

    return KRYPTOS.Promise.all(promises)
  }

  const packageResults = function(keys) {
    const signatureLength = new Uint16Array([signature.byteLength])
    return {
      blob: new Blob(
        [
          new Uint16Array([KRYPTOS.LENGTH_256]), // keyLength, // 2 bytes
          signatureLength, // 2 bytes
          new ArrayBuffer(KRYPTOS.LENGTH_256), // encryptedKey, // 256 bytes
          signature, // 256 bytes
          encryptedPlainText[0],
          encryptedPlainText[1],
        ],
        { type: 'application/octet-stream' },
      ),
      keys,
    }
  }

  const encryptMessage = function() {
    return generateSessionKey()
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
        KU.log(error)
        if (encrypterCallback) {
          encrypterCallback(false, error.message ? error.message : error)
        }
      })
  }

  /**
   * Encrypt Session Key Promise, encrypts the message session key with the
   * recipients public encrypt key.
   *
   * @param {String} recipient
   * @returns {Promise}
   */
  var encryptRecipientSessionKey = function(recipient) {
    const username = KU.extractUsernameFromFullName(recipient)
    let aesKey = null

    return new KRYPTOS.Promise((resolve, reject) =>
      keyStore.getPublicKey(username, 'encrypt').then(pek =>
        keyStore
          .importPek(pek, ['encrypt'])
          .then(publicKey => encryptSessionKey(publicKey))
          .then(encryptedSessionKey => {
            aesKey = encryptedSessionKey
            return new Blob([encryptedSessionKey], {
              type: 'application/octet-stream',
            })
          })
          .then(blob => {
            //                        sendData['key_' + KU.dot2us(username)] = blob;
            resolve({ u: username, k: KU.ab2b64(aesKey) })
          })
          .catch(error => {
            KU.log(error)
            reject(
              `encrypt key error: Something went wrong encrypting key ${
                error.message
              }\n${error.stack}`,
            )
          }),
      ),
    )
  }

  /**
   * Encrypt File Promise, encrypts an individual file/attachment
   * belonging to a message.
   *
   * @param {ArrayBuffer} file
   * @param {string} id
   * @returns {Promise}
   */
  const encryptFile = function(file, id) {
    let fileSessionKey = null
    let exportedFileSessionKey = null
    let encryptedFile = null
    const result = []
    result.id = id
    //        if (options === null) {
    //            options = {
    //                'resource': 'messages',
    //                'type'    : 'attachment'
    //            };
    //        }
    return new KRYPTOS.Promise((resolve, reject) =>
      generateSessionKey()
        // Save raw file session and export it
        .then(key => {
          fileSessionKey = key

          return KRYPTOS.cryptoSubtle.exportKey('raw', key)
        })
        // Save File Session Key
        .then(exportedSessionKey => {
          result.key = KU.ab2hex(exportedSessionKey)
          exportedFileSessionKey = exportedSessionKey
        })
        // Encrypt File
        .then(() => {
          const iv = KRYPTOS.nonce()
          return KRYPTOS.cryptoSubtle
            .encrypt({ name: 'AES-CBC', iv }, fileSessionKey, file)
            .then(cipherText => {
              encryptedFile = [iv, new Uint8Array(cipherText)]
            })
        })
        // Import sign key
        .then(() =>
          KRYPTOS.cryptoSubtle.importKey(
            'raw',
            exportedFileSessionKey,
            KRYPTOS.HMAC_ALGO,
            KRYPTOS.NONEXTRACTABLE,
            ['sign', 'verify'],
          ),
        )
        // Sign File
        .then(signKey =>
          KRYPTOS.cryptoSubtle.sign(
            KRYPTOS.HMAC_ALGO,
            signKey,
            encryptedFile[1],
          ),
        )
        // Save HMAC signaure
        .then(signature => {
          result.hmac = KU.ab2hex(signature)
        })
        // Blob it up
        .then(() => {
          result.file_transfer = new Blob(encryptedFile, {
            type: 'application/octet-stream',
          })
          resolve(result)
          //                        return new Blob(
          //                                encryptedFile,
          //                                {type: "application/octet-stream"}
          //                        );
        })
        // Upload file and resolve Promise!
        //                    .then(function(blob) {
        //                        if (options['type'] === 'upload') {
        //                            sendData['file_transfer'] = blob;
        //                            sendData['to_username'] = options['to_username'];
        //                        } else {
        //                             sendData['attachment'] = blob;
        //                        }
        //                        //KU.sendData(sendData, 'messages', 'attachment', function(success, response) {
        //                        KU.sendData(sendData, options['resource'], options['type'], function(success, response) {
        //                            if (success) {
        //                                result['uuid'] = response.uuid;
        //                                result['status'] = success;
        //                                resolve([result]);
        //                            }
        //                            else {
        //                                result['status'] = success;
        //                                result['message'] = response;
        //                                uploadCallback = null;
        //                                resolve([result]);
        //                                //reject("Something went wrong uploading the encrypted file " + response.message + "\n" + response.stack);
        //                            }
        //                        }, uploadCallback);
        //                    })
        .catch(error => {
          KU.log(error)
          reject(
            `encryptFile: Something went wrong encrypting file ${
              error.message
            }\n${error.stack}`,
          )
        }),
    )
  }

  const encryptFilePart = function(file, id, partNumber) {
    const iv = KRYPTOS.nonce()
    let aesKey = null
    let encryptedFile = null

    return new KRYPTOS.Promise((resolve, reject) =>
      generateSessionKey(KRYPTOS.ENCRYPT_USAGE, KRYPTOS.AES_GCM_ALGO)
        .then(key => {
          aesKey = key
          return aesKey
        })
        // Encrypt file part
        .then(aesKey =>
          KRYPTOS.cryptoSubtle.encrypt(
            { name: 'AES-GCM', iv, tagLength: 128 },
            aesKey,
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
            //                    hmac: KU.ab2b64(signature),
            key: KU.ab2b64(rawAesKey),
            iv: KU.ab2b64(iv),
            enctype: 'AES-GCM-256',
          }
          return resolve(result)
        })
        .catch(error => {
          KU.log(error)
          reject(
            `encryptFilePart: Something went wrong encrypting file ${
              error.message
            }\n${error.stack}`,
          )
          return error
        }),
    )
  }

  const encryptAssignmentKey = function() {
    const promises = []

    for (let i = 0; i < recipients.length; i++) {
      promises.push(encryptRecipientAssignmentKey(recipients[i]))
    }

    return KRYPTOS.Promise.all(promises)
  }

  /**
   * Encrypt Session Key Promise, encrypts the message session key with the
   * recipients public encrypt key.
   *
   * @param {String} recipient
   * @returns {Promise}
   */
  var encryptRecipientAssignmentKey = function(recipient) {
    const username = recipient
    return new KRYPTOS.Promise((resolve, reject) => {
      keyStore.getPublicKey(username, 'encrypt', pek =>
        keyStore
          .importPek(pek, ['encrypt'])
          .then(publicKey => encryptSessionKey(publicKey))
          .then(encryptedSessionKey => {
            return resolve({
              username: recipient.username ? recipient.username : username,
              key: KU.ab2b64(encryptedSessionKey),
            })
          })
          .catch(error => {
            KU.log(error)
            reject(
              `encrypt key error: Something went wrong encrypting key ${
                error.message
              }\n${error.stack}`,
            )
          }),
      )
    })
  }

  const protocol = function(message, envelope, pek) {
    let nodePek = null
    return keyStore
      .importPek(pek, [])
      .catch(error => {
        KU.log(error)
      })
      .then(importedPek => {
        nodePek = importedPek
      })
      .then(keyStore.getPdk)
      .catch(error => {
        KU.log(error)
      })
      .then(pdk => deriveSessionKey(KRYPTOS.AES_GCM_ALGO, pdk, nodePek))
      .then(saveSessionKey)
      .then(encryptPlainText)
      .catch(error => {
        KU.log(error)
      })
      .then(saveEncryptedPlainText)
      .catch(error => {
        KU.log(error)
      })
      .then(exportSessionKey)
      .catch(error => {
        KU.log(error)
      })
      .then(key => {
        envelope.iv = KRYPTOS.utils.ab2b64(encryptedPlainText[0])
        envelope.data = KRYPTOS.utils.ab2b64(encryptedPlainText[1])
        message.ServiceData = envelope
        encryptedPlainText[1] = KRYPTOS.utils.str2ab(JSON.stringify(message))
      })
      .then(keyStore.getPsk)
      .then(signEncryptedPlainText)
      .then(signature => {
        message.Sign = KRYPTOS.utils.ab2b64(signature)
        encrypterCallback(true, message)
        return message
      })
      .catch(error => {
        KU.log(error)
        KU.log(error)
        if (encrypterCallback) {
          encrypterCallback(false, error.message ? error.message : error)
        }
      })
  }

  const encryptIt = function(algo, key, excludeSign) {
    exportedSessionKey = key
    return getSessionKey(KRYPTOS.ENCRYPT_USAGE, algo, key)
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
          m: KU.ab2b64(encryptedPlainText[1]),
          iv: KU.ab2b64(encryptedPlainText[0]),
          s: KU.ab2b64(signature),
          keys: sessionKeys,
        })
      })
      .catch(error => {
        KU.log(error)
        if (encrypterCallback) {
          encrypterCallback(false, error.message ? error.message : error)
        }
      })
  }

  const signIt = function(data, includeSignature, base64Url) {
    encryptedPlainText = []
    encryptedPlainText[1] = KRYPTOS.utils.str2ab(JSON.stringify(data))
    return keyStore
      .getPsk()
      .then(signEncryptedPlainText)
      .then(signature => {
        const s = KRYPTOS.utils.ab2b64(signature, base64Url)
        if (includeSignature) {
          data.signature = s
        } else {
          data = { data, signature: s }
        }
        encrypterCallback(true, data)
      })
      .catch(error => {
        KU.log(error)
        if (encrypterCallback) {
          encrypterCallback(false, error.message ? error.message : error)
        }
      })
  }

  const macSignIt = function(data, key) {
    encryptedPlainText = []
    encryptedPlainText[1] = KRYPTOS.utils.str2ab(data)
    return importHmacKey(KU.str2ab(key))
      .then(hmacSign)
      .then(signature => {
        encrypterCallback(true, { data, signature: KU.ab2b64(signature) })
      })
      .catch(error => {
        KU.log(error)
        if (encrypterCallback) {
          encrypterCallback(false, error.message ? error.message : error)
        }
      })
  }

  const encryptChatMessage = function(algo) {
    if (!algo) {
      algo = KRYPTOS.AES_CBC_ALGO
    }
    return encryptIt(algo)
  }

  const encryptGroupChatMessage = function(key) {
    return encryptIt(KRYPTOS.AES_GCM_ALGO, key)
  }

  const log = function(msg) {
    return false
  }

  return {
    encrypt: encryptMessage,

    encryptFile(file, id, callback) {
      return encryptFile(file, id)
        .then(result => {
          callback(result)
        })
        .catch(error => {
          KU.log(error)
          if (encrypterCallback) {
            callback(false, error.message)
          }
        })
    },

    encryptChatMessage,

    encryptGroupChatMessage,

    //        encryptGroupChatMessage: function(key) {
    //            saveSessionKey(key, true);
    //            return keyStore.getPsk()
    //                    .then(signPlainText)
    //                    .then(encryptSignedPlainText)
    //                    .then(function(encryptedPlainText) {
    //                        encrypterCallback(true, {
    //                            m: KU.ab2b64(encryptedPlainText[1]),
    //                            iv: KU.ab2b64(encryptedPlainText[0])
    //                        });
    //                    })
    //                    .catch(function (error) {
    //                        KU.log(error);
    //                        if (encrypterCallback) {
    //                            encrypterCallback(false, error.message);
    //                        }
    //                    });
    //        },

    encryptGroupChatKey() {
      return generateSessionKey(KRYPTOS.ENCRYPT_USAGE, KRYPTOS.AES_GCM_ALGO)
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
          KU.log(error)
          if (encrypterCallback) {
            encrypterCallback(false, error.message)
          }
        })
    },

    encryptExistingGroupChatKey(key) {
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
          KU.log(error)
          if (encrypterCallback) {
            encrypterCallback(false, error.message)
          }
        })
    },

    encryptSignatureMessage() {
      return generateSessionKey()
        .then(saveSessionKey)
        .then(encryptPlainText)
        .then(saveEncryptedPlainText)
        .then(exportSessionKey)
        .then(saveExportedSessionKey)
        .then(KRYPTOS.importIntermediateKeyUnwrapKey)
        .then(KRYPTOS.unwrapPrivateSignKey)
        .then(signEncryptedPlainText)
        .then(saveSignature)
        .then(encryptSessionKeys)
        .then(sessionKeys => {
          encrypterCallback(true, {
            m: KU.ab2b64(encryptedPlainText[1]),
            iv: KU.ab2b64(encryptedPlainText[0]),
            s: KU.ab2b64(signature),
            k: sessionKeys[0].k,
          })
        })
        .catch(error => {
          KU.log(error)
          if (encrypterCallback) {
            encrypterCallback(false, error.message)
          }
        })
    },

    encryptNewItemAssignment() {
      return generateSessionKey()
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
            message: KU.ab2b64(encryptedPlainText[1]),
            iv: KU.ab2b64(encryptedPlainText[0]),
            signature: KU.ab2b64(signature),
            key: KU.ab2b64(exportedSessionKey),
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
          KU.log(error)
          if (encrypterCallback) {
            encrypterCallback(false, error)
          }
          return error
        })
    },

    encryptItemAssignment(existingKey) {
      saveExportedSessionKey(existingKey)
      return encryptAssignmentKey()
        .then(result => {
          encrypterCallback(true, result)
          return result
        })
        .catch(error => {
          KU.log(error)
          if (encrypterCallback) {
            encrypterCallback(false, error)
          }
          return error
        })
    },

    // PSK should be cached previously
    encryptNewItem(rid) {
      return generateSessionKey()
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
            message: KU.ab2b64(encryptedPlainText[1]),
            iv: KU.ab2b64(encryptedPlainText[0]),
            signature: KU.ab2b64(signature),
            key: KU.ab2b64(exportedSessionKey),
            rid,
          }
          encrypterCallback(true, result)
          return result
        })
        .catch(error => {
          KU.log(error)
          if (encrypterCallback) {
            encrypterCallback(false, error)
          }
          return error
        })
    },

    encryptExistingItem(existingKey) {
      return importSessionKey(existingKey)
        .then(encryptPlainText)
        .then(saveEncryptedPlainText)
        .then(keyStore.getPsk)
        .then(signEncryptedPlainText)
        .then(saveSignature)
        .then(() => {
          const result = {
            message: KU.ab2b64(encryptedPlainText[1]),
            iv: KU.ab2b64(encryptedPlainText[0]),
            signature: KU.ab2b64(signature),
          }
          encrypterCallback(true, result)
          return result
        })
        .catch(error => {
          KU.log(error)
          if (encrypterCallback) {
            encrypterCallback(false, error)
          }
          return error
        })
    },

    /*
         * 1. AES Key: Get HMAC of plain file part with 32 0 bytes key
         * 2. Encrypt file part with HMAC -> AES key
         * 2. HMAC: Get HMAC of encrypted file part
         * 3. partsize = 4194304
         */
    encryptFilePart(file, id, partNumber, callback) {
      return encryptFilePart(file, id, partNumber, callback).then(result => {
        callback(result)
        return result
      })
    },

    protocol,

    encryptIt,

    signIt,

    macSignIt,
  }
}

KRYPTOS.Encrypter = Encrypter
