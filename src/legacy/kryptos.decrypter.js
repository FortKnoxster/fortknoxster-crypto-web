/* global KRYPTOS, CryptoKey */

"use strict";
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
KRYPTOS.Decrypter = function(serviceKeyStore, encryptedKey, iv, cipherText, signature, theirPublicKey, privateKey, callback) {
    var keyStore = serviceKeyStore;
    var key = encryptedKey;
    var iv = iv;
    var cipherText = cipherText;
    var publicKey = theirPublicKey;
    var privateKey = privateKey;
    var signature = signature;
    var callback = callback;
    var sessionKey = null;
    var hmacKey = null;

    var deriveSessionKey = function(algorithm, pdk, pek) {
        return KRYPTOS.cryptoSubtle.deriveKey({name: "ECDH", namedCurve: "P-521", public: pek}, pdk, algorithm, KRYPTOS.EXTRACTABLE, KRYPTOS.ENCRYPT_USAGE);
    };

    var verifyEncryptedMessage = function() {
        return KRYPTOS.cryptoSubtle.verify(KRYPTOS.getSignAlgo(publicKey.algorithm.name), publicKey, signature, cipherText); //cipherText

        //return true;
    };

    var verifyEncryptedFile = function(verifyKey) {
        hmacKey = verifyKey;
        return KRYPTOS.cryptoSubtle.verify(KRYPTOS.HMAC, verifyKey, signature, cipherText); //cipherText
    };

    var handleMessageVerification = function(successful) {
        if (successful !== true) {
            throw "Verification Error: The sender could not be verified. Decryption of this message has been cancelled.";
        }
    };

    var handleFileVerification = function(successful) {
        if (successful !== true) {
            throw "Verification Error: The file integrity could not be verified. File corrupted.";
        }
    };

    var decryptKey = function(pdk) {
        return KRYPTOS.cryptoSubtle.decrypt({name: "RSA-OAEP"}, pdk || privateKey, key);
    };

    var unwrapKey = function(pdk) {
        return KRYPTOS.cryptoSubtle.unwrapKey("raw", key, pdk, {name: "RSA-OAEP"}, {name: "AES-GCM"}, KRYPTOS.NONEXTRACTABLE, KRYPTOS.ENCRYPT_USAGE);
        //return KRYPTOS.cryptoSubtle.decrypt({name: "RSA-OAEP"}, pdk, key);
    };

    var importSessionKey = function(keyBytes, algo) {

        if (!keyBytes) {
            keyBytes = key;
        }
        if (keyBytes instanceof CryptoKey) {
            log('CryptoKey');
            return new KRYPTOS.Promise(function (resolve, reject) {
                resolve(key);
            });
        }
        if (!algo) {
            algo = KRYPTOS.AES_CBC_ALGO;
        }
        return KRYPTOS.cryptoSubtle.importKey("raw", keyBytes, algo, KRYPTOS.NONEXTRACTABLE, KRYPTOS.ENCRYPT_USAGE);
    };

    var saveSessionKey = function(key) {
        sessionKey = key;
        return sessionKey;
    };

    var savePublicKey = function(key) {
        publicKey = key;
        return publicKey;
    };

    var decryptCipherText = function(sessionKey, algorithm) {
        var algo = {};
        if (algorithm && algorithm.indexOf('AES-GCM') !== -1) {
            algo = {name: "AES-GCM", iv: iv, tagLength: 128};
        }
        else {
            algo = {name: "AES-CBC", iv: iv};
        }
        return KRYPTOS.cryptoSubtle.decrypt(algo, sessionKey, cipherText);
    };

    var handlePlainText = function(plainText) {
        var json = KRYPTOS.utils.ab2json(plainText);
        callback(json);
    };

    var handlePlainFile = function(plainFile) {
        callback(true, plainFile);
    };

    var importVerifyKey = function() {
        return KRYPTOS.cryptoSubtle.importKey('raw', key, KRYPTOS.HMAC_ALGO, KRYPTOS.NONEXTRACTABLE, ["sign", "verify"]);
    };

    var importPublicVerifyKey = function() {
        return KRYPTOS.cryptoSubtle.importKey("jwk", publicKey, KRYPTOS.getImportAlgo(publicKey.kty), false, ["verify"]);
    };

    var saveImportedPublicVerifyKey = function(publicVerifyKey) {
        publicKey = publicVerifyKey;
        return;
    };

//    var extractData = function(data) {
//        var signatureLength = KRYPTOS.utils.byteLength(publicKey);
//        signature = new Uint8Array(data, 0, signatureLength);
//        plain = new Uint8Array(data, signatureLength);
//        return publicKey;
//    };

    var protocol = function(data, pvk, pek, verifyOnly) {
        cipherText = KRYPTOS.utils.str2ab(JSON.stringify(data));
        var nodePek = null;
        log(cipherText);
        return keyStore.importPvk(pvk, ['verify'])
                .then(saveImportedPublicVerifyKey)
                .then(verifyEncryptedMessage)
                .then(handleMessageVerification)
                .then(function() {
                    if (verifyOnly) {
                        callback(true);
                    }
                    else
                        var message = data.ServiceData;
                        iv = KRYPTOS.utils.b642ab(message.iv);
                        cipherText = KRYPTOS.utils.b642ab(message.data);
                        keyStore.importPek(pek, [])
                        .then(function(importedPek) {
                            nodePek = importedPek;
                        })
                        .then(keyStore.getPdk)
                        .then(function(pdk) {
                            log('pdk ---------------------------');
                            log(pdk);
                            return deriveSessionKey(KRYPTOS.AES_GCM_ALGO, pdk, nodePek);
                        })
                        .then(function(key) {
                            log('deriveSessionKey key done!');
                            log(key);
                            return decryptCipherText(key, "AES-GCM");
                        })
                        .then(handlePlainText)
                        .catch(function(error) {
                                KRYPTOS.utils.log(error);
                                callback(false, error);
                            });
                })
                .catch(function(error) {
                        KRYPTOS.utils.log(error);
                        callback(false, error);
                    });
    };

    var justDecryptIt = function(id, algo, key) {
        sessionKey = key;
        return new KRYPTOS.Promise(function (resolve, reject) {
            if (!key) {
                return keyStore.getPdk()
                        .then(decryptKey)
                        .then(saveSessionKey)
                        .then(function() {
                            resolve(sessionKey);
                        });
            }
            else {
//                return sessionKey;
                resolve(sessionKey);
            }
        })
        .then(function(sessionKey) {
                return importSessionKey(sessionKey, KRYPTOS.getAlgo(algo));
            })
            .then(function(key) {
                return decryptCipherText(key, algo);
            })
            .then(function(plainText) {
                var data = {
                    id: id,
                    plain: KRYPTOS.utils.ab2json(plainText),
                    failed: false,
                    key: KRYPTOS.utils.ab2b64(sessionKey)
                };
                if (callback) {
                    callback(data);
                }
                else {
                     return new KRYPTOS.Promise(function (resolve, reject) {
                        resolve(data);
                     });
                }
            })
            .catch(function(error) {
                KRYPTOS.utils.log(error);
                if (callback) {
                    callback(false, error);
                }
                else {
                    return new KRYPTOS.Promise(function (resolve, reject) {
                        resolve(error);
                     });
                }
            });
    };

    var decryptIt = function(from, id, algo, key) {
        sessionKey = key;
        return keyStore.getPublicKey(from, 'verify')
                    .then(savePublicKey)
                    .then(importPublicVerifyKey)
                    .then(saveImportedPublicVerifyKey)
                    .then(verifyEncryptedMessage)
                    .then(handleMessageVerification)
                    .then(function() {
                        return justDecryptIt(id, algo, key);
                    }).catch(function(error) {
                        KRYPTOS.utils.log(error);
                        if (callback) {
                           callback(false, error);
                       }
                    });
    };

    var verifyIt = function(from, id) {
        return keyStore.getPublicKey(from, 'verify')
                    .then(savePublicKey)
                    .then(keyStore.importPvk)
                    .then(saveImportedPublicVerifyKey)
                    .then(verifyEncryptedMessage)
                    .then(handleMessageVerification)
//                        .catch(function (error) {
////                            alert('ERROR! Check console!');
//                        })
                    .then(function() {
                        var data = {
                            id: id
                        };
                        if (callback) {
                            callback(data);
                        }
                        else {
                             return new KRYPTOS.Promise(function (resolve, reject) {
                                resolve(data);
                             });
                        }
                    })
                    .catch(function(error) {
                        KRYPTOS.utils.log(error);
                         if (callback) {
                            callback(false, error);
                        }
                        else {
                            return new KRYPTOS.Promise(function (resolve, reject) {
                                resolve(error);
                             });
                        }
                    });
    };

    var log = function(msg) {
        return false;
    };

    return {
        decrypt: function() {
            return importPublicVerifyKey()
                    .then(saveImportedPublicVerifyKey)
                    .then(verifyEncryptedMessage)
                    .then(handleMessageVerification)
                    .then(keyStore.getPdk)
                    .then(decryptKey)
                    .then(importSessionKey)
                    .then(decryptCipherText)
                    .then(handlePlainText)
                    .catch(function(error) {
                        KRYPTOS.utils.log(error);
                        callback(false, error);
                    });
        },
        decrypt3: function() {
            return decryptKey()
                    .then(importSessionKey)
                    .then(decryptCipherText)
                    .then(handlePlainText)
                    .catch(function(error) {
                        KRYPTOS.utils.log(error);
                        callback(false, error);
                    });
        },
        decryptGroupKey: function(raw) {
            if (raw) {
                return keyStore.getPdk()
                    .then(decryptKey)
                    .then(function(result) {
                        callback(true, result);
                    })
                    .catch(function(error) {
                        KRYPTOS.utils.log(error);
                        callback(false, error);
                    });
            }
            else {
               return keyStore.getPdk()
                    .then(unwrapKey)
//                    .then(decryptKey)
//                    .then(importGroupSessionKey)
                    .then(function(result) {
                        callback(true, result);
                    })
                    .catch(function(error) {
                        KRYPTOS.utils.log(error);
                        callback(false, error);
                    });
            }

        },
        decryptGroupMessage: function(from, id) {
            return decryptIt(from, id, "AES-GCM", key);
        },
        decryptFile: function() {
            return importVerifyKey()
//                    .then(saveExportedFileSessionKey)
//                    .then(importVerifyKey)
                    .then(verifyEncryptedFile)
                    .then(handleFileVerification)
                    .then(importSessionKey)
                    .then(decryptCipherText)
                    .then(handlePlainFile)
                    .catch(function(error) {
                        KRYPTOS.utils.log(error);
                        callback(false, error.message ? error.message : error);
                    });
        },
        decrypt2: function(from, uuid) {
            return new KRYPTOS.Promise(function (resolve, reject) {
//                return importPublicVerifyKey().catch(function (error) {log('a'); log(error); KRYPTOS.utils.log(error);})
                return keyStore.getPublicKey(from, 'verify')
                    .then(savePublicKey)
                    .then(importPublicVerifyKey)
                    .then(saveImportedPublicVerifyKey)
                    .then(verifyEncryptedMessage)
                        .catch(function (error) {
                            resolve({uuid: uuid, failed: true, plain: {subject: "Could not verify sender"}});
                        })
                    .then(handleMessageVerification)
                    .then(keyStore.getPdk)
                    .then(decryptKey)
                    .catch(function(error) {
                        resolve({uuid: uuid, failed: true, plain: {subject: "Error!"}}); //Incorrect key!!
                    })
                    .then(importSessionKey)
                    .then(decryptCipherText)
                    .catch(function(error) {
                        KRYPTOS.utils.log(error);
                        resolve({uuid: uuid, failed: true, plain: {subject: "Could not decrypt message!!"}});
                    })
                    .then(function(plainText) {
                        if (plainText) {
                            var plain = KRYPTOS.utils.ab2json(plainText);
                            resolve({uuid: uuid, failed: false, plain: plain});
                        }
                    })
                    .catch(function(error) {
                        KRYPTOS.utils.log(error);
                        resolve({uuid: uuid, failed: true, plain: {subject: "Something went wrong!!"}});
                        //reject("DECRYPT 2: Something went wrong decrypting message " + error.message + "\n" + error.stack);
                    });
            });
        },
        decryptItemAssignment: function() {
            return importPublicVerifyKey().catch(function (error) {log('a'); log(error); KRYPTOS.utils.log(error);})
                    .then(saveImportedPublicVerifyKey)
                    .then(verifyEncryptedMessage).catch(function (error) {log('b'); log(error); KRYPTOS.utils.log(error);})
                    .then(handleMessageVerification).catch(function (error) {KRYPTOS.utils.log('decryptItemAssignment'); KRYPTOS.utils.log(error); KRYPTOS.utils.log(error);})
                    .then(keyStore.getPdk).catch(function (error) {log('b2'); log(error); KRYPTOS.utils.log(error);})
                    .then(decryptKey).catch(function (error) {log('c'); log(error); KRYPTOS.utils.log(error);})
                    .then(saveSessionKey)
                    .then(importSessionKey).catch(function (error) {log('d'); log(error); KRYPTOS.utils.log(error);})
                    .then(decryptCipherText).catch(function (error) {log('e'); log(error); KRYPTOS.utils.log(error);})
                    .then(function(plainText) {
                        callback({
                            json: KRYPTOS.utils.ab2json(plainText),
                            key: KRYPTOS.utils.ab2b64(sessionKey)
                        });
                    })
                    .catch(function(error) {
                        KRYPTOS.utils.log(error);
                        callback(false, error);
                    });
        },
        decryptItem: function(itemId, referenceId) {
            return importPublicVerifyKey()
                    .then(saveImportedPublicVerifyKey)
                    .then(verifyEncryptedMessage)
                    .then(handleMessageVerification).catch(function (error) {KRYPTOS.utils.log('decryptItem'); KRYPTOS.utils.log(error); KRYPTOS.utils.log(error);})
//                    .then(decryptKey)
                    .then(function() {
                        return key;
                    })
                    .then(importSessionKey)
                    .catch(function(error) {
                        KRYPTOS.utils.log(error);
//                        resolve({uuid: uuid, failed: true, plain: {subject: "Incorrect key!!"}});
                    })
                    .then(decryptCipherText)
                    .catch(function(error) {
                        KRYPTOS.utils.log(error);
//                        resolve({uuid: uuid, failed: true, plain: {subject: "Incorrect key!!"}});
                    })
                    .then(function(plainText) {
                        callback({
                            plain: KRYPTOS.utils.ab2json(plainText),
                            id: itemId,
                            rid: referenceId
                        });
                    })
                    .catch(function(error) {
                        KRYPTOS.utils.log(error);
                        callback(false, error);
                    });
        },
        decryptFilePart: function(id, partNumber) {
//            return importVerifyKey()
//                    .then(verifyEncryptedFile)
//                    .then(handleFileVerification)
//                    .then(importSessionKey)
                    var algo = KRYPTOS.AES_GCM_ALGO;
                    return importSessionKey(null, algo)
                    .then(function(key) {
                        log(key);
                        return decryptCipherText(key, "AES-GCM");
                    })
                    .then(function(plainFile) {
                        callback({
                            id: id,
                            part: partNumber,
                            file: plainFile
                        });
                    })
                    .catch(function(error) {
                        KRYPTOS.utils.log(error);
                        callback(false, error.message ? error.message : error);
                    });
        },
        protocol: protocol,
        decryptIt: decryptIt,
        verifyIt: verifyIt,
        justDecryptIt: justDecryptIt
    };

};


