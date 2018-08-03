/* global KRYPTOS, Promise, CryptoKey */

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
 * The KRYPTOS Encrypter module.
 *
 * @param {KRYPTOS.KeyStore} serviceKeyStore
 * @param {String} plainText
 * @param {Array} recipients
 * @param {function} callback
 * @returns {KRYPTOS.Encrypter} the public methods
 */
KRYPTOS.Encrypter = function (serviceKeyStore, plainText, recipients, callback) {
    var KU = KRYPTOS.utils;
    var keyStore = serviceKeyStore;
    var plain = plainText;
    var sessionKey = null;
    var exportedSessionKey = null;
    var encryptedPlainText = null;
    var signature = null;
    var encrypterCallback = callback;
    var sendData = [];
    var method = 'message';

    var deriveSessionKey = function(algorithm, pdk, pek) {
        return KRYPTOS.cryptoSubtle.deriveKey({name: "ECDH", namedCurve: "P-521", public: pek}, pdk, algorithm, KRYPTOS.EXTRACTABLE, KRYPTOS.ENCRYPT_USAGE);
    };

    var getSessionKey = function(usage, algo, key) {
        if (key) {
            if (key instanceof CryptoKey) {
                return new KRYPTOS.Promise(function (resolve, reject) {
                    resolve(key);
                });
            }
            return importSessionKey(key, algo);
        }
        else {
            return generateSessionKey(usage, algo);
        }
    };

    var generateSessionKey = function (usage, algorithm) {
        if (!usage) {
            usage = KRYPTOS.ENCRYPT_USAGE;
        }
        if (!algorithm) {
            algorithm = KRYPTOS.AES_CBC_ALGO;
        }
        return KRYPTOS.cryptoSubtle.generateKey(algorithm, KRYPTOS.EXTRACTABLE, usage);
    };

    var saveSessionKey = function (generatedSessionKey, skip) {
        sessionKey = generatedSessionKey;
        return sessionKey;
    };

    var importSessionKey = function(keyBytes, algo) {
        if (!algo) {
            algo = KRYPTOS.AES_CBC_ALGO;
        }
        return KRYPTOS.cryptoSubtle.importKey("raw", keyBytes, algo, KRYPTOS.NONEXTRACTABLE, KRYPTOS.ENCRYPT_USAGE);
    };

    var importHmacKey = function(raw) {
        return KRYPTOS.cryptoSubtle.importKey('raw', raw, KRYPTOS.HMAC_ALGO, KRYPTOS.NONEXTRACTABLE, ['sign', 'verify']);
    };

    var encryptPlainText = function (sessionKey) {
        var iv = KRYPTOS.nonce();
        var algo = {name: sessionKey.algorithm.name, iv: iv};
        if (algo.name === 'AES-GCM') {
            algo.tagLength = 128;
        }
        return KRYPTOS.cryptoSubtle.encrypt(algo, sessionKey, KU.str2ab(JSON.stringify(plain)))
                .then(function (cipherText) {
                    return [iv, new Uint8Array(cipherText)];
                });
    };

    var saveEncryptedPlainText = function (ivAndCiphertext) {
        encryptedPlainText = ivAndCiphertext;
        return sessionKey;
    };

    var exportSessionKey = function (key) {
        if (!key) {
            key = sessionKey;
        }
        if (exportedSessionKey) {
            return exportedSessionKey;
        }
        return KRYPTOS.cryptoSubtle.exportKey("raw", key);
    };

    var saveExportedSessionKey = function (exportedKey) {
        exportedSessionKey = exportedKey;
        //return exportedSessionKey;
    };

    var signEncryptedPlainText = function (psk) {
        if (!psk) {
            return "";
        }
        return KRYPTOS.cryptoSubtle.sign(KRYPTOS.getSignAlgo(psk.algorithm.name), psk, new Uint8Array(encryptedPlainText[1]));
    };

    var hmacSign = function(signKey) {
        return KRYPTOS.cryptoSubtle.sign(KRYPTOS.HMAC_ALGO, signKey, encryptedPlainText[1]);
    };

    var saveSignature = function (fileSignature) {
        signature = fileSignature;
    };

    var encryptSessionKey = function (publicEncryptKey) {
        return KRYPTOS.cryptoSubtle.encrypt(KRYPTOS.RSA_OAEP_ALGO, publicEncryptKey, exportedSessionKey);
    };

    var encryptSessionKeys = function() {
        var promises = [];
        for (var prop in recipients) {
            if (recipients.hasOwnProperty(prop)) {
                for (var i = 0; i < recipients[prop].length; i++) {
                    promises.push(encryptRecipientSessionKey(recipients[prop][i]));
                }
                KRYPTOS.Promise.all(promises)
                    .then(function(result) {
                        sendData['keys'] = JSON.stringify(result);
                });
            }
        }

        return KRYPTOS.Promise.all(promises);
    };

    var packageResults = function (keys) {
        var signatureLength = new Uint16Array([signature.byteLength]);
        return {
            blob: new Blob(
                [
                    new Uint16Array([KRYPTOS.LENGTH_256]), //keyLength, // 2 bytes
                    signatureLength, //2 bytes
                    new ArrayBuffer(KRYPTOS.LENGTH_256),//encryptedKey, // 256 bytes
                    signature, // 256 bytes
                    encryptedPlainText[0],
                    encryptedPlainText[1]
                ],
                {type: "application/octet-stream"}
            ),
            keys: keys
        };
    };

    var encryptMessage = function () {
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
                .then(function(result) {
                    encrypterCallback(true, result);
                })
                .catch(function (error) {
                    KU.log(error);
                    if (encrypterCallback) {
                        encrypterCallback(false, error.message ? error.message : error);
                    }
                });

    };

    /**
     * Encrypt Session Key Promise, encrypts the message session key with the
     * recipients public encrypt key.
     *
     * @param {String} recipient
     * @returns {Promise}
     */
    var encryptRecipientSessionKey = function(recipient) {
        var username = KU.extractUsernameFromFullName(recipient);
        var aesKey = null;

        return new KRYPTOS.Promise(function(resolve, reject) {
            return keyStore.getPublicKey(username, 'encrypt').then(function(pek) {
                return keyStore.importPek(pek, ['encrypt'])
                        .then(function(publicKey) {
                            return encryptSessionKey(publicKey);
                        })
                        .then(function(encryptedSessionKey) {
                            aesKey = encryptedSessionKey;
                            return new Blob(
                                    [
                                        encryptedSessionKey
                                    ],
                                    {type: "application/octet-stream"}
                            );
                        })
                        .then(function(blob) {
    //                        sendData['key_' + KU.dot2us(username)] = blob;
                            resolve({u: username, k: KU.ab2b64(aesKey)});
                        })
                        .catch(function (error) {
                            KU.log(error);
                            reject("encrypt key error: Something went wrong encrypting key " + error.message + "\n" + error.stack);
                        });
                    });

        });

    };

    /**
     * Encrypt File Promise, encrypts an individual file/attachment
     * belonging to a message.
     *
     * @param {ArrayBuffer} file
     * @param {string} id
     * @returns {Promise}
     */
    var encryptFile = function (file, id) {
        var fileSessionKey = null;
        var exportedFileSessionKey = null;
        var encryptedFile = null;
        var result = [];
        result['id'] = id;
//        if (options === null) {
//            options = {
//                'resource': 'messages',
//                'type'    : 'attachment'
//            };
//        }
        return new KRYPTOS.Promise(function (resolve, reject) {

            return generateSessionKey()
                    // Save raw file session and export it
                    .then(function (key) {

                        fileSessionKey = key;

                        return KRYPTOS.cryptoSubtle.exportKey('raw', key);
                    })
                    // Save File Session Key
                    .then(function (exportedSessionKey) {

                        result['key'] = KU.ab2hex(exportedSessionKey);
                        exportedFileSessionKey = exportedSessionKey;
                    })
                    // Encrypt File
                    .then(function () {

                        var iv = KRYPTOS.nonce();
                        return KRYPTOS.cryptoSubtle.encrypt({name: "AES-CBC", iv: iv}, fileSessionKey, file)
                                    .then(function (cipherText) {
                                        encryptedFile = [iv, new Uint8Array(cipherText)];
                                    });
                    })
                    // Import sign key
                    .then(function () {
                        return KRYPTOS.cryptoSubtle.importKey('raw', exportedFileSessionKey, KRYPTOS.HMAC_ALGO, KRYPTOS.NONEXTRACTABLE, ['sign', 'verify']);
                    })
                    // Sign File
                    .then(function (signKey) {
                        return KRYPTOS.cryptoSubtle.sign(KRYPTOS.HMAC_ALGO, signKey, encryptedFile[1]);
                    })
                    // Save HMAC signaure
                    .then(function (signature) {
                        result['hmac'] = KU.ab2hex(signature);
                    })
                    // Blob it up
                    .then(function () {
                        result['file_transfer'] = new Blob(
                                encryptedFile,
                                {type: "application/octet-stream"});
                        resolve(result);
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
                    .catch(function (error) {
                        KU.log(error);
                        reject("encryptFile: Something went wrong encrypting file " + error.message + "\n" + error.stack);
                    });
        });
    };

    var encryptFilePart = function(file, id, partNumber) {
        var iv = KRYPTOS.nonce();
        var aesKey = null;
        var encryptedFile = null;

        return new KRYPTOS.Promise(function (resolve, reject) {
            return generateSessionKey(KRYPTOS.ENCRYPT_USAGE, KRYPTOS.AES_GCM_ALGO)
            .then(function(key) {
                aesKey = key;
                return aesKey;
            })
            // Encrypt file part
            .then(function(aesKey) {
                return KRYPTOS.cryptoSubtle.encrypt({name: "AES-GCM", iv: iv, tagLength: 128}, aesKey, file);

            })
            // Save encrypted file part
            .then(function(cipherText) {
                encryptedFile = new Uint8Array(cipherText);
                return aesKey;
            })
            .then(exportSessionKey)
            .then(function(rawAesKey) {
                resolve({
                    id: id,
                    part: partNumber,
                    encrypted: new Blob([encryptedFile], {type: "application/octet-stream"}),
//                    hmac: KU.ab2b64(signature),
                    key: KU.ab2b64(rawAesKey),
                    iv: KU.ab2b64(iv),
                    enctype: "AES-GCM-256"
                });
            })
            .catch(function (error) {
                KU.log(error);
                reject("encryptFilePart: Something went wrong encrypting file " + error.message + "\n" + error.stack);
            });

        });
    };

    var encryptAssignmentKey = function() {
        var promises = [];

        for (var i = 0; i < recipients.length; i++) {
            promises.push(encryptRecipientAssignmentKey(recipients[i]));
        }

        return KRYPTOS.Promise.all(promises);
    };

    /**
     * Encrypt Session Key Promise, encrypts the message session key with the
     * recipients public encrypt key.
     *
     * @param {String} recipient
     * @returns {Promise}
     */
    var encryptRecipientAssignmentKey = function(recipient) {
        var username = recipient;
        return new KRYPTOS.Promise(function(resolve, reject) {
            keyStore.getPublicKey(username, 'encrypt', function(pek) {
                return keyStore.importPek(pek, ['encrypt'])
                        .then(function(publicKey) {
                            return encryptSessionKey(publicKey);
                        })
                        .then(function(encryptedSessionKey) {

                            resolve({
                                    email: username,
                                    key: KU.ab2b64(encryptedSessionKey)
                            });

                        })
                        .catch(function (error) {
                            KU.log(error);
                            reject("encrypt key error: Something went wrong encrypting key " + error.message + "\n" + error.stack);
                        });
            });

        });

    };

    var protocol = function(message, envelope, pek) {
        var nodePek = null;
        return keyStore.importPek(pek, []).catch(function (error) {KU.log(error);})
                .then(function(importedPek) {
                    nodePek = importedPek;
                })
                .then(keyStore.getPdk).catch(function (error) {KU.log(error);})
                .then(function(pdk) {
                    return deriveSessionKey(KRYPTOS.AES_GCM_ALGO, pdk, nodePek);
                })
                .then(saveSessionKey)
                .then(encryptPlainText).catch(function (error) {KU.log(error);})
                .then(saveEncryptedPlainText).catch(function (error) {KU.log(error);})
                .then(exportSessionKey).catch(function (error) {KU.log(error);})
                .then(function(key) {
                    envelope.iv = KRYPTOS.utils.ab2b64(encryptedPlainText[0]);
                    envelope.data = KRYPTOS.utils.ab2b64(encryptedPlainText[1]);
                    message.ServiceData = envelope;
                    encryptedPlainText[1] = KRYPTOS.utils.str2ab(JSON.stringify(message));
                    return;
                })
                .then(keyStore.getPsk)
                .then(signEncryptedPlainText)
                .then(function(signature) {
                    message.Sign = KRYPTOS.utils.ab2b64(signature);
                    encrypterCallback(true, message);
                })
                .catch(function (error) {
                    KU.log(error);
                    KU.log(error);
                    if (encrypterCallback) {
                        encrypterCallback(false, error.message ? error.message : error);
                    }
                });
    };

    var encryptIt = function(algo, key, excludeSign) {
        exportedSessionKey = key;
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
                .then(function(sessionKeys) {
                    encrypterCallback(true, {
                        m: KU.ab2b64(encryptedPlainText[1]),
                        iv: KU.ab2b64(encryptedPlainText[0]),
                        s: KU.ab2b64(signature),
                        keys: sessionKeys
                    });
                })
                .catch(function (error) {
                    KU.log(error);
                    if (encrypterCallback) {
                        encrypterCallback(false, error.message ? error.message : error);
                    }
                });
    };

    var signIt = function(data, includeSignature, base64Url) {
        encryptedPlainText = [];
        encryptedPlainText[1] = KRYPTOS.utils.str2ab(JSON.stringify(data));
        return keyStore.getPsk()
                .then(signEncryptedPlainText)
                .then(function(signature) {
                    var s = KRYPTOS.utils.ab2b64(signature, base64Url);
                    if (includeSignature) {
                        data.signature = s;
                    }
                    else {
                        data = {data: data, signature: s};
                    }
                    encrypterCallback(true, data);
                })
                .catch(function (error) {
                    KU.log(error);
                    if (encrypterCallback) {
                        encrypterCallback(false, error.message ? error.message : error);
                    }
                });

    };

    var macSignIt = function(data, key) {
        encryptedPlainText = [];
        encryptedPlainText[1] = KRYPTOS.utils.str2ab(data);
        return importHmacKey(KU.str2ab(key))
                .then(hmacSign)
                .then(function(signature) {
                    encrypterCallback(true, {data: data, signature: KU.ab2b64(signature)});
                })
                .catch(function (error) {
                    KU.log(error);
                    if (encrypterCallback) {
                        encrypterCallback(false, error.message ? error.message : error);
                    }
                });
    };

    var encryptChatMessage = function(algo) {
        if (!algo) {
            algo = KRYPTOS.AES_CBC_ALGO;
        }
        return encryptIt(algo);
    };

    var encryptGroupChatMessage = function(key) {
        return encryptIt(KRYPTOS.AES_GCM_ALGO, key);
    };

    var log = function(msg) {
        return false;
    };

    return {
        encrypt: encryptMessage,

        encryptFile: function (file, id, callback) {
            return encryptFile(file, id).then(function(result) {
                callback(result);
            })
            .catch(function (error) {
                KU.log(error);
                if (encrypterCallback) {
                    callback(false, error.message);
                }
            });
        },

        encryptChatMessage: encryptChatMessage,

        encryptGroupChatMessage: encryptGroupChatMessage,

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

        encryptGroupChatKey: function() {
            return generateSessionKey(KRYPTOS.ENCRYPT_USAGE, KRYPTOS.AES_GCM_ALGO)
                    .then(saveSessionKey)
                    .then(exportSessionKey)
                    .then(saveExportedSessionKey)
                    .then(encryptSessionKeys)
                    .then(function(sessionKeys) {
                        encrypterCallback(true, {
                            members_keys: sessionKeys
                        });
                    })
                    .catch(function (error) {
                        KU.log(error);
                        if (encrypterCallback) {
                            encrypterCallback(false, error.message);
                        }
                    });
        },

        encryptExistingGroupChatKey: function(key) {
            saveExportedSessionKey(key);
            return importSessionKey(key)
                .then(saveSessionKey)
                .then(encryptSessionKeys)
                .then(function(sessionKeys) {
                    encrypterCallback(true, {
                        members_keys: sessionKeys
                    });
                })
                .catch(function (error) {
                    KU.log(error);
                    if (encrypterCallback) {
                        encrypterCallback(false, error.message);
                    }
                });
        },

        encryptSignatureMessage: function() {
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
                .then(function(sessionKeys) {
                    encrypterCallback(true, {
                        m: KU.ab2b64(encryptedPlainText[1]),
                        iv: KU.ab2b64(encryptedPlainText[0]),
                        s: KU.ab2b64(signature),
                        k: sessionKeys[0].k
                    });
                })
                .catch(function (error) {
                    KU.log(error);
                    if (encrypterCallback) {
                        encrypterCallback(false, error.message);
                    }
                });
        },

        encryptNewItemAssignment: function() {
            return generateSessionKey()
                    .then(saveSessionKey)
                    .then(encryptPlainText)
                    .then(saveEncryptedPlainText)
                    .then(exportSessionKey)
                    .then(saveExportedSessionKey)
                    .then(keyStore.getPsk)
                    .then(signEncryptedPlainText)
                    .then(saveSignature)
                    .then(function(key) {
                        encrypterCallback(true, {
                            message: KU.ab2b64(encryptedPlainText[1]),
                            iv: KU.ab2b64(encryptedPlainText[0]),
                            signature: KU.ab2b64(signature),
                            key: KU.ab2b64(exportedSessionKey),
                            encrypted_key: new Blob(
                                [key],
                                {type: "application/octet-stream"}
                            )
                        });
                    })
                    .catch(function (error) {
                        KU.log(error);
                        if (encrypterCallback) {
                            encrypterCallback(false, error);
                        }
                    });
        },

        encryptItemAssignment: function(existingKey) {
            saveExportedSessionKey(existingKey);
            return encryptAssignmentKey()
                    .then(function(result) {
                        encrypterCallback(true, result);
                    })
                    .catch(function (error) {
                        KU.log(error);
                        if (encrypterCallback) {
                            encrypterCallback(false, error);
                        }
                    });
        },

        // PSK should be cached previously
        encryptNewItem: function() {
            return generateSessionKey()
                    .then(saveSessionKey)
                    .then(encryptPlainText)
                    .then(saveEncryptedPlainText)
                    .then(exportSessionKey)
                    .then(saveExportedSessionKey)
                    .then(keyStore.getPsk)
                    .then(signEncryptedPlainText)
                    .then(saveSignature)
                    .then(function() {
                        encrypterCallback(true, {
                            message: KU.ab2b64(encryptedPlainText[1]),
                            iv: KU.ab2b64(encryptedPlainText[0]),
                            signature: KU.ab2b64(signature),
                            key: KU.ab2b64(exportedSessionKey)
                        });
                    })
                    .catch(function (error) {
                        KU.log(error);
                        if (encrypterCallback) {
                            encrypterCallback(false, error);
                        }
                    });
        },

        encryptExistingItem: function(existingKey) {
            return importSessionKey(existingKey)
                    .then(encryptPlainText)
                    .then(saveEncryptedPlainText)
                    .then(keyStore.getPsk)
                    .then(signEncryptedPlainText)
                    .then(saveSignature)
                    .then(function() {
                        encrypterCallback(true, {
                            message: KU.ab2b64(encryptedPlainText[1]),
                            iv: KU.ab2b64(encryptedPlainText[0]),
                            signature: KU.ab2b64(signature)
                        });
                    })
                    .catch(function (error) {
                        KU.log(error);
                        if (encrypterCallback) {
                            encrypterCallback(false, error);
                        }
                    });
        },

        /*
         * 1. AES Key: Get HMAC of plain file part with 32 0 bytes key
         * 2. Encrypt file part with HMAC -> AES key
         * 2. HMAC: Get HMAC of encrypted file part
         * 3. partsize = 4194304
         */
        encryptFilePart: function(file, id, partNumber, callback) {
            return encryptFilePart(file, id, partNumber, callback).then(function(result) {
                callback(result);
            });
        },

        protocol: protocol,

        encryptIt: encryptIt,

        signIt: signIt,

        macSignIt: macSignIt

    };
};



