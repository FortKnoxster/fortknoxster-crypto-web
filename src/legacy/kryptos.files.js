/* global KRYPTOS, Sanitize, MediaRecorder, App, U, jsxc */

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
 * @version 1.0
 */

/**
 * The KRYPTOS Files module. Used to encrypt inbox and chat attachments using
 * AES-CBC-256 and HMAC-SHA256. The 16 byte random IV is embedded in the
 * encrypted file.
 *
 */

KRYPTOS.Files = function() {

    let keyStore = null;

    const symmetricAlgo = "AES-CBC-256";

    /**
     * Encrypts a File returning the meta data and the encrypted file in the
     * callback handler.
     *
     * @param {File} file
     * @param {function} callback
     * @returns {void}
     */
    let encryptFile = function(file, callback) {
        if (file === null) {
            return callback(true, null);
        }

        App.KU.readFile(file, function(blob, meta) {
            new KRYPTOS.Encrypter(keyStore).encryptFile(blob, meta.id, function(result, error) {
                if (result === false) {
                    callback(false, error);
                    return;
                }
                let msgObj = {
                    id: result['id'],
                    key: result['key'],
                    hmac: result['hmac'],
                    uuid: "",
                    name: meta['name'],
                    type: meta['type'],
                    size: meta.size
                };
                callback(true, result['file_transfer'], msgObj);
            });
        });
    };

    /**
     * Decrypts an encrypted file.
     *
     * @param {Array} meta
     * @param {ByteArray} data
     * @param {function} callback
     * @returns {void}
     */
    let decryptFile = function(meta, data, callback) {

        let ivLength        = 16;
        let iv              = new Uint8Array(data, 0, ivLength);
        let attachment      = new Uint8Array(data, ivLength);
        let key             = KRYPTOS.utils.hex2ab(meta.key);
        let signature       = KRYPTOS.utils.hex2ab(meta.hmac);

        new KRYPTOS.Decrypter(null, key, iv, attachment, signature, null, null, function(success, fileTransfer) {

            if (success) {
                callback(true, new Blob([fileTransfer], {type: App.KU.dURI(meta.type)}));
            }

        }).decryptFile();
    };

    return {
        encryptFile: encryptFile,
        decryptFile: decryptFile
    };

}();

