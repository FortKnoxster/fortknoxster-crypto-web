/* global KRYPTOS, Promise, Token, Contacts, CryptoKey */

"use strict";
/**
 * KRYPTOS is a cryptographic library wrapping and implementing the
 * Web Cryptography API. It supports both symmetric keys and asymmetric key pair
 * generation, encryption, decryption, signing and verification.
 *
 *
 *
 * @name KRYPTOS
 * @copyright Copyright © FortKnoxster Ltd. 2014 - 2018.
 * @license Apache License, Version 2.0 http://www.apache.org/licenses/LICENSE-2.0
 * @author MJ <mj@fortknoxster.com>
 * @version 4.0
 */

/**
 * The KRYPTOS Identity module.
 *
 * @returns {KRYPTOS.Identity} the public methods
 */
KRYPTOS.Identity = function (keyStore) {

    var identityKeyStore = keyStore;

    var KU = KRYPTOS.utils;

//    var certificate = function(id, username, fingerprint) {
    var certificate = function(id, pvk) {
        return {
            id: id,
//            username: username,
//            fingerprint: fingerprint,
            pvk: pvk,
            signature: ""
        };
    };

    var init = function() {

    };

    var create = function(cert) {
        return new KRYPTOS.Promise(function (resolve, reject) {
            var Encrypter = new KRYPTOS.Encrypter(identityKeyStore, null, null, function(success, signedCertificate) {
                if (!success) {
                    reject();
                }
                else {
                    resolve(signedCertificate);
                }
            });
            Encrypter.signIt(cert, true);
        });
    };

    var verify = function(attributes) {

    };

    var verifyCert = function(cert, signature) {
        return new KRYPTOS.Decrypter(identityKeyStore, null, null, KU.str2ab(JSON.stringify(cert)), KU.b642ab(signature), null, null, null)
                            .verifyIt(cert.id, cert.id)
                            .then(function(result) {
                            })
                            .catch(function(error) {
                            });
    };

    return {
        init: init,
        certificate: certificate,
        create: create,
        verify: verify
    };
};



