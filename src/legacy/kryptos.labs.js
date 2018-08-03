/* global KRYPTOS, Promise, Token */

"use strict";
/**
 * KRYPTOS is a cryptographic library wrapping and implementing the
 * Web Cryptography API. It supports both symmetric keys and asymmetric key pair
 * generation, encryption, decryption, signing and verification.
 *
 * If the Web Cryptography API is not supported by the browser, it falls back
 * to the an implementation of the MSR JavaScript Cryptography Library.
 *
 *
 * @name KRYPTOS
 * @copyright Copyright © FortKnoxster Ltd. 2014 - 2017.
 * @license Apache License, Version 2.0 http://www.apache.org/licenses/LICENSE-2.0
 * @author MJ <mj@fortknoxster.com>
 * @version 3.1
 */

/**
 * The KRYPTOS Labs module.
 *
 * @param {String} plainText
 * @param {CryptoKey} theirPublicKey
 * @param {function} callback
 * @returns {KRYPTOS.Encrypter} the public methods
 */
KRYPTOS.Labs = function () {

    var KU = KRYPTOS.utils;

    var generateECHHKeypair = function() {

    };

    var testECDH = function() {
        var kp1 = null; //base
        var kp2 = null;
        var kp3 = null;

        KRYPTOS.cryptoSubtle.generateKey(
            {
                name: "ECDH",
                namedCurve: "P-521", //can be "P-256", "P-384", or "P-521"
            },
            true, //whether the key is extractable (i.e. can be used in exportKey)
            ["deriveKey", "deriveBits"] //can be any combination of "deriveKey" and "deriveBits"
        )
        .then(function(key){
            //returns a keypair object
            kp1 = key;
            return key;
        })
        .then(function(key) {
            return KRYPTOS.cryptoSubtle.exportKey("jwk", kp1.publicKey);
        })
        .then(function(keydata){
            //returns the exported key data
        })
        .then(function(key) {
            return KRYPTOS.cryptoSubtle.exportKey("jwk", kp1.privateKey);
        })
        .then(function(keydata){
            //returns the exported key data
        })
        .then(function() {
            return KRYPTOS.cryptoSubtle.generateKey(
                {
                    name: "ECDH",
                    namedCurve: "P-521", //can be "P-256", "P-384", or "P-521"
                },
                true, //whether the key is extractable (i.e. can be used in exportKey)
                ["deriveKey", "deriveBits"] //can be any combination of "deriveKey" and "deriveBits"
            )
        })
        .then(function(key){
            //returns a keypair object
            kp2 = key;
            return key;
        })
        .then(function(key) {
            return KRYPTOS.cryptoSubtle.exportKey("jwk", kp2.publicKey);
        })
        .then(function(keydata){
            //returns the exported key data
        })
        .then(function(key) {
            return KRYPTOS.cryptoSubtle.exportKey("jwk", kp2.privateKey);
        })
        .then(function(keydata){
            //returns the exported key data
        })
        .then(function() {
            return KRYPTOS.cryptoSubtle.generateKey(
                {
                    name: "ECDH",
                    namedCurve: "P-521", //can be "P-256", "P-384", or "P-521"
                },
                true, //whether the key is extractable (i.e. can be used in exportKey)
                ["deriveKey", "deriveBits"] //can be any combination of "deriveKey" and "deriveBits"
            )
        })
        .then(function(key){
            //returns a keypair object
            kp3 = key;
            return key;
        })
        .then(function(key) {
            return KRYPTOS.cryptoSubtle.exportKey("jwk", kp3.publicKey);
        })
        .then(function(keydata){
            //returns the exported key data
        })
        .then(function(key) {
            return KRYPTOS.cryptoSubtle.exportKey("jwk", kp3.privateKey);
        })
        .then(function(keydata){
            //returns the exported key data
        })
        .then(function(keydata){
            return KRYPTOS.cryptoSubtle.deriveKey(
                {
                    name: "ECDH",
                    namedCurve: "P-521", //can be "P-256", "P-384", or "P-521"
                    public: kp2.publicKey, //an ECDH public key from generateKey or importKey
                },
                kp1.privateKey, //your ECDH private key from generateKey or importKey
                { //the key type you want to create based on the derived bits
                    name: "AES-GCM", //can be any AES algorithm ("AES-CTR", "AES-CBC", "AES-CMAC", "AES-GCM", "AES-CFB", "AES-KW", "ECDH", "DH", or "HMAC")
                    //the generateKey parameters for that type of algorithm
                    length: 256, //can be  128, 192, or 256
                },
                true, //whether the derived key is extractable (i.e. can be used in exportKey)
                ["encrypt", "decrypt"] //limited to the options in that algorithm's importKey
            );
        })
        .then(function(keydata){
            //returns the exported key data
            return keydata;
        })
        .then(function(key) {
            return KRYPTOS.cryptoSubtle.exportKey("jwk", key);
        })
        .then(function(keydata){
            //returns the exported key data
            return keydata;
        })
        .then(function(keydata){
            return KRYPTOS.cryptoSubtle.deriveKey(
                {
                    name: "ECDH",
                    namedCurve: "P-521", //can be "P-256", "P-384", or "P-521"
                    public: kp3.publicKey, //an ECDH public key from generateKey or importKey
                },
                kp1.privateKey, //your ECDH private key from generateKey or importKey
                { //the key type you want to create based on the derived bits
                    name: "AES-GCM", //can be any AES algorithm ("AES-CTR", "AES-CBC", "AES-CMAC", "AES-GCM", "AES-CFB", "AES-KW", "ECDH", "DH", or "HMAC")
                    //the generateKey parameters for that type of algorithm
                    length: 256, //can be  128, 192, or 256
                },
                true, //whether the derived key is extractable (i.e. can be used in exportKey)
                ["encrypt", "decrypt"] //limited to the options in that algorithm's importKey
            );
        })
        .then(function(keydata){
            //returns the exported key data
            return keydata;
        })
        .then(function(key) {
            return KRYPTOS.cryptoSubtle.exportKey("jwk", key);
        })
        .then(function(keydata){
            //returns the exported key data
            return keydata;
        })
        .then(function(keydata){
            return KRYPTOS.cryptoSubtle.deriveKey(
                {
                    name: "ECDH",
                    namedCurve: "P-521", //can be "P-256", "P-384", or "P-521"
                    public: kp1.publicKey, //an ECDH public key from generateKey or importKey
                },
                kp2.privateKey, //your ECDH private key from generateKey or importKey
                { //the key type you want to create based on the derived bits
                    name: "AES-GCM", //can be any AES algorithm ("AES-CTR", "AES-CBC", "AES-CMAC", "AES-GCM", "AES-CFB", "AES-KW", "ECDH", "DH", or "HMAC")
                    //the generateKey parameters for that type of algorithm
                    length: 256, //can be  128, 192, or 256
                },
                true, //whether the derived key is extractable (i.e. can be used in exportKey)
                ["encrypt", "decrypt"] //limited to the options in that algorithm's importKey
            );
        })
        .then(function(keydata){
            //returns the exported key data
            return keydata;
        })
        .then(function(key) {
            return KRYPTOS.cryptoSubtle.exportKey("jwk", key);
        })
        .then(function(keydata){
            //returns the exported key data
            return keydata;
        })
        .then(function(keydata){
            return KRYPTOS.cryptoSubtle.deriveKey(
                {
                    name: "ECDH",
                    namedCurve: "P-521", //can be "P-256", "P-384", or "P-521"
                    public: kp2.publicKey, //an ECDH public key from generateKey or importKey
                },
                kp1.privateKey, //your ECDH private key from generateKey or importKey
                { //the key type you want to create based on the derived bits
                    name: "AES-GCM", //can be any AES algorithm ("AES-CTR", "AES-CBC", "AES-CMAC", "AES-GCM", "AES-CFB", "AES-KW", "ECDH", "DH", or "HMAC")
                    //the generateKey parameters for that type of algorithm
                    length: 256, //can be  128, 192, or 256
                },
                true, //whether the derived key is extractable (i.e. can be used in exportKey)
                ["encrypt", "decrypt"] //limited to the options in that algorithm's importKey
            );
        })
        .then(function(keydata){
            //returns the exported key data
            return keydata;
        })
        .then(function(key) {
            return KRYPTOS.cryptoSubtle.exportKey("jwk", key);
        })
        .then(function(keydata){
            //returns the exported key data
            return keydata;
        })
        .then(function(keydata){
            return KRYPTOS.cryptoSubtle.deriveKey(
                {
                    name: "ECDH",
                    namedCurve: "P-521", //can be "P-256", "P-384", or "P-521"
                    public: kp1.publicKey, //an ECDH public key from generateKey or importKey
                },
                kp2.privateKey, //your ECDH private key from generateKey or importKey
                { //the key type you want to create based on the derived bits
                    name: "AES-GCM", //can be any AES algorithm ("AES-CTR", "AES-CBC", "AES-CMAC", "AES-GCM", "AES-CFB", "AES-KW", "ECDH", "DH", or "HMAC")
                    //the generateKey parameters for that type of algorithm
                    length: 256, //can be  128, 192, or 256
                },
                true, //whether the derived key is extractable (i.e. can be used in exportKey)
                ["encrypt", "decrypt"] //limited to the options in that algorithm's importKey
            );
        })
        .then(function(keydata){
            //returns the exported key data
            return keydata;
        })
        .then(function(key) {
            return KRYPTOS.cryptoSubtle.exportKey("jwk", key);
        })
        .then(function(keydata){
            //returns the exported key data
            return keydata;
        })
        .catch(function(err){
            console.error(err);
        });
    };

    var testECDSA = function() {
        var kp1 = null;
        var data = KU.str2ab("This is some test data to sign");
        var dSignature = null;
        KRYPTOS.cryptoSubtle.generateKey(
            {
                name: "ECDSA",
                namedCurve: "P-521", //can be "P-256", "P-384", or "P-521"
            },
            true, //whether the key is extractable (i.e. can be used in exportKey)
            ["sign", "verify"] //can be any combination of "sign" and "verify"
        )
        .then(function(key){
            //returns a keypair object
            kp1 = key;
        })
        .then(function(key) {
            return KRYPTOS.cryptoSubtle.exportKey("jwk", kp1.publicKey);
        })
        .then(function(keydata){
            //returns the exported key data
        })
        .then(function(key) {
            return KRYPTOS.cryptoSubtle.exportKey("jwk", kp1.privateKey);
        })
        .then(function(keydata){
            //returns the exported key data
        })
        .then(function() {
            return KRYPTOS.cryptoSubtle.sign(
                {
                    name: "ECDSA",
                    hash: {name: "SHA-256"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
                },
                kp1.privateKey, //from generateKey or importKey above
                data //ArrayBuffer of data you want to sign
            )
            .then(function(signature) {
                dSignature = signature;
                //returns an ArrayBuffer containing the signature
            })
            .catch(function(err){
                console.error(err);
            });
        })
        .then(function() {
            return KRYPTOS.cryptoSubtle.verify(
                {
                    name: "ECDSA",
                    hash: {name: "SHA-256"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
                },
                kp1.publicKey, //from generateKey or importKey above
                dSignature, //ArrayBuffer of the signature
                data //ArrayBuffer of the data
            )
            .then(function(isvalid){
                //returns a boolean on whether the signature is true or not
            })
            .catch(function(err){
                console.error(err);
            });
        })
        .catch(function(err){
            console.error(err);
        });
    };

    var testHKDF = function() {
        var encoder = new TextEncoder();
        var rawSecret = KRYPTOS.crypto.getRandomValues(new Uint8Array(32));
        return KRYPTOS.cryptoSubtle.importKey(
          'raw',
          rawSecret,
          'HKDF',
          false,
          ['deriveKey']
        ).then(function(secretKey) {
            return KRYPTOS.cryptoSubtle.deriveKey(
                {
                  name: 'HKDF',
                  salt: new Uint8Array(),
                  info: encoder.encode('encryption2'),
                  hash: 'SHA-256'
                },
                secretKey,
                {
                  name: 'AES-GCM',
                  length: 256
                },
                false,
                ['encrypt']
              ).then(function(derivedKey) {
              });
        });


    };

    return {
        testECDH: testECDH,
        testECDSA: testECDSA,
        testHKDF: testHKDF
    };
}();



