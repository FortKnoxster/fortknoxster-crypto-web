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
 * The KRYPTOS Tests module.
 * 
 * @param {String} plainText
 * @param {CryptoKey} theirPublicKey
 * @param {function} callback
 * @returns {KRYPTOS.Encrypter} the public methods
 */
KRYPTOS.Tests = function () {
    
    var KU = KRYPTOS.utils;
    
    var KA = KRYPTOS.API;
    


    return {
        testContactSearch: KA,
    };
}();



