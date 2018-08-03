
/* global KRYPTOS, App, Groups */

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
 * The KRYPTOS Contacts module.
 * AES-GCM-256.
 *
 */

KRYPTOS.Contacts = function() {

    let keyStore = null;

    
    let init = function(serviceKeyStore) {
        keyStore = serviceKeyStore;
    };
    
    let getServicePublicKeys = function(userIds, service, cb) {
        console.log('getServicePublicKeys');
        console.dir(userIds);
        let ids = [];
        for (let userId of userIds) {
            if (KRYPTOS.session.getItem(service + ":pub:" + userId)) {
                continue;
            }
            ids.push(userId);
        }
        if (!ids.length) {
            return cb(true);
        }
        console.dir(ids);
        KRYPTOS.API.getUsersPublicKeys({
            userids: ids, 
            servicetype: service
        }, function(response) {
            if (!response.length) {
                return cb();
            }
            console.dir(response);
            for (let key of response) {
                console.log(key);
                KRYPTOS.session.setItem(service + ":pub:" + key.id, key.publickeys);
            }
            cb(true);
        });
    };

    return {
        init: init,
        getServicePublicKeys: getServicePublicKeys,
        log: function() {
        }
    };

}();
