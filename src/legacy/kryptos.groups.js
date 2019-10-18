
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
 * The KRYPTOS Groups module. Used to encrypt group keys using
 * AES-GCM-256.
 *
 */

KRYPTOS.Groups = function() {

    let keyStore = null;

    let groupKeys = new Map();

    const symmetricAlgo = "AES-GCM-256";

    let encryptGroupKey = function(contacts, callback, errorCallback) {
        let members = [];
        contacts.forEach((contact, k) => {
            members.push(contact.contact.contact_user_id);
        });
        members.push(App.getUserId());

        let Encrypter = new KRYPTOS.Encrypter(keyStore, null, {to: members}, function(success, result) {
            if (success) {
                callback(result);
            }
            else {
                errorCallback(result);
            }
        });

        Encrypter.encryptGroupChatKey();
    };

    let loadGroupChats = function(callback, errorCallback) {
        KRYPTOS.API.getGroupChats(null, function(groups) {
            let promises = [];
            for (var j = 0; j < groups.length; j++) {
                let gid = groups[j].group_chat_id;
                promises.push(getGroupKey(gid, groups[j].key));
            }
            KRYPTOS.Promise.all(promises)
                .then(function(result) {
                    if (callback) {
                        callback(groups);
                    }
                }).catch(function(error) {
                    if (errorCallback) errorCallback(error);
                });

        }, errorCallback);
    };

    let removeGroupKey = function(id) {
        return groupKeys.delete(id);
    };

    let getGroupKey = function(fid, raw, cb) {
        return new KRYPTOS.Promise(function (resolve, reject) {
            let gid = App.KU.e2u(fid);
            let key = groupKeys.get(gid);
            if (key) {
                if (cb) return cb(key);
                resolve(key);
            }
            else {
                if (!raw) {
                    Groups.getGroupFromCache(gid, function(group) {
                        key = App.KU.b642ab(group.key);
                        new KRYPTOS.Decrypter(keyStore, key, null, null, null, null, null, function(success, plainKey) {
                            if (!success) {
                                return;
                            }
                            groupKeys.set(gid, plainKey);
                            if (cb) return cb(plainKey);
                            resolve(plainKey);
                        }).decryptGroupKey(false);
                    });
                }
                else {
                    key = App.KU.b642ab(raw);

                        new KRYPTOS.Decrypter(keyStore, key, null, null, null, null, null, function(success, plainKey) {
                            if (!success) {
                                return;
                            }
                            groupKeys.set(gid, plainKey);
                            if (cb) return cb(plainKey);
                            resolve(plainKey);
                        }).decryptGroupKey(false);
                    }
            }
        });
    };

    let create = function(data, callback, errorCallback) {
        encryptGroupKey(data.contacts, function(result) {
            if (result) {
                result.subject = App.KU.eURI(data.subject);
                App.KA.createGroupChat(result, function(group) {
                    let members = [];
                    data.contacts.forEach(function (contact) {
                        if (App.getUserId() === contact.contact.contact_user_id) {
                            return;
                        }
                        members.push({
                            nick: contact.contact.contact_user_id,
                            jid: contact.contact.jid
                        });
                    });

                    KRYPTOS.XMPP.subscribeGroup();
                    KRYPTOS.XMPP.subscribeMembersGroup(group.jid, members, function() {
                        callback(group);
                    });

                }, errorCallback);
            }
            else {
                errorCallback(result);
            }
        });
    };

    let destroy = function(id, callback, errorCallback) {
        App.KA.deleteGroupChat({id: id}, function(group) {
                    callback(group);
                }, errorCallback);
    };

    let leave = function(group, callback, errorCallback) {
        KRYPTOS.XMPP.unsubscribeGroup(group.jid, function() {
            App.KA.leaveGroupChat({id: group.group_chat_id}, function(group) {
                    callback(group);
                }, errorCallback);
        });

    };

    let subject = function(id, subject, callback, errorCallback) {
        App.KA.changeGroupChatSubject({id: id, subject: App.KU.eURI(subject)}, function(group) {
                    callback(group);
                }, errorCallback);
    };

    let subscribe = function(group) {
        KRYPTOS.XMPP.subscribeGroup(group.jid, function() {
        });
    };

    let getGroup = function(id, callback, errorCallback) {
        App.KA.getGroupChat({id: id}, function(group) {
                    callback(group);
                }, errorCallback);
    };

    let init = function(serviceKeyStore) {
        keyStore = serviceKeyStore;
    };

    return {
        init: init,
        create: create,
        destroy: destroy,
        leave: leave,
        subject: subject,
        subscribe: subscribe,
        getGroup: getGroup,
        loadGroupChats: loadGroupChats,
        getGroupKey: getGroupKey,
        removeGroupKey: removeGroupKey,
        log: function() {
        }
    };

}();
