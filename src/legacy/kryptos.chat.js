/* global KRYPTOS, Sanitize, MediaRecorder, App, U, jsxc, Groups, Chats */

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
 * The KRYPTOS Chat module.
 */

KRYPTOS.Chat = function() {

    let keyStore = null;

    const KG = KRYPTOS.Groups;

    const symmetricAlgo = "AES-CBC-256";

    let handlers = [];

    let jid = null;

    let init = function(chatKeyStore, myJid, password) {
        jid = myJid;

        keyStore = chatKeyStore;

        KRYPTOS.XMPP.setKeyStore(keyStore);
        KRYPTOS.XMPP.connect(jid, password);
        addXmppHandler('message', receiveEncryptedMessage);
        addXmppHandler('group-message', receiveEncryptedGroupMessage);
//        KRYPTOS.XMPP.addHandler('message', receiveMessage);
//        KRYPTOS.XMPP.addHandler('sent', messageSentReceipt);
//        KRYPTOS.XMPP.addHandler('receipt', messageReceivedReceipt);

    };

    let addHandler = function(handle, handler) {
        handlers.push({
            handle: handle,
            handler: handler
        });
    };

    let addXmppHandler = function(handle, handler) {
        KRYPTOS.XMPP.addHandler(handle, handler);
    };

    let removeHandler = function(handle) {
    };

    let handle = function(handle, data) {
        for (var i = 0; i < handlers.length; i++) {
            if (handlers[i].handle === handle) {
                handlers[i].handler(data);
            }
        }
    };

    let receiveEncryptedMessage = function(msg) {
        let message = JSON.parse(msg.msg);
        if (message.t === 'sys') {
            msg.dir = Chats.MESSAGE.SYS;
            handle('system', {
                msg: msg,
                parsed: message
            });
        }
        else if (message.t === 'sync' && !message.keys) {
            handle('sync', {
                msg: msg,
                parsed: message.body
            });
        }
        else {
            return decryptMessage(msg.from, message, msg.id)
                .then(function(msgObj) {
//                    console.log('decryptMessage');
//                    console.dir(msgObj);
                    msg.msg = msgObj.obj.body;
                    msg.attachment = msgObj.obj.attachment || null;

                    if (message.t === 'call') {
                        handle('signal', {
                            from: App.KU.e2u(msg.from),
                            body: msg.msg
                        });
                    }
                    else if (message.t === 'chat') {
                        handle('message', msg);
                    }
                    else if (message.t === 'sync') {
                        handle('sync', {
                            msg: msg,
                            parsed: JSON.parse(msg.msg)
                        });
                        //handleSync(msgObj.body);
                    }
                    else {
                    }


                }).catch(function(error) {
                });
            }
    };

    let receiveEncryptedGroupMessage = function(msg) {
        let message = JSON.parse(msg.msg);
        if (message.t === 'sys') {
            msg.dir = Chats.MESSAGE.SYS;
            handle('system', {
                msg: msg,
                parsed: message
            });
        }
        else {
            return decryptGroupMessage(msg.from, message, msg.fid, msg.id)
                .then(function(msgObj) {
                    msg.msg = msgObj.obj.body;
                    msg.attachment = msgObj.obj.attachment || null;

                    if (message.t === 'call') {
                        handle('signal', {
                            from: App.KU.e2u(msg.from),
                            body: msg.msg
                        });
                    }
                    else if (message.t === 'chat') {
                        handle('message', msg);
                    }
                    else if (message.t === 'sync') {
                        handle('sync', msg);
                        //handleSync(msgObj.body);
                    }
                    else {
                    }


                }).catch(function(error) {
                });
            }
    };

    let encryptMessage = function(fid, protocol, body, cb) {
        if (App.KU.isConference(fid)) {
            return encryptGroupMessage(fid, body, cb);
        }
        let to = [];
        let plainText = App.KU.eURI(JSON.stringify(body));
        to = [KRYPTOS.utils.e2u(fid)];
        to.push(App.getUserId()); // Include yourself
        keyStore.getRecipientsPublicKeys(to, function(success, message) {
            if (success) {
                //log(plainText);
                let encrypter = new KRYPTOS.Encrypter(keyStore, plainText, {to: to}, function(success, result) {
                    if (success) {
                        result.t = protocol;
                        cb(JSON.stringify(result), true);
                        //cb(App.KU.obj2b64(result), true);
                    }
                    else {
                        cb(result, false);
                    }
                });
                encrypter.encryptChatMessage();
            }
            else {
                cb(message, false);
            }
        });
    };

    let encryptSend = function(message, protocol, errorCb) {
        let msgObj = {body: message.msg || "", attachment: message.attachment || ''};

        encryptMessage(message.fid, protocol, msgObj, function(result, success) {
            if (success) {
                let sendObj = {
                    jid: message.fid,
                    msg: result,
                    mid: message.id || KRYPTOS.uniqueId(32),
                    type: message.type,
                    sig: message.sig,
                    priv: message.priv
                };
                try {
                    //jid, msg, mid, type, sig, priv
                    KRYPTOS.XMPP.sendMessage(sendObj);
                }
                catch(e) {
                    if (errorCb) {
                        errorCb(e);
                    }
                }
            }
        });
    };

    let encryptGroupMessage = function(fid, body, cb) {
        let to = [];
        let plainText = encodeURIComponent(JSON.stringify(body));
        let Encrypter = new KRYPTOS.Encrypter(keyStore, plainText, null, function(success, result) {
            if (success) {
                log(' ------------------------ GROUP CHAT MESSAGE ------------------------');
                log(result);
                let message = {
                    m: result.m,
                    iv: result.iv,
                    s: result.s
                    //from: me
                };
                result.t = 'chat';
                cb(JSON.stringify(result), true);
                //cb(App.KU.obj2b64(message), true);
            }
            else {
               cb(result, false);
            }
        });
        KG.getGroupKey(fid, false, function(key) {
            Encrypter.encryptGroupChatMessage(key);
        });
    };

    let handleSystemMessage = function(from, message, bid, direction, forwarded, stamp, sender, mamMessage) {
        let msg = {};
        try {
            msg = JSON.parse(message);
            // validate system message
            if (!msg.message && !msg.action && !msg.value) {
                return;
            }
        }
        catch(error) {
            return;
        }
        let sysMsg = {
            bid: bid,
            direction: jsxc.Message.SYS,
//            stamp: stamp,
            msg: KRYPTOS.utils.decodeURIComp(null, msg.message, "subj")
        };
        // if (mamMessage) {
        //     sysMsg.isMam = true;
        // }
        if (mamMessage) {
            let gId = mamMessage._uid.match(/^\d+:msg$/);
            if (!gId) {
                sysMsg._uid = mamMessage.stamp+":msg";
            }
            //sysMsg._uid = mamMessage._uid;
            if (msg.action !== 'change-avatar') {
                jsxc.gui.window.postMessage(sysMsg);
                // countMamMessageAsProcessed(mamMessage);
                return;
            }
        }

        if (isOwner(bid) && msg.action === 'create-group') {
            return;
        }

        jsxc.gui.window.postMessage(sysMsg);
        switch(msg.action) {
            case 'create-group':
//                Groups.notifyNewGroup(bid);
                break;
            case 'add-member':
                getGroupChat(bid, false, false, function() {
                    let members = msg.value.split(',');
                    let data = jsxc.storage.getUserItem('buddy', bid);
                    for (let i = 0; i < members.length; i++) {
                        let member = getGroupMember(bid, members[i]);
                        if (App.KU.e2u(members[i]) === App.getUserId()) {
//                            Groups.notifyNewGroup(bid);
                        }
                        jsxc.muc.insertMember(bid, members[i], member, isOwner(bid), data.has_subject);
                    }
                });
                //jsxc.gui.window.open(bid);
                break;
            case 'remove-member':
            case 'leave-group':
                jsxc.muc.removeMember(bid, msg.value);
                break;
            case 'change-subject':
                jsxc.storage.updateUserItem('buddy', bid, 'name', msg.value);
                jsxc.storage.updateUserItem('buddy', bid, 'has_subject', true);
                let win = jsxc.gui.window.get(bid);
                win.find('.jsxc_name:first').html(KRYPTOS.utils.escapeHTML(msg.value));
                jsxc.gui.roster.getItem(bid).find('.jsxc_name').html(KRYPTOS.utils.escapeHTML(msg.value));
                break;
            case 'change-avatar':
                if (isOwner(bid)) {
                    return;
                }
                Groups.updateGroupPicture(bid, msg.value);
//                if (mamMessage) { // Just updated session storage
//                    Groups.updateGroup(bid, {avatar: msg.value});
//                }
//                else {
//                    Groups.updateGroupPicture(bid, msg.value);
//                }
                break;
        }
    };

    let decryptMessage = function(from, messageObj, mid) {
        let fromUser = App.KU.e2u(from);
//        log(KRYPTOS.utils.getUsernameById(fromUser));
        return new KRYPTOS.Promise(function (resolve, reject) {
//            let messageObj = App.KU.b642obj(message);
//            let messageObj = JSON.parse(message);
            let mKey = null;
            for (let i in messageObj.keys) {
                if (messageObj.keys[i].u === App.getUserId()) {
                    mKey = messageObj.keys[i].k;
                    break;
                }
            }
            if (mKey === null) {
                reject("No encryption key found.")
                return;
            }
            messageObj.key = App.KU.b642ab(mKey);
            messageObj.iv = App.KU.b642ab(messageObj.iv);
            messageObj.message = App.KU.b642ab(messageObj.m);
            messageObj.signature = App.KU.b642ab(messageObj.s);

            new KRYPTOS.Decrypter(keyStore, messageObj.key, messageObj.iv, messageObj.message, messageObj.signature, null, null, function(decText) {
                let msgObj = decText;
                msgObj.obj = JSON.parse(decodeURIComponent(decText.plain));
                resolve(msgObj);
//                if (messageObj.t === 'call') {
//                    handle('signal', {
//                        from: fromUser,
//                        body: msgObj.body
//                    });
//                    resolve();
//                }
////                else if (messageObj.t === 'sys') {
////                }
//                else if (messageObj.t === 'chat') {
//                    resolve(msgObj);
//                }
//                else {
//                }
            })
            .decryptIt(fromUser, mid, symmetricAlgo)
            .catch(function (error) {
                KRYPTOS.utils.log(error);
                reject(error.message ? error.message : error);
            });
        });
    };

    let decryptGroupMessage = function(from, messageObj, fid, mid) {
        return new KRYPTOS.Promise(function (resolve, reject) {
                KG.getGroupKey(fid, false, function(key) {
                    new KRYPTOS.Decrypter(keyStore, key, App.KU.b642ab(messageObj.iv), App.KU.b642ab(messageObj.m), App.KU.b642ab(messageObj.s), null, null, function(decText) {
                        //console.dir(decText);
                        let msgObj = decText;
                        msgObj.obj = JSON.parse(decodeURIComponent(decText.plain));
                        resolve(msgObj);
                    }).decryptGroupMessage(from, mid);
                });
        });
    };

    let encryptFile = function(file, callback) {
        KRYPTOS.Files.encryptFile(file, callback);
    };

    let decryptFile = function(meta, data, callback) {
        KRYPTOS.Files.decryptFile(meta, data, callback);
    };
    
    let syncChatAllRead = function(fid) {
//        console.log('syncChatAllRead');
//        console.dir(fid);
        let command = {
            a: 'ar',
            v: fid
        };
        systemMessage(command);
    };

    let systemMessage = function(body) {
        let msg = "";
        if (typeof body === 'object') {
            msg = JSON.stringify(body);
        }
        else if (typeof body === 'string') {
            msg = body;
        }
        else {
            log('Invalid type of body, Object og JSON string allowed');
            return;
        }

        let sendObj = {
            fid: jid,
            msg: msg,
            type: 'chat',
            sig: true,
            priv: false
        };

        encryptSend(sendObj, 'sync');
    };



    let sendSignal = function(to, body, errorCb) {
        let json = {
            fid: to,
            msg: JSON.stringify(body),
            type: 'chat',
            sig: true,
            priv: false
        };
        encryptSend(json, 'call', errorCb);
    };

    let sendGroupSignal = function(to, body, priv, errorCb) {
        let json = {
            fid: to,
            msg: JSON.stringify(body),
            type: 'groupchat',
            sig: true,
            priv: priv
        };
        encryptSend(json, 'call', errorCb);
    };

    let addSignalCallback = function(callback) {
        addHandler('signal', callback);
    };

    let addGroupSignalCallback = function(callback) {
        addHandler('groupsignal', callback);
    };

    let addSyncCallback = function(callback) {
        addHandler('sync', callback);
    };

    let recentChats = function(count, callback) {


        App.KA.getRecentChats({n: count}, function(response) {
            if (!response || response.length === 0) {
                callback(false);
                return;
            }
            let recentChats = [];
            let promises = [];

//            let usernames = [];
//            for (let i = 0; i < response.length; i++) {
//                if (App.KU.isConference(response[i].to)) {
//                    continue;
//                }
//                usernames.push(response[i].from_username);
//            };


            for (let i = 0; i < response.length; i++) {
//                if (App.KU.isConference(response[i].to) || response[i].peer === "admin@localhost") {
//                    continue;
//                }

                let message = response[i].message;
                let to = App.KU.e2u(response[i].to);
                let from = App.KU.e2u(response[i].from);
                let username = response[i].from_username;
                let type = response[i].type;
                let id = response[i].id;
                let jid = type === 'groupchat' ? response[i].to : response[i].peer;//response[i].peer === 'admin@localhost' ||  id === App.getUserId() ? response[i].to : response[i].peer;

                recentChats.push({
                    id: id,
                    from: from,
                    to: to,
                    jid: jid,
                    type: type,
                    body: null,
                    timestamp: response[i].timestamp,
                    created_at: response[i].created_at,
//                    created_at_f: response[i].created_at_f,
//                    created_at_today: response[i].created_at_today,
//                    created_at_time: response[i].created_at_time,
                    bare_peer: App.KU.e2u(response[i].peer),//App.KU.getUsernameById(App.KU.e2u(response[i].peer)),
                    peer: response[i].peer
                });

                let msgObj = JSON.parse(message);

                if (U.isFK(from)) {
                    from = "FortKnoxster";
                    promises.push(
                        new KRYPTOS.Promise(function (resolve, reject) {
                            resolve({
                                id: id,
                                plain: App.KU.dURI(msgObj.message),
                                failed: false,
                                system: true
                            });
                        })
                    );
                    break;
                }
                if (type === 'groupchat') {
                    if (msgObj.t && msgObj.t === 'sys') {
                        let systemMessage = {
                            msg: message,
                            parsed: msgObj
                        };
                        promises.push(
                            new KRYPTOS.Promise(function (resolve, reject) {
                                resolve({
                                    id: id,
                                    plain: Chats.systemMessage(systemMessage, true),
                                    failed: false,
                                    system: true
                                });
                            })
                        );
                    }
                    else {
                        promises.push(
                            decryptGroupMessage(from, msgObj, jid, id)
                            //new KRYPTOS.Decrypter(keyStore, key, iv, body, signature).decrypt2(from, id)
                        );
                    }
                    continue;
                }
//                let mKey = null;
//                for (let j in msgObj.keys) {
//                    if (msgObj.keys[j].u === App.getUserId()) {
//                        mKey = msgObj.keys[j].k;
//                        break;
//                    }
//                }
//                if (mKey === null) {
//                    continue;
//                }
//                let key = App.KU.b642ab(mKey);
//                let iv = App.KU.b642ab(msgObj.iv);
//                let body = App.KU.b642ab(msgObj.m);
//                let signature = App.KU.b642ab(msgObj.s);
                promises.push(
                    decryptMessage(from, msgObj, id)
                    //new KRYPTOS.Decrypter(keyStore, key, iv, body, signature).decrypt2(from, id)
                );
            }

            KRYPTOS.Promise.all(promises)
                .then(function(result) {
                    for (let i = 0; i < result.length; i++) {
                        for (let j = 0; j < recentChats.length; j++) {
                            if (result[i].id === recentChats[j].id) {
                                if (result[i].plain.t && result[i].plain.t === 'sys') {
                                    //recentChats[j].msg = "system message";
                                    recentChats[j].body = recentChats[j].msg;
                                    recentChats[j].attachment = null;
                                    recentChats[j].dir = Chats.MESSAGE.SYS;
                                }
                                else {
                                    let msgObj = {};
                                    if (result[i].failed || result[i].system) {
                                        msgObj = {body: result[i].plain};
                                    }
                                    else {
                                        msgObj = JSON.parse(App.KU.dURI(result[i].plain));
                                    }
                                    if (msgObj.attachment) {
                                        recentChats[j].msg = "";
                                        recentChats[j].body = "Sent file";
                                        recentChats[j].attachment = msgObj.attachment;
                                    }
                                    else if (msgObj.body) {
                                        recentChats[j].msg = App.KU.dURI(msgObj.body); //App.KU.decodeURIComp(null, msgObj.body, 'subj');
                                        recentChats[j].body = recentChats[j].msg;
                                        recentChats[j].attachment = null;
                                        recentChats[j].system = result[i].system && !U.isFK(recentChats[j].from);
                                    }
                                }
                                //log(jsxc.gui.shortnameToImage(plainText));
                            }
                        }
                    }
                    callback(recentChats);
                });
        });
    };

    let log = function(msg) {
    };

    return {
        init: init,

        addHandler: addHandler,
        addXmppHandler: addXmppHandler,
        removeHandler: removeHandler,

        encryptMessage: encryptMessage,
        encryptGroupMessage: encryptGroupMessage,
        decryptMessage: decryptMessage,
        decryptGroupMessage: decryptGroupMessage,
        encryptFile: encryptFile,
        decryptFile: decryptFile,

        encryptSend: encryptSend,

        sendSignal: sendSignal,
        sendGroupSignal: sendGroupSignal,
        addSignalCallback: addSignalCallback,
        addGroupSignalCallback: addGroupSignalCallback,

        addSyncCallback: addSyncCallback,

        systemMessage: systemMessage,
        syncChatAllRead: syncChatAllRead,
        getRecentChats: recentChats,
    };

}();

