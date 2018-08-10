/* global KRYPTOS, Chats, Calls, Contacts, App */

"use strict";
/**
 * KRYPTOS XMPP Module over WebSocket using Strophejs and used for end-to-end
 * encrypted chat messaging, group chat messaging and call signalling.
 *
 * @name KRYPTOS
 * @copyright Copyright © FortKnoxster Ltd. 2014 - 2018.
 * @license Apache License, Version 2.0 http://www.apache.org/licenses/LICENSE-2.0
 * @author Mickey Johnnysson <mj@fortknoxster.com>
 * @version 4.0
 */

/**
 * The KRYPTOS XMPP Module.
 */
KRYPTOS.XMPP = function() {

    const IQ_SEND_TIMEOUT = 3000;

    const CHECK_INTERVAL_MS = 5000; //ms

    const PING_TIMEOUT_MS = 15000; //ms

    const NS = {
        CARBONS: 'urn:xmpp:carbons:2',
        FORWARD: 'urn:xmpp:forward:0',
        PUSH: 'urn:xmpp:push:0',
        BLOCKING: 'urn:xmpp:blocking',
        MUCSUB: 'urn:xmpp:mucsub:0',
        UNREAD: 'p1:unread',
        MAM: 'urn:xmpp:mam:tmp',
        RECEIPTS: 'urn:xmpp:receipts'
    };

    const KA = KRYPTOS.API;

    const KC = KRYPTOS.Chat;

    const RESOURCE = "FKX_WEB";

    let keyStore = null;

    let wsEndPoint = KRYPTOS.session.getItem('websocket_url');

    let chatHost = KRYPTOS.session.getItem('chat_host');

    let username = null;

    let password = null;

    let xmppHandlers = [];

    let xmpp = null;

    let hasInit = false;

    let isConnected = function() {
        return xmpp && xmpp.connected;
    };

    let isAuthenticated = function() {
        return xmpp && xmpp.authenticated;
    };

    let jidToFid = function (jid) {
        return Strophe.unescapeNode(getBareJid(jid).toLowerCase());
    };

    let pingTimer = null;

    let handleStatus = function (status, condition) {
        switch (status) {
            case Strophe.Status.CONNECTING:
                break;
            case Strophe.Status.CONNECTED:
                xmpp.addHandler(KRYPTOS.XMPP.onRosterChanged, 'jabber:iq:roster', 'iq', 'set');
                xmpp.addHandler(KRYPTOS.XMPP.onPresence, null, 'presence');
                xmpp.addHandler(KRYPTOS.XMPP.onChatMessage, null, 'message', 'chat');
                xmpp.addHandler(KRYPTOS.XMPP.onChatMessage, null, 'message', 'headline');
                xmpp.addHandler(KRYPTOS.XMPP.onGroupChatMessage, null, 'message', 'groupchat');
                //xmpp.addHandler(KRYPTOS.XMPP.onReceipt, 'urn:xmpp:receipts', 'received', 'id');
                xmpp.addHandler(KRYPTOS.XMPP.onReceived, null, 'message');

                sendPresence('online');
                carbon('enable');
                initPing();


                if (KRYPTOS.session.getItem('enable_push') === 'true') {
                    enablePush(function() {
                        KRYPTOS.session.removeItem('enable_push');
                    });
                }
                handle('connected', {});
                break;
            case Strophe.Status.ATTACHED:
                break;
            case Strophe.Status.DISCONNECTED:
                break;
            case Strophe.Status.CONNFAIL:
                break;
            case Strophe.Status.AUTHFAIL:
                break;
            case Strophe.Status.CONNTIMEOUT:
                break;
            case Strophe.Status.DISCONNECTING:
                break;
            case Strophe.Status.ERROR:
                break;
        }
    };

    /**
     * Handle carbons (XEP-0280).
     *
     * @param {string} enable
     * @param {function} cb
     * @returns {void}
     */
    let carbon = function(enable, cb) {
        let iq = $iq({
            type: 'set'
        }).c(enable, {
            xmlns: NS.CARBONS
        });

        xmpp.sendIQ(iq, function() {
            if (cb) {
                cb.call(this);
            }
        }, function (stanza) {
            console.error(stanza);
        });
    };

    let block = function(jid, cb) {
        let iq = $iq({
            type: 'set'
        }).c('block', {
            xmlns: NS.BLOCKING
        }).c('item', {
            jid: jid
        });

        xmpp.sendIQ(iq, function() {
            if (cb) {
                cb(true);
            }
        }, function (stanza) {
            console.error(stanza);
            if (cb) {
                cb(false);
            }
        });
    };


    let unblock = function(jid, cb) {
        let iq = $iq({
            type: 'set'
        }).c('unblock', {
            xmlns: NS.BLOCKING,
        }).c('item', {
            jid: jid
        });

        xmpp.sendIQ(iq, function() {
            if (cb) {
                cb(true);
            }
        }, function (stanza) {
            console.error(stanza);
            if (cb) {
                cb(false);
            }
        });
    };

    let getUnread = function(jids)  {
        let iq = $iq({type: 'get', id: KRYPTOS.uniqueId(32)})
                    .c('status', {xmlns: NS.UNREAD})
                    for (let jid of jids) {
                        iq.c('peer', {jid: jid});
                    }

        iq.up();
        send(iq);
    };

    let onRosterChanged = function(iq) {


        $(iq).find('item').each(function () {
            let jid = $(this).attr('jid');
            let sub = $(this).attr('subscription');
            let fid = jidToFid(jid);
            // let ask = $(this).attr('ask');
            if (sub === 'remove') {
            }
            else if (sub === 'from') {

            }
            // Remove pending friendship request from notice list
            else if ( sub === 'both') {
                handle('roster-accepted', {fid: fid});
            }

        });


        return true;
    };

    let onPresence = function(presence) {
        let $presence = $(presence);

        let ptype = $presence.attr('type');
        let from = $presence.attr('from');
        let status = $presence.find('status').text();
//        let setAvatar = $presence.attr('set_avatar');
        let broadcast = null;
        try {
            broadcast = status !== "" ? JSON.parse(status) : {};
        }
        catch(error) {

        }
        let jid = Strophe.getBareJidFromJid(from).toLowerCase();
        //let resource = Strophe.getResourceFromJid(from);
        let fid = jidToFid(jid);


        if (broadcast && broadcast.set_avatar) {
            handle('avatar', {fid: fid, avatar_id: broadcast.set_avatar});
            return true;
        }

        if (ptype === 'unavailable' || ptype === 'unsubscribed') {
            handle('online', {fid: fid, online: false});
            return true;
        }
        if (ptype === 'error') {

            return true;
        }
        if (ptype === 'subscribe') {

            return true;
        }

        handle('online', {fid: fid, online: true});

        return true;
    };

    let onChatMessage = function(stanza) {
        let $stanza = $(stanza);
        let forwarded = $stanza.find('forwarded[xmlns="' + NS.FORWARD + '"]');
        let message = null, carbon = null;

        if (forwarded.length > 0) {
            message = forwarded.find('> message');
            forwarded = true;
            carbon = $stanza.find('> [xmlns="' + NS.CARBONS + '"]');

            if (carbon.length === 0) {
                carbon = false;
            }

        }
        else {
            message = stanza;
            forwarded = false;
            carbon = false;

        }

        let $message = $(message);

        let body = $message.find('body:first').text();
        if (!body) {
            return true;
        }

        let type = $message.attr('type');
        let from = $message.attr('from');
        let mid = $message.attr('id');

        if (!mid) { // iOS message id fix - when id is tag
            mid = $message.find('stanza-id:first').attr('id');
        }
        if (!mid) { // iphone fix - when message id is tag messageId
            mid = $message.find('messageId:first').text();
        }
        let fid;

        let delay = $message.find('delay[xmlns="urn:xmpp:delay"]');

        let stamp = (delay.length > 0) ? new Date(delay.attr('stamp')) : new Date();
        stamp = stamp.getTime();
        // Used to get the sender via the resource when private signal messaging over MUC
//        let nickname = Strophe.unescapeNode(Strophe.getResourceFromJid(from));
//        let sender = {};
//        sender.name = nickname;

        if (carbon) {
            let direction = (carbon.prop("tagName") === 'sent') ? Chats.MESSAGE.OUT : Chats.MESSAGE.IN;
            fid = jidToFid((direction === Chats.MESSAGE.OUT) ? $message.attr('to') : from);

            let msgObj = {
                from: from,
                msg: body,
                fid: fid,
                dir: Chats.MESSAGE.IN,
                frw: forwarded,
                ts: stamp,
                //sender: sender,
                id: mid
            };

            handle('message', msgObj);
            return true;

        }
        else if (forwarded) {
            // Someone forwarded a message to us
//            body = from + ' ' + $.t('to') + ' ' + $(stanza).attr('to') + '"' + body + '"';
//            from = $(stanza).attr('from');

        }
        else {
            let jid = getBareJid(from);
            fid = jidToFid(jid);
        }

        let request = $message.find("request[xmlns='" + NS.RECEIPTS + "']");

//        if (data === null) {
//            // jid not in roster or offline messages
//
//            // Cache offline messages to fire off later when rosters are loaded.
//            xmpp.offlineMessages.push({
//                from: from,
//                msg: body,
//                fid: fid,
//                direction: Chats.MESSAGE.IN,
//                forwarded: forwarded,
//                stamp: stamp
//            });
//            return true;
//        }

        if (!forwarded && mid !== null && request.length && type === 'chat') {
            // Send received according to XEP-0184
            send($msg({
                to: from
             }).c('received', {
                xmlns: NS.RECEIPTS,
                id: mid
             }));
        }
        let msgObj = {
            from: from,
            msg: body,
            fid: fid,
            dir: Chats.MESSAGE.IN,
            frw: forwarded,
            ts: stamp,
            //sender: sender,
            id: mid
        };
//        if (type === 'headline') {
//            handle('system', msgObj);
//        }
//        else {
//            handle('message', msgObj);
//        }
        handle('message', msgObj);
        // preserve handler
        return true;

    };

    let onMamMessage = function(stanza) {
        let $stanza = $(stanza);
        let result = $stanza.find('result[xmlns="' + NS.MAM + '"]');
        //let queryId = result.attr('queryid');

        if (result.length !== 1) {
           return;
        }

        let forwarded = result.find('forwarded[xmlns="' +  NS.FORWARD + '"]');
        let message = forwarded.find('message');
        let mid = message.attr('id');
        let type = message.attr('type');
        let status;

        if (message.length !== 1) {
           return;
        }

        let from = message.attr('from');
        let fid = jidToFid(from);
        let to = message.attr('to');
        let direction, handler;

        if (type === 'groupchat') {
            handler = 'group-message';
            from = Strophe.unescapeNode(Strophe.getResourceFromJid(from));
            if (from === App.getUserId()) {
                direction = Chats.MESSAGE.OUT;
                status = Chats.STATUS.SENT;
            }
            else {
                direction = Chats.MESSAGE.IN;
                status = Chats.STATUS.RECEIVED;
            }
        }
        else {
            handler = 'message';
            let toJid = jidToFid(to);
            if (username === fid) {
                direction = Chats.MESSAGE.OUT;
                status = Chats.STATUS.SENT;
                fid = toJid;
            }
            else {
                direction = Chats.MESSAGE.IN;
                status = Chats.STATUS.RECEIVED;
            }
        }
        let delay = forwarded.find('delay[xmlns="urn:xmpp:delay"]');
        if (delay.length === 0) {
        }
        else {
        }
        let stamp = (delay.length > 0) ? new Date(delay.attr('stamp')) : new Date();
        stamp = stamp.getTime();
        let ts = result.attr('id');
        let body = message.find('body:first').text();

        //let direction = (jidToFid(to) === fid) ? Chats.MESSAGE.OUT : Chats.MESSAGE.IN;

        // ACK MAM stored deliver requests
        let request = message.find("request[xmlns='" + NS.RECEIPTS + "']");
        if (mid !== null && request.length && direction === Chats.MESSAGE.IN) {
            // Send received according to XEP-0184
            send($msg({
                to: from
             }).c('received', {
                xmlns: NS.RECEIPTS,
                id: mid
             }));
        }
        let received = message.find("received[xmlns='" + NS.RECEIPTS + "']");
        if (mid !== null && received.length && direction === Chats.MESSAGE.IN) {
            let receivedId = received.attr('id');
            status = Chats.STATUS.DELIVERED;
            handle('receipt', {id: receivedId});
            return true;
        }

        let msgObj = {
            from: from,
            msg: body,
            fid: fid,
            dir: direction,
            frw: true,
            ts: ts, // timestamp for sorting / querying
            stamp: stamp,
            id: mid,
            mam: true,
            status: status
        };

        //return true;

        handle(handler, msgObj);

        // preserve handler
        return true;
    };

    let onGroupChatMessage = function($message) {

        let mid = $message.attr('id');
        let ts = $message.find('stanza-id:first').attr('id');
        if (!mid) { // iOS message id fix - group chat ios fix
            mid = ts;
        }
        let from = $message.attr('from');
        let to = $message.attr('to');
        let body = $message.find('body:first').text();
        let roomJid = getBareJid(from);
        let fromUser = Strophe.unescapeNode(Strophe.getResourceFromJid(from));
        if (body !== '') {
            let stamp = ts;

            //New way with muc

            // Old way with delay
            let delay = $message.find('delay[xmlns="urn:xmpp:delay"]');
            stamp = (delay.length > 0) ? new Date(delay.attr('stamp')) : new Date();
            stamp = stamp.getTime();

            let direction, forwarded;
            if (fromUser === App.getUserId()) {
                direction = Chats.MESSAGE.OUT;
                forwarded = true;
            }
            else {
                direction = Chats.MESSAGE.IN;
                forwarded = false;
            }

            let msgObj = {
                from: fromUser,
                msg: body,
                fid: roomJid,
                dir: direction,
                frw: forwarded,
                ts: stamp,
                stamp: stamp,
                id: mid
            };
            handle('group-message', msgObj);
            return true;
        }

        return true;

    };

    let onReceived = function(stanza) {
        let $stanza = $(stanza);
        let received = $stanza.find('received[xmlns="' + NS.RECEIPTS + '"]');
        let request = $stanza.find('request[xmlns="' + NS.RECEIPTS + '"]');

        if (received.length) {
            let receivedId = received.attr('id');
            handle('receipt', {id: receivedId});
        }
        if (request.length) {
            let requestId = $stanza.attr('id');
            handle('sent', {id: requestId});
        }
        let sent = $stanza.find('on-sender-server[xmlns="' + NS.RECEIPTS + '"]');
        if (sent.length) {
            let sentId = sent.attr('id');
            handle('sent', {id: sentId});
        }

        let mamMsg = $stanza.find('result[xmlns="' + NS.MAM + '"]');
        if (mamMsg.length) {
            //let receivedId = received.attr('id');
            //KRYPTOS.XMPP.onChatMessage(stanza);
            onMamMessage(stanza);
            //handle('archive', {});
            return true;
        }

        // New incoming groupchat
        let groupChat = $stanza.find("x[xmlns='jabber:x:conference']");
        if (groupChat.length) {
            let jid = groupChat.attr('jid');
            handle('groupchat', {jid: jid});
        }

        // New incoming group message
        let eventItems = $stanza.first('event').find("items[node='urn:xmpp:mucsub:nodes:messages']");
        if (eventItems.length) {
            eventItems.children('item').each(function(index, item) {
                let message = $(item).find('message');
                onGroupChatMessage(message);
            });
        }

        // Always return true to keep alive
        return true;
    };

    let addHandler = function(handle, handler) {
        xmppHandlers.push({
            handle: handle,
            handler: handler
        });
    };

    let removeHandler = function(handle) {
    };

    let handle = function(handle, data) {
        for (let i = 0; i < xmppHandlers.length; i++) {
            if (xmppHandlers[i].handle === handle) {
                xmppHandlers[i].handler(data);
            }
        }
    };

//    let send = function (strData) {
//        if (!isConnected()) {
//            if (!isConnecting()) {
//                connect();
//            }
//            return false;
//        }
//        wSocket.send(strData);
//    };

    let setKeyStore = function(serviceKeyStore) {
        keyStore = serviceKeyStore;
    };

    let connect = function(jid, pass) {
        username = jid;
        password = pass;
        Strophe.addNamespace('RECEIPTS', NS.RECEIPTS);
        xmpp = new Strophe.Connection(wsEndPoint);
        let fullJid = jid + "/" + RESOURCE + "_" + KRYPTOS.uniqueId(8);
        xmpp.connect(fullJid, password, handleStatus);
    };

    let disconnect = function() {
        try {
            if (xmpp) {
                xmpp.flush(); // flush any pending messages on the queue
                xmpp.disconnect();
                setTimeout(function () {
                    if (xmpp) {
                        xmpp.disconnect();
                    }
                 }, 500);
            }
        }
        catch (error) {
            console.error(error);
        }
    };

    let reconnect = function() {
        connect(username, password);
    };

    let ping = function() {
        if (Calls.isBusy()) { // Don't ping while on call
            return;
        }
        xmpp.ping.ping(chatHost, pong, pingError, 15000);
    };

    let pong = function(ping) {
        xmpp.ping.pong(ping);
        // last response from server.
        let lastPingTimeStamp = new Date();
        return true;
    };

    let pingError = function(errorStanza) {
    };

    let stopPing = function() {
        if (pingTimer !== null) {
            clearInterval(pingTimer);
        }
    };

    /**
     * Keep alive.
     *
     * @returns {undefined}
     */
    let initPing = function() {
        pingTimer = setInterval(function() {
            if (isOnline()) {
                ping({});
            }
            else {
                reconnect();
            }

        }, 10000);
    };

    let sendPresence = function(presence) {
        if (xmpp && xmpp.disco) {
            xmpp.disco.addIdentity('client', 'web', 'FKX');
            xmpp.disco.addFeature(Strophe.NS.DISCO_INFO);
            xmpp.disco.addFeature(Strophe.NS.RECEIPTS);
        }

        let pres = null;

        if (presence === 'offline') {
            pres = $pres({
                xmlns: Strophe.NS.CLIENT,
                type: 'unavailable'
            });
        }
        else {
            pres = $pres();
            if (xmpp.caps) {
                // attach caps
                pres.c('c', xmpp.caps.generateCapsAttrs()).up();
            }
            if (presence !== 'online') {
                pres.c('show').t(presence).up();
            }
        }
        send(pres);
    };

    let sendMessage = function(sendObj) {
        if (!isOnline()) {
            throw new Error('No connection');
            return;
        }
        let from = xmpp.jid;
        let xmlMsg = $msg({
            from: from,
            to: sendObj.jid,
            type: sendObj.type,
            id: sendObj.mid
        }).c('body').t(sendObj.msg);

        if (sendObj.sig) {
            xmlMsg.up().c("no-store", {
                xmlns: 'urn:xmpp:hints'
            });
        }

        if (sendObj.priv) {
            xmlMsg.up().c("private", {
                xmlns: NS.CARBONS
            });
        }
        if (!sendObj.sig) {
            //Add request according to XEP-0184
            xmlMsg.up().c('request', {
                xmlns: NS.RECEIPTS
            });
        }
        send(xmlMsg);
        //xmpp.sendIQ(xmlMsg, sendObj.success, null, IQ_SEND_TIMEOUT);
    };

    let sendMessage2 = function(to, message) {
        let  msg = $msg({to: to, type: "chat"}).c("body").t(message);
        send(msg);
    };

    let sendGroupMessage = function(to, message) {
        let  msg = $msg({to: to, type: "groupchat"}).c("body").t(message);
        send(msg);
    };

    let send = function(stanza) {
        xmpp.send(stanza);
    };

    let isOnline = function() {
        //https://developer.mozilla.org/en-US/docs/Web/API/NavigatorOnLine/onLine
//        if (window.navigator.onLine) {
//        } else {
//        }
        return xmpp && xmpp.connected && xmpp.authenticated;
    };

    let enablePush = function(cb) {
        let userId = App.getUserId();
        let id = userId + ":" + new Date().getTime();
        KRYPTOS.Encrypter(keyStore, null, null, function(success, data) {


            let identifier = data.id + ":" + data.signature;

            let iq = $iq({type:'set', id: KRYPTOS.uniqueId(32)})
                .c('push', {xmlns:'p1:push'})
                .c('keepalive', {max:'60'}).up()
                .c('session', {duration:'60'}).up()
                .c('body', {send:'all', groupchat:'true', from:'jid'}).up()
                .c('offline', 'true').up()
                .c('notification')
                .c('type').t('webhook').up()
                .c('id').t(identifier).up()
                .up().c('appid').t('id');

            send(iq);
            if (cb) cb();

        }).signIt({id: id}, true, true);
    };

    let subscribeGroup = function(toJid, cb) {
        /**
         *
         * <iq from='hag66@shakespeare.example'
         *       to='coven@muc.shakespeare.example'
         *       type='set'
         *       id='E6E10350-76CF-40C6-B91B-1EA08C332FC7'>
         *     <subscribe xmlns='urn:xmpp:mucsub:0'
         *                nick='newnick'>
         *       <event node='urn:xmpp:mucsub:nodes:messages' />
         *       <event node='urn:xmpp:mucsub:nodes:presence' />
         *     </subscribe>
         *   </iq>
         */
        sendSubscription(toJid, getJid(), App.KU.e2u(getJid()));
        if (cb) cb();
    };
    let unsubscribeGroup = function(toJid, cb) {
        sendUnsubscription(toJid, getJid(), App.KU.e2u(getJid()));
        if (cb) cb();
    };

    let subscribeMembersGroup = function(toJid, members, cb) {
        for (let value of members) {
            //sendSubscription(toJid, value.jid, value.nick);
            subscribeMemberToGroup(toJid, value.jid, value.nick);
        }
        if (cb) cb();
    };

    let subscribeMemberToGroup = function(toJid, memberJid, memberNick, cb) {
        let iq = $iq({from: getJid(), to: toJid, type: 'set', id: KRYPTOS.uniqueId(32)})
                    .c('subscribe', {xmlns: NS.MUCSUB, jid: memberJid, nick: memberNick})
                    .c('event', {node: 'urn:xmpp:mucsub:nodes:messages'}).up();
        send(iq);
        if (cb) cb();
    };

    let sendSubscription = function(to, from, nick) {
        let iq = $iq({from: from, to: to, type: 'set', id: KRYPTOS.uniqueId(32)})
                    .c('subscribe', {xmlns: NS.MUCSUB, nick: nick})
                    .c('event', {node: 'urn:xmpp:mucsub:nodes:messages'}).up();
        send(iq);
    };

    let sendUnsubscription = function(to, from, nick) {
        let iq = $iq({from: from, to: to, type: 'set', id: KRYPTOS.uniqueId(32)})
                    .c('unsubscribe', {xmlns: NS.MUCSUB, nick: nick}).up();
        send(iq);
    };

    let loadMam = function(fid, before, onCompleted) {
        if (!before) {
            before = new Date().getTime() * 1000;
        }

        if (App.KU.isConference(fid)) {
            xmpp.mam.query(fid, {
                max: 20,
                before: before,
                onMessage: function(message) {
                    return true;
                },
                onComplete: onCompleted
            });
        }
        else {
            xmpp.mam.query(username, {
                with: fid,
                max: 20,
                before: before,
                onMessage: function(message) {
                    return true;
                },
                onComplete: onCompleted
            });
        }
    };

    let getResource = function() {
        return Strophe.getResourceFromJid(getFullJid());
    };

    let getFullJid = function() {
        return xmpp.jid;
    };

    let getJid = function() {
        return getBareJid(getFullJid());
    };

    let getBareJid = function(fullJid) {
        return Strophe.getBareJidFromJid(fullJid);
    };

    return {
        setKeyStore: setKeyStore,
        connect: connect,
        disconnect: disconnect,
        isConnected: isConnected,
        isAuthenticated: isAuthenticated,
        isOnline: isOnline,
        send: send,
        addHandler: addHandler,
        removeHandler: removeHandler,
        stopPing: stopPing,
        initPing: initPing,
        sendPresence: sendPresence,
        sendMessage: sendMessage,
        sendGroupMessage: sendGroupMessage,

        onRosterChanged: onRosterChanged,

        onPresence: onPresence,

        onChatMessage: onChatMessage,

        onGroupChatMessage: onGroupChatMessage,

        onReceived: onReceived,

        loadMam: loadMam,

        block: block,
        unblock: unblock,

        getUnread: getUnread,

        getResource: getResource,
        getFullJid: getFullJid,
        getJid: getJid,
        getBareJid: getBareJid,
        subscribeGroup: subscribeGroup,
        unsubscribeGroup: unsubscribeGroup,
        subscribeMembersGroup: subscribeMembersGroup,
        enablePush: enablePush,
        log: function() {
        }
    };

}();
