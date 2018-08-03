/* global KRYPTOS, converse, locales, UNKNOWN, showErrorMessage, Token */

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
 * @author Mickey Johnnysson <mj@fortknoxster.com>
 * @version 4.0
 */

/**
 * The KRYPTOS Websocket Module.
 */
KRYPTOS.WS = function() {

    var KA = KRYPTOS.API;

    var wsEndPoint = KRYPTOS.session.getItem('node_websocket_url');

    var wsHandlers = [];

    var wSocket = null;

    var hasInit = false;

    var isConnected = function() {
        return wSocket.readyState === 1;
    };

    var isConnecting = function() {
        return wSocket.readyState === 0;
    };

    var pingTimer = null;

    var currentState = function() {
        var state = wSocket.readyState;
        switch(state) {
            case 0: return "CONNECTING";
            case 1: return "OPEN";
            case 2: return "CLOSING";
            case 3: return "CLOSED";
            default: return "UNKNOWN";
        };
    };

    var registerSocketEvents = function() {
        wSocket.addEventListener('open', function (event) {
            KA.wsRegister({});
            initPing();
        });
        wSocket.addEventListener('close', function (event) {
            stopPing();
        });
        wSocket.addEventListener('message', function (event) {

            KA.wsReceiveData(event.data, function(message, data) {
//

                for (var i = 0; i < wsHandlers.length; i++) {
                    if (wsHandlers[i].handle === data.ServiceType) {
                        wsHandlers[i].handler(message);
                    }
                }

            });

        });
        wSocket.addEventListener('error', function (event) {
            stopPing();
        });

    };

    var addHandler = function(handle, handler) {
        wsHandlers.push({
            handle: handle,
            handler: handler
        });
    };

    var removeHandler = function(handle) {
    };

    var send = function (strData) {
        if (!isConnected()) {
            if (!isConnecting()) {
                connect();
            }
            return false;
        }
        wSocket.send(strData);
    };

    var connect = function() {
        wSocket = new WebSocket(wsEndPoint);
        registerSocketEvents();
    };

    var stopPing = function() {
        if (pingTimer !== null) {
            clearInterval(pingTimer);
        }
    };

    var initPing = function() {
        pingTimer = setInterval(function() {
            KA.wsPing({});
        }, 30000);
    };

    var init = function() {
        if (!hasInit) {
            connect();

            hasInit = true;
        }
    };

    return {
        init: init,
        send: send,
        addHandler: addHandler,
        removeHandler: removeHandler,
        stopPing: stopPing,
        initPing: initPing,
    }

}();


