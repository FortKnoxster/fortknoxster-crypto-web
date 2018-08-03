/* global KRYPTOS, converse, locales, Token */

"use strict";
/**
 * KRYPTOS.API handles all API calls made from the FortKnoxster Web App using
 * the FortKnoxster Advanced Communication Protocol Standard with its own
 * bi-directional encryption and authentication layer.
 *
 * @name KRYPTOS.API
 * @copyright Copyright © FortKnoxster Ltd. 2014 - 2018.
 * @license Apache License, Version 2.0 http://www.apache.org/licenses/LICENSE-2.0
 * @author MJ <mj@fortknoxster.com>
 * @version 4.0
 */

/**
 * The KRYPTOS Storage API Module.
 */
KRYPTOS.API = function () {

    let userId = null; //KRYPTOS.session.getItem('id');

    let nodeId = null; //KRYPTOS.session.getItem('nodeID');

    let errorHandler = null;

    let KU = KRYPTOS.utils;

    let keyStore = null;

    let nodePrefix = function (type) {
        return "node:" + type;
    };

    let setUserId = function (id) {
        userId = id;
    };

    let setNodeId = function (id) {
        nodeId = id;
    };

    /**
     * Standard Communication Protocol format.
     *
     * @param {String} type
     * @param {JSON} data
     * @returns {JSON}
     */
    let message = function (type, data) {
        return {
            From: userId + "@" + nodeId,
            To: nodeId,
            ServiceType: type,
            // ServiceData: data ? data: null,
            ServiceData: data,
            Flags: 0,
            Timestamp: new Date().getTime(),
            Sign: null
        };
    };

    /**
     * Standard Encryption Envelope format used in the Standard Communication
     * Protocol.
     *
     * @param {type} algo
     * @param {type} data
     * @returns {JSON}
     */
    let envelope = function (algo, data) {
        return {
            name: algo || null,
            iv: null,
            encryptedKey: null,
            data: JSON.stringify(data) || null
        };
    };

    /**
     * Standard Communication Protocol used for encryption.
     *
     * @param {String} type
     * @param {Object} data
     * @param {function} callback
     * @returns {void}
     */
    let encryptProtocol = function (type, data, callback) {
        let algo = "EC:AES-GCM-256";
        let Encrypter = new KRYPTOS.Encrypter(keyStore, data, null, function (success, message) {
            if (!success) {
                log(message);
                return;
            }
            log(message);
            callback(message);
        });
        let nodePek = JSON.parse(KRYPTOS.session.getItem(nodePrefix('pek')));
        Encrypter.protocol(message(type), envelope(algo), nodePek);
    };

    /**
     * Standard Communication Protocol used for decryption.
     *
     * @param {Object} result
     * @param {function} callback
     * @param {bool} isError
     * @param {bool} verifyOnly
     * @param {bool} debug
     * @returns {void}
     */
    let decryptProtocol = function (result, callback, isError, verifyOnly, debug) {
        if (debug) {
        }
        let data = {};
        if (isError) {
            data = JSON.parse(result.errors.message);
        }
        else {
            data = KU.isObject(result) ? result : JSON.parse(result);
        }
        if (debug) {
        }
        let signature = KU.b642ab(data.Sign, true);
        if (debug) {
        }
        data.Sign = null;
        log(data);
        let nodePvk = JSON.parse(KRYPTOS.session.getItem(nodePrefix('pvk')));
        let nodePek = JSON.parse(KRYPTOS.session.getItem(nodePrefix('pek')));
        log(nodePvk);
        let Decrypter = new KRYPTOS.Decrypter(keyStore, null, null, null, signature, null, null, function (message) {
            // if (message === false) {
            if (isError) {
                //KU.error(errorHandler, "Error", message.message);
                callback(message.message);
            }
            else {
                callback(message);
            }
        });
        Decrypter.protocol(data, nodePvk, nodePek, verifyOnly);
    };

    let testProtocol = function (type) {
        let data = {
            test: "test"
        };
        type = type ? type : "test.action";
        encryptProtocol(type, data, function (message) {
            log('testProtocol message');
            log(message);
        });
    };

    let handleNodeError = function (error, cb) {
        let nodeError = JSON.parse(error.errors.message);
    };

    let getItem = function (itemId, callback) {
        KU.getJson({item_id: itemId}, 'storage/item', function (success, response) {
            if (success === false) {
                KU.error(errorHandler, "Get Error", response);
            }
            else {
                callback(response);
            }
        });
    };

    let getRoot = function (callback) {
        KU.getJson(null, 'storage/init', function (success, response) {
            if (success === false) {
                KU.error(errorHandler, "Get Error", response);
            }
            else {
                callback(response);
            }
        });
    };

    let getShares = function (callback) {
        KU.getJson(null, 'storage/new-shares', function (success, response) {
            if (success === false) {
                KU.error(errorHandler, "Get Error", response);
            }
            else {
                callback(response);
            }
        });
    };

    let getManageShares = function (callback) {
        KU.getJson(null, 'storage/manage-shares', function (success, response) {
            if (success === false) {
                KU.error(errorHandler, "Get Error", response);
            }
            else {
                callback(response);
            }
        });
    };

    let getManageShare = function (itemId, callback) {
        KU.getJson({item_id: itemId}, 'storage/manage-share', function (success, response) {
            if (success === false) {
                KU.error(errorHandler, "Get Error", response);
            }
            else {
                callback(response);
            }
        });
    };

    let acceptShare = function (itemId, callback) {
        KU.getJson({item_id: itemId}, 'storage/accept-share', function (success, response) {
            if (success === false) {
                KU.error(errorHandler, "Get Error", response);
            }
            else {
                callback(response);
            }
        });
    };

    let addItem = function (json, callback) {
        KU.sendJson(json, 'storage/item', function (success, response) {
            if (success === false) {
                KU.error(errorHandler, "Create Error", response);
            }
            else {
                callback(response);
            }
        });
    };

    let addItems = function (json, callback) {
        KU.sendJson(json, 'storage/items', function (success, response) {
            if (success === false) {
                KU.error(errorHandler, "Create Error", response);
            }
            else {
                callback(response);
            }
        });
    };

    let updateItem = function (json, callback) {
        KU.sendJson(json, 'storage/update-item', function (success, response) {
            if (success === false) {
                KU.error(errorHandler, "Update Error", response);
            }
            else {
                callback(response);
            }
        });
    };

    let deleteItem = function (json, callback) {
        KU.sendJson(json, 'storage/delete-item', function (success, response) {
            if (success === false) {
                KU.error(errorHandler, "Delete Error", response);
            }
            else {
                callback(response);
            }
        });
    };

    let moveItem = function (json, callback) {
        KU.sendJson(json, 'storage/move-item', function (success, response) {
            if (success === false) {
                KU.error(errorHandler, "Move Error", response);
            }
            else {
                callback(response);
            }
        });
    };

    let copyItem = function (json, callback) {
        KU.sendJson(json, 'storage/copy-item', function (success, response) {
            if (success === false) {
                KU.error(errorHandler, "Copy Error", response);
            }
            else {
                callback(response);
            }
        });
    };

    let shareItem = function (json, callback) {
        KU.sendJson(json, 'storage/share-item', function (success, response) {
            if (success === false) {
                KU.error(errorHandler, "Share Error", response);
            }
            else {
                callback(response);
            }
        });
    };

    let updateShareItem = function (json, callback) {
        KU.sendJson(json, 'storage/update-share-item', function (success, response) {
            if (success === false) {
                KU.error(errorHandler, "Share Error", response);
            }
            else {
                callback(response);
            }
        });
    };

    let unshareItem = function (json, callback) {

        KU.sendJson(json, 'storage/unshare-item', function (success, response) {
            if (success === false) {
                KU.error(errorHandler, "Share Error", response);
            }
            else {
                callback(response);
            }
        });
    };

    let downloadAttachment = function (messageId, attachmentId, callback, downloadCallback) {
        let url = '/messages/attachment?message_id=' + messageId + '&attachment_id='+attachmentId;
        return downloadFile(url, callback, downloadCallback);
    };

    let downloadFileTransfer = function (fileId, callback, downloadCallback) {
        let url = '/filetransfer/transfer?file_id=' + fileId;
        return downloadFile(url, callback, downloadCallback);
    };

    let downloadItem = function (itemId, partNumber, callback, downloadCallback) {
        let url = '/storage/download-item?item_id=' + itemId + '&part_no=' + partNumber;
        return downloadFile(url, callback, downloadCallback);
    };

    let downloadFile = function (url, callback, downloadCallback) {
        let xhr = new XMLHttpRequest();
        xhr.open('GET', url, true);
        xhr.responseType = 'blob';
        xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
        xhr.setRequestHeader('X-CSRF-Token', Token.getToken());
        xhr.onload = function (e) {
            if (xhr.status === 200) {
                let blob = new Blob([xhr.response], {type: "application/octet-stream"});
                KU.readBlob(blob, function () {
                    let reader = this;
                    let data = reader.result;

                    callback(data);
                });
            }
            else {
                KU.readBlob(xhr.response, function (ab) {
                    KU.error(errorHandler, "Download Error", KU.ab2json(ab.target.result));
                    callback(false, xhr.status === 404 || xhr.status === 403);
                });

            }
        };

        xhr.addEventListener('progress', downloadCallback, false);
        xhr.addEventListener('abort', downloadCallback, false);
        xhr.onerror = function (e) {
            callback(false);
        };
        xhr.send();
        return xhr;
    };

    let createGroupChat = function (json, callback, errorCallback) {
        encryptProtocol('chat.group.create', json, function (message) {
            postJsonProtocol(message, 'chat/group/create', 'Create Error', callback, errorCallback);
        });
    };

    let getGroup = function (json, callback, errorCallback) {
        encryptProtocol('chat.group.get', json, function (message) {
            postJsonProtocol(message, 'chat/group/get', 'Get Error', callback, errorCallback);
        });
    };

    let getGroups = function (json, callback, errorCallback) {
        encryptProtocol('chat.group.getList', json, function (message) {
            postJsonProtocol(message, 'chat/group/all', 'Get Error', callback, errorCallback);
        });
    };

    let deleteGroupChat = function (json, callback, errorCallback) {
        //postJson(json, 'chat', 'group/delete', 'Delete Error', callback, errorCallback);
        encryptProtocol('chat.group.delete', json, function (message) {
            log(message);
            postJsonProtocol(message, 'chat/group/delete', 'Get Error', callback, errorCallback);
        });
    };

    let leaveGroupChat = function (json, callback, errorCallback) {
        //postJson(json, 'chat', 'group/leave', 'Invite Error', callback, errorCallback);
        encryptProtocol('chat.group.leave', json, function (message) {
            log(message);
            postJsonProtocol(message, 'chat/group/leave', 'Get Error', callback, errorCallback);
        });
    };

    let deleteGroupChatMember = function (json, callback, errorCallback) {
        //postJson(json, 'chat', 'group/member/delete', 'Delete Error', callback, errorCallback);
        log('--- deleteGroup API ---');
        encryptProtocol('chat.group.member.delete', json, function (message) {
            log(message);
            postJsonProtocol(message, 'chat/group/member/delete', 'Get Error', callback, errorCallback);
        });
    };

    let addGroupChatMembers = function (json, callback, errorCallback) {
        log('--- addGroupMember API ---');
        encryptProtocol('chat.group.member.add', json, function (message) {
            log(message);
            postJsonProtocol(message, 'chat/group/member/add', 'Get Error', callback, errorCallback);
        });

    };

    let changeGroupChatSubject = function (json, callback, errorCallback) {
        //postJson(json, 'chat', 'group/subject', 'Subject Error', callback, errorCallback);
        log('--- updateSubject API ---');
        encryptProtocol('chat.group.subject', json, function (message) {
            log(message);
            postJsonProtocol(message, 'chat/group/subject', 'Get Error', callback, errorCallback);
        });
    };

    let getRecentChats = function (json, callback, errorCallback) {
        //getJson(json, 'chat', 'recent', 'Get Error', callback, errorCallback);
        log('--- Chat API ---');
        encryptProtocol('chat.recentChats', json, function (message) {
            postJsonProtocol(message, 'chat/recent', 'Get Error', callback, errorCallback);
        });
    };

    let getGroupsSync = function (json, callback, errorCallback) {
        log('--- Group Sync API ---');
        encryptProtocol('chat.group.sync', json, function (message) {
            log(message);
            postJsonProtocol(message, 'chat/group/sync', 'Get Error', callback, errorCallback);
        });
    };

    let uploadGroupPicture = function (data, callback, errorCallback, uploadCallback) {
        KU.sendData(data, 'chat/group/avatar/upload', function (success, response) {
            if (success) {
                callback(response);
            }
            else {
                KU.error(errorHandler, "Upload Error", response);
                errorCallback(response);
            }
        });
    };

    let deleteGroupPicture = function (data, callback, errorCallback, uploadCallback) {
        KU.sendData(data, 'chat', 'group/avatar/delete', function (success, response) {
            if (success) {
                callback(response);
            }
            else {
                KU.error(errorHandler, "Upload Error", response);
                errorCallback(response);
            }
        });
    };

    let offlinePush = function (json, callback, errorCallback) {
        postJson(json, 'call/offline-push', 'Subject Error', callback, errorCallback, true /* Suppress error toastr */);
    };

    let getContacts = function (json, callback, errorCallback) {
        log('--- getContacts API ---');
        encryptProtocol('contacts.list', json, function (message) {
            log(message);
            postJsonProtocol(message, 'contacts/list', 'Get Error', callback, errorCallback);
        });
    };

    let searchContacts = function (json, callback, errorCallback) {
        log('--- searchContacts API ---');
        encryptProtocol('contacts.searchBy', json, function (message) {
            log(message);
            postJsonProtocol(message, 'contacts/search', 'Get Error', callback, errorCallback);
        });
    };

    let declineContact = function (json, callback, errorCallback) {
        encryptProtocol('contacts.decline', json, function (message) {
            postJsonProtocol(message, 'contacts/decline', 'Get Error', callback, errorCallback);
        });
    };

    let deleteContact = function (json, callback, errorCallback) {
        encryptProtocol('contacts.delete', json, function (message) {
            postJsonProtocol(message, 'contacts/delete', 'Get Error', callback, errorCallback);
        });
    };

    let searchUsers = function (json, callback, errorCallback) {
        log('--- searchUsers API ---');
        encryptProtocol('user.search', json, function (message) {
            log(message);
            postJsonProtocol(message, 'admin/users/search', 'Get Error', callback, errorCallback);
        });
    };


    let addContact = function (json, callback, errorCallback) {
        encryptProtocol('contacts.add', json, function (message) {
            log(message);
            postJsonProtocol(message, 'contacts/add', 'Get Error', callback, errorCallback);
        });
    };

    let getContact = function (json, callback, errorCallback) {
        log('--- getContact API ---');
        encryptProtocol('contacts.get', json, function (message) {
            log(message);
            postJsonProtocol(message, 'contacts/get', 'Get Error', callback, errorCallback);
        });
    };

    let inviteUsers = function (json, callback, errorCallback) {
        log('--- inviteNewUser API ---');
        encryptProtocol('user.referNewUsers', json, function (message) {
            postJsonProtocol(message, 'invite', 'Create Error', callback, errorCallback);
        });
    };

    let inviteUserBySMS = function (json, callback, errorCallback) {
        log('--- inviteNewUserBySMS API ---');
        encryptProtocol('user.referNewUserBySMS', json, function (message) {
            postJsonProtocol(message, 'invite', 'Create Error', callback, errorCallback);
        });
    };

    let getInvitedUsers = function (json, callback, errorCallback) {
        encryptProtocol('contacts.inviteList', json, function (message) {
            postJsonProtocol(message, 'contacts/invite-list', 'Get Error', callback, errorCallback);
        });
    };

    let getPendingInvitedUsers = function (json, callback, errorCallback) {
        encryptProtocol('contacts.pendingInviteList', json, function (message) {
            postJsonProtocol(message, 'contacts/pending-invite-list', 'Get Error', callback, errorCallback);
        });
    };

    let getContactByEmail = function (json, callback, errorCallback) {
        log('--- getContactByEmail API ---');
        encryptProtocol('contacts.getByEmail', json, function (message) {
            postJsonProtocol(message, 'contacts/get-by-email', 'Get Error', callback, errorCallback);
        });
    };

    let getContactByUsername = function (json, callback, errorCallback) {
        log('--- getContactByUsername API ---');
        encryptProtocol('contacts.getByUsername', json, function (message) {
            postJsonProtocol(message, 'contacts/get-by-username', 'Get Error', callback, errorCallback);
        });
    };

    let getContactByPhone = function (json, callback, errorCallback) {
        log('--- getContactByPhone API ---');
        encryptProtocol('contacts.getByPhone', json, function (message) {
            postJsonProtocol(message, 'contacts/get-by-phone', 'Get Error', callback, errorCallback);
        });
    };

    let getContactByReferral = function (json, callback, errorCallback) {
        log('--- getContactByReferral API ---');
        encryptProtocol('contacts.getByReferral', json, function (message) {
            postJsonProtocol(message, 'contacts/get-by-referral', 'Get Error', callback, errorCallback);
        });
    };

    let getContactSync = function (json, callback, errorCallback) {
        log('--- getContactSync API ---');
        encryptProtocol('contacts.sync', json, function (message) {
            postJsonProtocol(message, 'contacts/sync', 'Get Error', callback, errorCallback);
        });
    };

    let blockContact = function (json, callback, errorCallback) {
        encryptProtocol('contacts.block', json, function (message) {
            postJsonProtocol(message, 'contacts/block', 'Get Error', callback, errorCallback);
        });
    };

    let unblockContact = function (json, callback, errorCallback) {
        encryptProtocol('contacts.unblock', json, function (message) {
            postJsonProtocol(message, 'contacts/unblock', 'Get Error', callback, errorCallback);
        });
    };

    let getUsersPublicKeys = function (json, callback, errorCallback) {
        encryptProtocol('user.getkeys', json, function (message) {
            postJsonProtocol(message, 'users/getkeys', 'Get Error', callback, errorCallback);
        });
    };

    let getPublicKeys = function (json, callback, errorCallback) {
        getJson(json, 'keys/public', 'Get Error', callback, errorCallback);
    };

    let errorReport = function (json, callback, errorCallback) {
        postJson(json, 'errors/report', 'Subject Error', callback, errorCallback);
    };

    let adminSetup = function (json, callback, errorCallback) {
        let jsonData = message('node.postSetup', envelope(null, json));
        KU.sendJson(jsonData, 'admin/setup', function (success, response) {
            if (success === false) {
                KU.error(errorHandler, "Setup Error", response);
                errorCallback(response);
            }
            else {
                callback(response);
            }
        });
    };

    let unlockServer = function (json, callback, errorCallback) {
        let jsonData = message('node.postUnlock', envelope(null, json));
        KU.sendJson(jsonData, 'admin/unlock', function (success, response) {
            if (success === false) {
                errorCallback(response);
            }
            else {
                callback(response);
            }
        });
    };

    let setup = function (json, callback, errorCallback) {
        let jsonData = message('user.setOneTimeUpdateKeys', envelope(null, json));
        log(jsonData);
        KU.sendJson(jsonData, 'account/setup', function (success, response) {
            if (success === false) {
                errorCallback(response);
            }
            else {
                callback(response);
            }
        });
    };

    let request = function (data, callback, errorCallback) {
        KU.sendJson(data, 'account/request', function (success, response) {
            if (success) {
                callback(response);
            }
            else {
                //TODO: PHP and Node errors possible, need to fix after common error handlig has been done!
                errorCallback(response);
                //decryptProtocol(response, errorCallback, true, true, true);
                //KU.error(errorCallback, "Signup Error", response);
            }
        });
    };

    let register = function (data, callback, errorCallback) {
        KU.sendJson(data, 'account/register', function (success, response) {
            if (success) {
                callback(response);
            }
            else {
                KU.error(errorCallback, "Signup Error", response);
            }
        });
    };

    let authenticate = function (data, callback, errorCallback) {
        KU.sendData(data, 'authenticate', function (success, response) {
            if (success) {
                callback(response);
            }
            else {
                errorCallback(response);
            }
        });
    };

    let uploadProfilePicture = function (data, callback, errorCallback, uploadCallback) {
        let jqXHR = KU.sendData(data, 'avatar/upload', function (success, response) {
            if (success) {
                callback(response);
            }
            else {
                KU.error(errorHandler, "Upload Error", response);
                errorCallback(response);
            }
        });
    };

    let uploadAttachment = function (data, callback, errorCallback, uploadCallback) {
        return uploadFile(data, "messages/attachment", callback, errorCallback, uploadCallback);
    };

    let uploadChatAttachment = function (data, callback, errorCallback, uploadCallback) {
        if (data.file_transfer === null) {
            return callback(null);
        }
        return uploadFile(data, "filetransfer/upload", callback, errorCallback, uploadCallback);
    };

    let deleteProfilePicture = function (json, callback, errorCallback) {
        postJson(json, 'avatar/delete', 'Delete Error', callback, errorCallback);
    };

    //Posible Deprecated
    let addUser = function (json, callback, errorCallback) {
//        log('add user!!!!');
        encryptProtocol('user.create', json, function (message) {
            postJsonProtocol(message, 'admin/users/add', 'Create Error', callback, errorCallback);
        });
    };

    let updateUser = function (json, callback, errorCallback) {
        encryptProtocol('user.update', json, function (message) {
            postJsonProtocol(message, 'admin/users/update', 'Update Error', callback, errorCallback);
        });
    };

    let getUsers = function (json, callback, errorCallback) {
        encryptProtocol('user.list', json, function (message) {
            postJsonProtocol(message, 'admin/users', 'Create Error', callback, errorCallback);
        });
    };

    let getAdminActivity = function (json, callback, errorCallback) {
        encryptProtocol('eventlog.listAll', json, function (message) {
            postJsonProtocol(message, 'admin/activity', 'List Error', callback, errorCallback);
        });
    };

    let getAdminFilteredActivity = function (json, callback, errorCallback) {
        encryptProtocol('eventlog.filterList', json, function (message) {
            postJsonProtocol(message, 'admin/activity', 'List Error', callback, errorCallback);
        });
    };

    let getAdminActivityStats = function (json, callback, errorCallback) {
        encryptProtocol('eventlog.basicStats', json, function (message) {
            postJsonProtocol(message, 'admin/activityBasicStats', 'List Error', callback, errorCallback);
        });
    };


    let disableUser = function (json, callback, errorCallback) {
        encryptProtocol('user.disable', json, function (message) {
            postJsonProtocol(message, 'admin/users/disable', 'Error', callback, errorCallback);
        });

    };

    let enableUser = function (json, callback, errorCallback) {
        encryptProtocol('user.enable', json, function (message) {
            postJsonProtocol(message, 'admin/users/enable', 'Error', callback, errorCallback);
        });

    };

    let changeUserRole = function (json, callback, errorCallback) {
        encryptProtocol('user.enable', json, function (message) {
            postJsonProtocol(message, 'admin/users/role', 'Error', callback, errorCallback);
        });

    };

    let changePassword = function (json, callback, errorCallback) {
        log('changePassword API call');
        encryptProtocol('user.changePassword', json, function (message) {
            postJsonProtocol(message, 'account/password', 'Error', callback, errorCallback);
        });

    };

    let device = function (json, callback, errorCallback) {
        log('device API call');
        encryptProtocol('account.device', json, function (message) {
            postJsonProtocol(message, 'account/device', 'Error', callback, errorCallback);
        });

    };

    let updateGeneralSettings = function (json, callback, errorCallback) {
        log('changePassword API call');
        encryptProtocol('settings.setgeneral', json, function (message) {
            postJsonProtocol(message, 'account/settings', 'Error', callback, errorCallback);
        });

    };

    let setupTfa = function(json, callback, errorCallback) {
         let password = json.pwd;
        KRYPTOS.deriveAccountPassword(KRYPTOS.session.getItem('username'),password,KRYPTOS.session.getItem('domain'), function (accountPassword) {
                    json.pwd = accountPassword;
         encryptProtocol('account.setupTfa', json, function(message) {
            postJsonProtocol(message, 'account/setup-tfa', 'Two-factor Error', callback, errorCallback);
        }); });
    };

    let disableTfa = function(json, callback, errorCallback) {
        let password = json.pwd;
        KRYPTOS.deriveAccountPassword(KRYPTOS.session.getItem('username'), password, KRYPTOS.session.getItem('domain'), function (accountPassword) {
            json.pwd = accountPassword;
            encryptProtocol('account.disableTfa', json, function (message) {
                postJsonProtocol(message, 'account/disable-tfa', 'Two-factor Error', callback, errorCallback);
            });
        });
    };

    let activateTfa = function (json, callback, errorCallback) {
        encryptProtocol('account.activateTfa', json, function (message) {
            postJsonProtocol(message, 'account/activate-tfa', 'Two-factor Error', callback, errorCallback);
        });
    };

  //    let showQr = function (json, callback, errorCallback) {
  //        encryptProtocol('account.showQr', json, function (message) {
  //            postJsonProtocol(message, 'account/show-qr', 'Two-factor Error', callback, errorCallback);
  //        });
  //    };

    let saveEmailSignature = function (json, callback, errorCallback) {
        encryptProtocol('settings.setEmailSignature', json, function (message) {
            postJsonProtocol(message, 'users/signature', 'Email Signature Error', callback, errorCallback);
        });
    };

    let getEmailSignature = function (json, callback, errorCallback) {
        encryptProtocol('settings.getEmailSignature', json, function (message) {
            postJsonProtocol(message, 'users/signature', 'Email Signature Error', callback, errorCallback);
        });
    };

    let enableEmail = function (json, callback, errorCallback) {
        encryptProtocol('account.enableEmail', json, function (message) {
            postJsonProtocol(message, 'account/enable-email', 'Two-factor Error', callback, errorCallback);
        });
    };

    let disableEmail = function (json, callback, errorCallback) {
        encryptProtocol('account.disableEmail', json, function (message) {
            postJsonProtocol(message, 'account/disable-email', 'Two-factor Error', callback, errorCallback);
        });
    };

    let wsPing = function (json, callback, errorCallback) {
        encryptProtocol('ws.ping', json, function (message) {
            sendWebsocket(message);
        });
    };

    let wsRegister = function (json, callback, errorCallback) {
        encryptProtocol('ws.register', json, function (message) {
            sendWebsocket(message);
        });
    };

    let wsReceiveData = function (data, callback) {
        decryptProtocol(data, callback);
    };

    let makeGroupCall = function (json, callback, errorCallback) {
        encryptProtocol('groupcall.make', json, function (message) {
            sendWebsocket(message);
        });
    };

    let checkGroupCalls = function (json, callback, errorCallback) {
        encryptProtocol('groupcall.check', json, function (message) {
            sendWebsocket(message);
        });
    };

    let declineGroupCall = function (json, callback, errorCallback) {
        encryptProtocol('groupcall.decline', json, function (message) {
            sendWebsocket(message);
        });
    };

    let joinGroupCall = function (json, callback, errorCallback) {
        encryptProtocol('groupcall.join', json, function (message) {
            sendWebsocket(message);
        });
    };

    let leaveGroupCall = function (json, callback, errorCallback) {
        encryptProtocol('groupcall.leave', json, function (message) {
            sendWebsocket(message);
        });
    };

    let requestPhoneChange = function(json, callback, errorCallback) {
        let password = json.pwd;
        KRYPTOS.deriveAccountPassword(KRYPTOS.session.getItem('username'), password, KRYPTOS.session.getItem('domain'), function (accountPassword) {
            json.pwd = accountPassword;
            encryptProtocol('account.requestPhoneChange', json, function (message) {
                postJsonProtocol(message, 'account/change-phone-request', 'Get Error', callback, errorCallback);
            });
        });
    };

    let confirmPhoneChange = function(json, callback, errorCallback) {
        encryptProtocol('account.confirmPhoneChange', json, function(message) {
            postJsonProtocol(message, 'account/change-phone-confirm', 'Get Error', callback, errorCallback);
        });
    };

    let requestEmailChange = function(json, callback, errorCallback) {
        let password = json.pwd;
        KRYPTOS.deriveAccountPassword(KRYPTOS.session.getItem('username'), password, KRYPTOS.session.getItem('domain'), function (accountPassword) {
            json.pwd = accountPassword;
            encryptProtocol('account.requestEmailChange', json, function (message) {
                postJsonProtocol(message, 'account/email-request', 'Get Error', callback, errorCallback);
            });
        });
    };

    let confirmEmailChange = function (json, callback, errorCallback) {
        encryptProtocol('account.confirmEmailChange', json, function (message) {
            postJsonProtocol(message, 'account/email-confirm', 'Get Error', callback, errorCallback);
        });
    };

    let removeEmail = function (json, callback, errorCallback) {
        encryptProtocol('account.removeEmail', json, function (message) {
            postJsonProtocol(message, 'account/remove-email', 'Get Error', callback, errorCallback);
        });
    };
    let getJson = function (json, resource, method, errorTitle, callback, errorCallback) {
        KU.getJson(json, resource, method, function (success, response) {
            if (success === false) {
                if (errorCallback) {
                    errorCallback(response);
                }
                else {
                    KU.error(errorHandler, errorTitle, response);
                }
            }
            else {
                callback(response);
            }
        });
    };

    let postJson = function (json, resource, errorTitle, callback, errorCallback, suppressError) {
        KU.sendJson(json, resource, function (success, response) {
            if (success === false) {
                if (!suppressError) {
                    KU.error(errorHandler, errorTitle, response);
                }
                if (errorCallback) {
                    errorCallback(response, true);
                }
            }
            else {
                callback(response);
            }
        });
    };

    let postJsonProtocol = function (json, resource, errorTitle, callback, errorCallback) {
        KU.sendJson(json, resource, function (success, response) {
            if (success === false) {
//                KU.error(errorHandler, errorTitle, response);
                decryptProtocol(response, errorCallback, true, false, true);
            }
            else {
                decryptProtocol(response, callback, false, false, false);
            }
        });
    };

    let sendData = function (data, resource, callback, errorCallback, uploadCallback) {
        return KU.sendData(data, resource, function (success, response) {
            if (success) {
                callback(response);
            }
            else {
                KU.error(errorCallback, "Upload Error", response);
                //errorCallback(response);
            }
        }, uploadCallback);
    };

    let uploadFile = function (data, resource, callback, errorCallback, uploadCallback) {
        return sendData(data, resource, callback, errorCallback, uploadCallback);
    };

    let sendWebsocket = function (message) {
        KRYPTOS.WS.send(JSON.stringify(message));
    };

    let setKeyStore = function (serviceKeyStore) {
        keyStore = serviceKeyStore;
    };

    let log = function (msg) {
        return false;
    };

    let protocol = function (json, callback, errorCallback) {
        log('--- getNote ---');
        encryptProtocol('notes.get', json, function (message) {
            postJsonProtocol(message, 'notes/get', 'Protocol Error', callback, errorCallback);
        });
    };

    let addCallLog = function (json, callback, errorCallback) {
        log('--- addCallLog ---');
        encryptProtocol('call.add', json, function (message) {
            postJsonProtocol(message, 'call/log/add', 'CallLog Error', callback, errorCallback);
        });
    };

    let deleteCallLog = function (json, callback, errorCallback) {
        log('--- deleteCallLog ---');
        encryptProtocol('call.delete', json, function (message) {
            postJsonProtocol(message, 'call/log/delete', 'CallLog Error', callback, errorCallback);
        });
    };

    let deleteAllCallLog = function (json, callback, errorCallback) {
        log('--- deleteAllCallLog ---');
        encryptProtocol('call.deleteall', json, function (message) {
            postJsonProtocol(message, 'call/log/delete-all', 'CallLog Error', callback, errorCallback);
        });
    };

    let listCallLog = function (json, callback, errorCallback) {
        log('--- listCallLog ---');
        encryptProtocol('call.list', json, function (message) {
            postJsonProtocol(message, 'call/log/list', 'CallLog Error', callback, errorCallback);
        });
    };

    let getSyncCallLog = function (json, callback, errorCallback) {
        log('--- getSyncCallLog ---');
        encryptProtocol('call.sync', json, function (message) {
            postJsonProtocol(message, 'call/log/sync', 'CallLog Error', callback, errorCallback);
        });
    };

    let getInbox = function (json, callback, errorHandler) {
        loadInbox(json, 'inbox', callback, errorHandler);
    };

    let getSent = function (json, callback, errorHandler) {
        loadInbox(json, 'sent', callback, errorHandler);
    };

    let getDrafts = function (json, callback, errorHandler) {
        loadInbox(json, 'drafts', callback, errorHandler);
    };

    let getStarred = function (json, callback, errorHandler) {
        loadInbox(json, 'starred', callback, errorHandler);
    };

    let getTrashed = function (json, callback, errorHandler) {
        loadInbox(json, 'trash', callback, errorHandler);
    };

    let sendMail = function (data, callback, errorHandler) {
        return sendData(data, 'messages/message', callback, errorHandler);
    };

    let draftMail = function (data, callback, errorHandler) {
        return sendData(data, 'messages/draft', callback, errorHandler);
    };

    let loadInbox = function (json, mailbox, callback, errorHandler) {
        KU.getJson(json, 'mail/' + mailbox, function (success, response) {
            if (success === false) {
                KU.error(errorHandler, "Get Error", response);
            }
            else {
                callback(response);
            }
        });
    };

    let readMail = function (json, callback, errorCallback) {
        postJson(json, 'mail/read', 'Error', callback, errorCallback);
    };

    let unreadMail = function (json, callback, errorCallback) {
        postJson(json, 'mail/unread', 'Error', callback, errorCallback);
    };

    let starMail = function (json, callback, errorCallback) {
        postJson(json, 'mail/star', 'Error', callback, errorCallback);
    };

    let unstarMail = function (json, callback, errorCallback) {
        postJson(json, 'mail/unstar', 'Error', callback, errorCallback);
    };

    let trashMail = function (json, callback, errorCallback) {
        postJson(json, 'mail/trash', 'Error', callback, errorCallback);
    };

    let restoreMail = function (json, callback, errorCallback) {
        postJson(json, 'mail/restore', 'Error', callback, errorCallback);
    };

    let deleteMail = function (json, callback, errorCallback) {
        postJson(json, 'mail/delete', 'Error', callback, errorCallback);
    };

    let checkMail = function (callback,errorHandler) {
        KU.getJson(null, 'messages/check?active', function (success, response) {
            if (success === false) {
                KU.error(errorHandler, "Get Error", response);
            }
            else {
                callback(response);
            }
        });
    };

    let searchMail = function (json, callback, errorHandler) {
        KU.getJson(null, 'mail/' + json.type + json.params, function (success, response) {
            if (success === false) {
                KU.error(errorHandler, "Get Error", response);
            }
            else {
                callback(response);
            }
        });
    };

    return {
        setErrorHandler: function () {
            errorHandler = function (error) {
            };
        },

        setKeyStore: setKeyStore,
        setUserId: setUserId,
        setNodeId: setNodeId,
        nodePrefix: nodePrefix,

        postJson: postJson,
        getJson: getJson,

        // Error report
        errorReport: errorReport,

        // Keys
        getPublicKeys: getPublicKeys,
        getUsersPublicKeys: getUsersPublicKeys,

        //Account
        requestPhoneChange: requestPhoneChange,
        confirmPhoneChange: confirmPhoneChange,
        requestEmailChange: requestEmailChange,
        confirmEmailChange: confirmEmailChange,
        removeEmail: removeEmail,
        device: device,

//        // Notes
//        addNote: addNote,
//        updateNote: updateNote,
//        getNote: getNote,
//        deleteNote: deleteNote,
//        getNotes: getNotes,
//
//        // Calendar Events
//        addEvent: addEvent,
//        updateEvent: updateEvent,
//        getEvent: getEvent,
//        deleteEvent: deleteEvent,
//        getEvents: getEvents,


        /* Setup & Login */
        request: request,
        register: register,
        setup: setup,
        adminSetup: adminSetup,
        unlockServer: unlockServer,
        authenticate: authenticate,
        changePassword: changePassword,
        updateGeneralSettings: updateGeneralSettings,
        setupTfa: setupTfa,
        disableTfa: disableTfa,
        activateTfa: activateTfa,
      // showQr: showQr,
        saveEmailSignature: saveEmailSignature,
        getEmailSignature: getEmailSignature,
        enableEmail: enableEmail,
        disableEmail: disableEmail,

        /* Avatar */
        uploadProfilePicture: uploadProfilePicture,
        deleteProfilePicture: deleteProfilePicture,

        /* Admin */
        addUser: addUser,
        inviteUsers: inviteUsers,
        inviteUserBySMS: inviteUserBySMS,

        /* Only Admin */
        getUsers: getUsers,
        updateUser: updateUser,
        disableUser: disableUser,
        enableUser: enableUser,
        changeUserRole: changeUserRole,
        getAdminActivityStats: getAdminActivityStats,
        getAdminActivity: getAdminActivity,
        getAdminFilteredActivity: getAdminFilteredActivity,

        /* Storage */
        getRoot: getRoot,
        getShares: getShares,
        getManageShares: getManageShares,
        getManageShare: getManageShare,
        unshareItem: unshareItem,
        acceptShare: acceptShare,
        getItem: getItem,
        addItem: addItem,
        addItems: addItems,
        updateItem: updateItem,
        deleteItem: deleteItem,
        moveItem: moveItem,
        copyItem: copyItem,
        shareItem: shareItem,
        updateShareItem: updateShareItem,
        downloadItem: downloadItem,

        downloadFileTransfer: downloadFileTransfer,

        /* Chat */
        createGroupChat: createGroupChat,
        getGroupChat: getGroup,
        getGroupChats: getGroups,
        deleteGroupChat: deleteGroupChat,
        leaveGroupChat: leaveGroupChat,
        addGroupChatMembers: addGroupChatMembers,
        deleteGroupChatMember: deleteGroupChatMember,
        changeGroupChatSubject: changeGroupChatSubject,
        getRecentChats: getRecentChats,
        uploadGroupPicture: uploadGroupPicture,
        deleteGroupPicture: deleteGroupPicture,
        getGroupsSync: getGroupsSync,
        /* Call */
        offlinePush: offlinePush,

        uploadChatAttachment: uploadChatAttachment,

        downloadFile: downloadFile,

        /* Contacts */
        getContacts: getContacts,
        getContact: getContact,
        getContactByEmail: getContactByEmail,
        getContactByUsername: getContactByUsername,
        getContactByPhone: getContactByPhone,
        getContactByReferral: getContactByReferral,
        searchContacts: searchContacts,
        searchUsers: searchUsers,
        addContact: addContact,
        declineContact: declineContact,
        delectContact: deleteContact,
        getInvitedUsers: getInvitedUsers,
        getPendingInvitedUsers: getPendingInvitedUsers,
        getContactSync: getContactSync,
        blockContact: blockContact,
        unblockContact: unblockContact,

        /* WebSocket */
        wsRegister: wsRegister,
        wsPing: wsPing,
        wsReceiveData: wsReceiveData,

        /* Group Call (ws) */
        makeGroupCall: makeGroupCall,
        checkGroupCalls: checkGroupCalls,
        declineGroupCall: declineGroupCall,
        joinGroupCall: joinGroupCall,
        leaveGroupCall: leaveGroupCall,

        testProtocol: testProtocol,
        protocol: protocol,

        /** Call Log **/
        addCallLog: addCallLog,
        deleteAllCallLog: deleteAllCallLog,
        deleteCallLog: deleteCallLog,

        listCallLog: listCallLog,

        getSyncCallLog: getSyncCallLog,

        /** Mail **/
        getInbox: getInbox,
        getSent: getSent,
        getDrafts: getDrafts,
        getStarred: getStarred,
        getTrashed: getTrashed,
        readMail: readMail,
        unreadMail: unreadMail,
        starMail: starMail,
        unstarMail: unstarMail,
        trashMail: trashMail,
        restoreMail: restoreMail,
        deleteMail: deleteMail,
        downloadAttachment: downloadAttachment,
        uploadAttachment: uploadAttachment,
        sendMail: sendMail,
        draftMail: draftMail,
        checkMail: checkMail,
        searchMail: searchMail

    };

}();
