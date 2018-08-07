/* global KRYPTOS, converse, locales, Token */

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
KRYPTOS.API = (function() {
  let userId = null // KRYPTOS.session.getItem('id');

  let nodeId = null // KRYPTOS.session.getItem('nodeID');

  let errorHandler = null

  const KU = KRYPTOS.utils

  let keyStore = null

  const nodePrefix = function(type) {
    return `node:${type}`
  }

  const setUserId = function(id) {
    userId = id
  }

  const setNodeId = function(id) {
    nodeId = id
  }

  /**
   * Standard Communication Protocol format.
   *
   * @param {String} type
   * @param {JSON} data
   * @returns {JSON}
   */
  const message = function(type, data) {
    return {
      From: `${userId}@${nodeId}`,
      To: nodeId,
      ServiceType: type,
      // ServiceData: data ? data: null,
      ServiceData: data,
      Flags: 0,
      Timestamp: new Date().getTime(),
      Sign: null,
    }
  }

  /**
   * Standard Encryption Envelope format used in the Standard Communication
   * Protocol.
   *
   * @param {type} algo
   * @param {type} data
   * @returns {JSON}
   */
  const envelope = function(algo, data) {
    return {
      name: algo || null,
      iv: null,
      encryptedKey: null,
      data: JSON.stringify(data) || null,
    }
  }

  /**
   * Standard Communication Protocol used for encryption.
   *
   * @param {String} type
   * @param {Object} data
   * @param {function} callback
   * @returns {void}
   */
  const encryptProtocol = function(type, data, callback) {
    const algo = 'EC:AES-GCM-256'
    const Encrypter = new KRYPTOS.Encrypter(
      keyStore,
      data,
      null,
      (success, message) => {
        if (!success) {
          log(message)
          return
        }
        log(message)
        callback(message)
      },
    )
    const nodePek = JSON.parse(KRYPTOS.session.getItem(nodePrefix('pek')))
    Encrypter.protocol(message(type), envelope(algo), nodePek)
  }

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
  const decryptProtocol = function(
    result,
    callback,
    isError,
    verifyOnly,
    debug,
  ) {
    if (debug) {
    }
    let data = {}
    if (isError) {
      data = JSON.parse(result.errors.message)
    } else {
      data = KU.isObject(result) ? result : JSON.parse(result)
    }
    if (debug) {
    }
    const signature = KU.b642ab(data.Sign, true)
    if (debug) {
    }
    data.Sign = null
    log(data)
    const nodePvk = JSON.parse(KRYPTOS.session.getItem(nodePrefix('pvk')))
    const nodePek = JSON.parse(KRYPTOS.session.getItem(nodePrefix('pek')))
    log(nodePvk)
    const Decrypter = new KRYPTOS.Decrypter(
      keyStore,
      null,
      null,
      null,
      signature,
      null,
      null,
      message => {
        // if (message === false) {
        if (isError) {
          // KU.error(errorHandler, "Error", message.message);
          callback(message.message)
        } else {
          callback(message)
        }
      },
    )
    Decrypter.protocol(data, nodePvk, nodePek, verifyOnly)
  }

  const testProtocol = function(type) {
    const data = {
      test: 'test',
    }
    type = type || 'test.action'
    encryptProtocol(type, data, message => {
      log('testProtocol message')
      log(message)
    })
  }

  const handleNodeError = function(error, cb) {
    const nodeError = JSON.parse(error.errors.message)
  }

  const getItem = function(itemId, callback) {
    KU.getJson({ item_id: itemId }, 'storage/item', (success, response) => {
      if (success === false) {
        KU.error(errorHandler, 'Get Error', response)
      } else {
        callback(response)
      }
    })
  }

  const getRoot = function(callback) {
    KU.getJson(null, 'storage/init', (success, response) => {
      if (success === false) {
        KU.error(errorHandler, 'Get Error', response)
      } else {
        callback(response)
      }
    })
  }

  const getShares = function(callback) {
    KU.getJson(null, 'storage/new-shares', (success, response) => {
      if (success === false) {
        KU.error(errorHandler, 'Get Error', response)
      } else {
        callback(response)
      }
    })
  }

  const getManageShares = function(callback) {
    KU.getJson(null, 'storage/manage-shares', (success, response) => {
      if (success === false) {
        KU.error(errorHandler, 'Get Error', response)
      } else {
        callback(response)
      }
    })
  }

  const getManageShare = function(itemId, callback) {
    KU.getJson(
      { item_id: itemId },
      'storage/manage-share',
      (success, response) => {
        if (success === false) {
          KU.error(errorHandler, 'Get Error', response)
        } else {
          callback(response)
        }
      },
    )
  }

  const acceptShare = function(itemId, callback) {
    KU.getJson(
      { item_id: itemId },
      'storage/accept-share',
      (success, response) => {
        if (success === false) {
          KU.error(errorHandler, 'Get Error', response)
        } else {
          callback(response)
        }
      },
    )
  }

  const addItem = function(json, callback) {
    KU.sendJson(json, 'storage/item', (success, response) => {
      if (success === false) {
        KU.error(errorHandler, 'Create Error', response)
      } else {
        callback(response)
      }
    })
  }

  const addItems = function(json, callback) {
    KU.sendJson(json, 'storage/items', (success, response) => {
      if (success === false) {
        KU.error(errorHandler, 'Create Error', response)
      } else {
        callback(response)
      }
    })
  }

  const updateItem = function(json, callback) {
    KU.sendJson(json, 'storage/update-item', (success, response) => {
      if (success === false) {
        KU.error(errorHandler, 'Update Error', response)
      } else {
        callback(response)
      }
    })
  }

  const deleteItem = function(json, callback) {
    KU.sendJson(json, 'storage/delete-item', (success, response) => {
      if (success === false) {
        KU.error(errorHandler, 'Delete Error', response)
      } else {
        callback(response)
      }
    })
  }

  const moveItem = function(json, callback) {
    KU.sendJson(json, 'storage/move-item', (success, response) => {
      if (success === false) {
        KU.error(errorHandler, 'Move Error', response)
      } else {
        callback(response)
      }
    })
  }

  const copyItem = function(json, callback) {
    KU.sendJson(json, 'storage/copy-item', (success, response) => {
      if (success === false) {
        KU.error(errorHandler, 'Copy Error', response)
      } else {
        callback(response)
      }
    })
  }

  const shareItem = function(json, callback) {
    KU.sendJson(json, 'storage/share-item', (success, response) => {
      if (success === false) {
        KU.error(errorHandler, 'Share Error', response)
      } else {
        callback(response)
      }
    })
  }

  const updateShareItem = function(json, callback) {
    KU.sendJson(json, 'storage/update-share-item', (success, response) => {
      if (success === false) {
        KU.error(errorHandler, 'Share Error', response)
      } else {
        callback(response)
      }
    })
  }

  const unshareItem = function(json, callback) {
    KU.sendJson(json, 'storage/unshare-item', (success, response) => {
      if (success === false) {
        KU.error(errorHandler, 'Share Error', response)
      } else {
        callback(response)
      }
    })
  }

  const downloadAttachment = function(
    messageId,
    attachmentId,
    callback,
    downloadCallback,
  ) {
    const url = `/messages/attachment?message_id=${messageId}&attachment_id=${attachmentId}`
    return downloadFile(url, callback, downloadCallback)
  }

  const downloadFileTransfer = function(fileId, callback, downloadCallback) {
    const url = `/filetransfer/transfer?file_id=${fileId}`
    return downloadFile(url, callback, downloadCallback)
  }

  const downloadItem = function(
    itemId,
    partNumber,
    callback,
    downloadCallback,
  ) {
    const url = `/storage/download-item?item_id=${itemId}&part_no=${partNumber}`
    return downloadFile(url, callback, downloadCallback)
  }

  let downloadFile = function(url, callback, downloadCallback) {
    const xhr = new XMLHttpRequest()
    xhr.open('GET', url, true)
    xhr.responseType = 'blob'
    xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest')
    xhr.setRequestHeader('X-CSRF-Token', Token.getToken())
    xhr.onload = function(e) {
      if (xhr.status === 200) {
        const blob = new Blob([xhr.response], {
          type: 'application/octet-stream',
        })
        KU.readBlob(blob, function() {
          const reader = this
          const data = reader.result

          callback(data)
        })
      } else {
        KU.readBlob(xhr.response, ab => {
          KU.error(errorHandler, 'Download Error', KU.ab2json(ab.target.result))
          callback(false, xhr.status === 404 || xhr.status === 403)
        })
      }
    }

    xhr.addEventListener('progress', downloadCallback, false)
    xhr.addEventListener('abort', downloadCallback, false)
    xhr.onerror = function(e) {
      callback(false)
    }
    xhr.send()
    return xhr
  }

  const createGroupChat = function(json, callback, errorCallback) {
    encryptProtocol('chat.group.create', json, message => {
      postJsonProtocol(
        message,
        'chat/group/create',
        'Create Error',
        callback,
        errorCallback,
      )
    })
  }

  const getGroup = function(json, callback, errorCallback) {
    encryptProtocol('chat.group.get', json, message => {
      postJsonProtocol(
        message,
        'chat/group/get',
        'Get Error',
        callback,
        errorCallback,
      )
    })
  }

  const getGroups = function(json, callback, errorCallback) {
    encryptProtocol('chat.group.getList', json, message => {
      postJsonProtocol(
        message,
        'chat/group/all',
        'Get Error',
        callback,
        errorCallback,
      )
    })
  }

  const deleteGroupChat = function(json, callback, errorCallback) {
    // postJson(json, 'chat', 'group/delete', 'Delete Error', callback, errorCallback);
    encryptProtocol('chat.group.delete', json, message => {
      log(message)
      postJsonProtocol(
        message,
        'chat/group/delete',
        'Get Error',
        callback,
        errorCallback,
      )
    })
  }

  const leaveGroupChat = function(json, callback, errorCallback) {
    // postJson(json, 'chat', 'group/leave', 'Invite Error', callback, errorCallback);
    encryptProtocol('chat.group.leave', json, message => {
      log(message)
      postJsonProtocol(
        message,
        'chat/group/leave',
        'Get Error',
        callback,
        errorCallback,
      )
    })
  }

  const deleteGroupChatMember = function(json, callback, errorCallback) {
    // postJson(json, 'chat', 'group/member/delete', 'Delete Error', callback, errorCallback);
    log('--- deleteGroup API ---')
    encryptProtocol('chat.group.member.delete', json, message => {
      log(message)
      postJsonProtocol(
        message,
        'chat/group/member/delete',
        'Get Error',
        callback,
        errorCallback,
      )
    })
  }

  const addGroupChatMembers = function(json, callback, errorCallback) {
    log('--- addGroupMember API ---')
    encryptProtocol('chat.group.member.add', json, message => {
      log(message)
      postJsonProtocol(
        message,
        'chat/group/member/add',
        'Get Error',
        callback,
        errorCallback,
      )
    })
  }

  const changeGroupChatSubject = function(json, callback, errorCallback) {
    // postJson(json, 'chat', 'group/subject', 'Subject Error', callback, errorCallback);
    log('--- updateSubject API ---')
    encryptProtocol('chat.group.subject', json, message => {
      log(message)
      postJsonProtocol(
        message,
        'chat/group/subject',
        'Get Error',
        callback,
        errorCallback,
      )
    })
  }

  const getRecentChats = function(json, callback, errorCallback) {
    // getJson(json, 'chat', 'recent', 'Get Error', callback, errorCallback);
    log('--- Chat API ---')
    encryptProtocol('chat.recentChats', json, message => {
      postJsonProtocol(
        message,
        'chat/recent',
        'Get Error',
        callback,
        errorCallback,
      )
    })
  }

  const getGroupsSync = function(json, callback, errorCallback) {
    log('--- Group Sync API ---')
    encryptProtocol('chat.group.sync', json, message => {
      log(message)
      postJsonProtocol(
        message,
        'chat/group/sync',
        'Get Error',
        callback,
        errorCallback,
      )
    })
  }

  const uploadGroupPicture = function(
    data,
    callback,
    errorCallback,
    uploadCallback,
  ) {
    KU.sendData(data, 'chat/group/avatar/upload', (success, response) => {
      if (success) {
        callback(response)
      } else {
        KU.error(errorHandler, 'Upload Error', response)
        errorCallback(response)
      }
    })
  }

  const deleteGroupPicture = function(
    data,
    callback,
    errorCallback,
    uploadCallback,
  ) {
    KU.sendData(data, 'chat', 'group/avatar/delete', (success, response) => {
      if (success) {
        callback(response)
      } else {
        KU.error(errorHandler, 'Upload Error', response)
        errorCallback(response)
      }
    })
  }

  const offlinePush = function(json, callback, errorCallback) {
    postJson(
      json,
      'call/offline-push',
      'Subject Error',
      callback,
      errorCallback,
      true /* Suppress error toastr */,
    )
  }

  const getContacts = function(json, callback, errorCallback) {
    log('--- getContacts API ---')
    encryptProtocol('contacts.list', json, message => {
      log(message)
      postJsonProtocol(
        message,
        'contacts/list',
        'Get Error',
        callback,
        errorCallback,
      )
    })
  }

  const searchContacts = function(json, callback, errorCallback) {
    log('--- searchContacts API ---')
    encryptProtocol('contacts.searchBy', json, message => {
      log(message)
      postJsonProtocol(
        message,
        'contacts/search',
        'Get Error',
        callback,
        errorCallback,
      )
    })
  }

  const declineContact = function(json, callback, errorCallback) {
    encryptProtocol('contacts.decline', json, message => {
      postJsonProtocol(
        message,
        'contacts/decline',
        'Get Error',
        callback,
        errorCallback,
      )
    })
  }

  const deleteContact = function(json, callback, errorCallback) {
    encryptProtocol('contacts.delete', json, message => {
      postJsonProtocol(
        message,
        'contacts/delete',
        'Get Error',
        callback,
        errorCallback,
      )
    })
  }

  const searchUsers = function(json, callback, errorCallback) {
    log('--- searchUsers API ---')
    encryptProtocol('user.search', json, message => {
      log(message)
      postJsonProtocol(
        message,
        'admin/users/search',
        'Get Error',
        callback,
        errorCallback,
      )
    })
  }

  const addContact = function(json, callback, errorCallback) {
    encryptProtocol('contacts.add', json, message => {
      log(message)
      postJsonProtocol(
        message,
        'contacts/add',
        'Get Error',
        callback,
        errorCallback,
      )
    })
  }

  const getContact = function(json, callback, errorCallback) {
    log('--- getContact API ---')
    encryptProtocol('contacts.get', json, message => {
      log(message)
      postJsonProtocol(
        message,
        'contacts/get',
        'Get Error',
        callback,
        errorCallback,
      )
    })
  }

  const inviteUsers = function(json, callback, errorCallback) {
    log('--- inviteNewUser API ---')
    encryptProtocol('user.referNewUsers', json, message => {
      postJsonProtocol(
        message,
        'invite',
        'Create Error',
        callback,
        errorCallback,
      )
    })
  }

  const inviteUserBySMS = function(json, callback, errorCallback) {
    log('--- inviteNewUserBySMS API ---')
    encryptProtocol('user.referNewUserBySMS', json, message => {
      postJsonProtocol(
        message,
        'invite',
        'Create Error',
        callback,
        errorCallback,
      )
    })
  }

  const getInvitedUsers = function(json, callback, errorCallback) {
    encryptProtocol('contacts.inviteList', json, message => {
      postJsonProtocol(
        message,
        'contacts/invite-list',
        'Get Error',
        callback,
        errorCallback,
      )
    })
  }

  const getPendingInvitedUsers = function(json, callback, errorCallback) {
    encryptProtocol('contacts.pendingInviteList', json, message => {
      postJsonProtocol(
        message,
        'contacts/pending-invite-list',
        'Get Error',
        callback,
        errorCallback,
      )
    })
  }

  const getContactByEmail = function(json, callback, errorCallback) {
    log('--- getContactByEmail API ---')
    encryptProtocol('contacts.getByEmail', json, message => {
      postJsonProtocol(
        message,
        'contacts/get-by-email',
        'Get Error',
        callback,
        errorCallback,
      )
    })
  }

  const getContactByUsername = function(json, callback, errorCallback) {
    log('--- getContactByUsername API ---')
    encryptProtocol('contacts.getByUsername', json, message => {
      postJsonProtocol(
        message,
        'contacts/get-by-username',
        'Get Error',
        callback,
        errorCallback,
      )
    })
  }

  const getContactByPhone = function(json, callback, errorCallback) {
    log('--- getContactByPhone API ---')
    encryptProtocol('contacts.getByPhone', json, message => {
      postJsonProtocol(
        message,
        'contacts/get-by-phone',
        'Get Error',
        callback,
        errorCallback,
      )
    })
  }

  const getContactByReferral = function(json, callback, errorCallback) {
    log('--- getContactByReferral API ---')
    encryptProtocol('contacts.getByReferral', json, message => {
      postJsonProtocol(
        message,
        'contacts/get-by-referral',
        'Get Error',
        callback,
        errorCallback,
      )
    })
  }

  const getContactSync = function(json, callback, errorCallback) {
    log('--- getContactSync API ---')
    encryptProtocol('contacts.sync', json, message => {
      postJsonProtocol(
        message,
        'contacts/sync',
        'Get Error',
        callback,
        errorCallback,
      )
    })
  }

  const blockContact = function(json, callback, errorCallback) {
    encryptProtocol('contacts.block', json, message => {
      postJsonProtocol(
        message,
        'contacts/block',
        'Get Error',
        callback,
        errorCallback,
      )
    })
  }

  const unblockContact = function(json, callback, errorCallback) {
    encryptProtocol('contacts.unblock', json, message => {
      postJsonProtocol(
        message,
        'contacts/unblock',
        'Get Error',
        callback,
        errorCallback,
      )
    })
  }

  const getUsersPublicKeys = function(json, callback, errorCallback) {
    encryptProtocol('user.getkeys', json, message => {
      postJsonProtocol(
        message,
        'users/getkeys',
        'Get Error',
        callback,
        errorCallback,
      )
    })
  }

  const getPublicKeys = function(json, callback, errorCallback) {
    getJson(json, 'keys/public', 'Get Error', callback, errorCallback)
  }

  const errorReport = function(json, callback, errorCallback) {
    postJson(json, 'errors/report', 'Subject Error', callback, errorCallback)
  }

  const adminSetup = function(json, callback, errorCallback) {
    const jsonData = message('node.postSetup', envelope(null, json))
    KU.sendJson(jsonData, 'admin/setup', (success, response) => {
      if (success === false) {
        KU.error(errorHandler, 'Setup Error', response)
        errorCallback(response)
      } else {
        callback(response)
      }
    })
  }

  const unlockServer = function(json, callback, errorCallback) {
    const jsonData = message('node.postUnlock', envelope(null, json))
    KU.sendJson(jsonData, 'admin/unlock', (success, response) => {
      if (success === false) {
        errorCallback(response)
      } else {
        callback(response)
      }
    })
  }

  const setup = function(json, callback, errorCallback) {
    const jsonData = message('user.setOneTimeUpdateKeys', envelope(null, json))
    log(jsonData)
    KU.sendJson(jsonData, 'account/setup', (success, response) => {
      if (success === false) {
        errorCallback(response)
      } else {
        callback(response)
      }
    })
  }

  const request = function(data, callback, errorCallback) {
    KU.sendJson(data, 'account/request', (success, response) => {
      if (success) {
        callback(response)
      } else {
        // TODO: PHP and Node errors possible, need to fix after common error handlig has been done!
        errorCallback(response)
        // decryptProtocol(response, errorCallback, true, true, true);
        // KU.error(errorCallback, "Signup Error", response);
      }
    })
  }

  const register = function(data, callback, errorCallback) {
    KU.sendJson(data, 'account/register', (success, response) => {
      if (success) {
        callback(response)
      } else {
        KU.error(errorCallback, 'Signup Error', response)
      }
    })
  }

  const authenticate = function(data, callback, errorCallback) {
    KU.sendData(data, 'authenticate', (success, response) => {
      if (success) {
        callback(response)
      } else {
        errorCallback(response)
      }
    })
  }

  const uploadProfilePicture = function(
    data,
    callback,
    errorCallback,
    uploadCallback,
  ) {
    const jqXHR = KU.sendData(data, 'avatar/upload', (success, response) => {
      if (success) {
        callback(response)
      } else {
        KU.error(errorHandler, 'Upload Error', response)
        errorCallback(response)
      }
    })
  }

  const uploadAttachment = function(
    data,
    callback,
    errorCallback,
    uploadCallback,
  ) {
    return uploadFile(
      data,
      'messages/attachment',
      callback,
      errorCallback,
      uploadCallback,
    )
  }

  const uploadChatAttachment = function(
    data,
    callback,
    errorCallback,
    uploadCallback,
  ) {
    if (data.file_transfer === null) {
      return callback(null)
    }
    return uploadFile(
      data,
      'filetransfer/upload',
      callback,
      errorCallback,
      uploadCallback,
    )
  }

  const deleteProfilePicture = function(json, callback, errorCallback) {
    postJson(json, 'avatar/delete', 'Delete Error', callback, errorCallback)
  }

  // Posible Deprecated
  const addUser = function(json, callback, errorCallback) {
    //        log('add user!!!!');
    encryptProtocol('user.create', json, message => {
      postJsonProtocol(
        message,
        'admin/users/add',
        'Create Error',
        callback,
        errorCallback,
      )
    })
  }

  const updateUser = function(json, callback, errorCallback) {
    encryptProtocol('user.update', json, message => {
      postJsonProtocol(
        message,
        'admin/users/update',
        'Update Error',
        callback,
        errorCallback,
      )
    })
  }

  const getUsers = function(json, callback, errorCallback) {
    encryptProtocol('user.list', json, message => {
      postJsonProtocol(
        message,
        'admin/users',
        'Create Error',
        callback,
        errorCallback,
      )
    })
  }

  const getAdminActivity = function(json, callback, errorCallback) {
    encryptProtocol('eventlog.listAll', json, message => {
      postJsonProtocol(
        message,
        'admin/activity',
        'List Error',
        callback,
        errorCallback,
      )
    })
  }

  const getAdminFilteredActivity = function(json, callback, errorCallback) {
    encryptProtocol('eventlog.filterList', json, message => {
      postJsonProtocol(
        message,
        'admin/activity',
        'List Error',
        callback,
        errorCallback,
      )
    })
  }

  const getAdminActivityStats = function(json, callback, errorCallback) {
    encryptProtocol('eventlog.basicStats', json, message => {
      postJsonProtocol(
        message,
        'admin/activityBasicStats',
        'List Error',
        callback,
        errorCallback,
      )
    })
  }

  const disableUser = function(json, callback, errorCallback) {
    encryptProtocol('user.disable', json, message => {
      postJsonProtocol(
        message,
        'admin/users/disable',
        'Error',
        callback,
        errorCallback,
      )
    })
  }

  const enableUser = function(json, callback, errorCallback) {
    encryptProtocol('user.enable', json, message => {
      postJsonProtocol(
        message,
        'admin/users/enable',
        'Error',
        callback,
        errorCallback,
      )
    })
  }

  const changeUserRole = function(json, callback, errorCallback) {
    encryptProtocol('user.enable', json, message => {
      postJsonProtocol(
        message,
        'admin/users/role',
        'Error',
        callback,
        errorCallback,
      )
    })
  }

  const changePassword = function(json, callback, errorCallback) {
    log('changePassword API call')
    encryptProtocol('user.changePassword', json, message => {
      postJsonProtocol(
        message,
        'account/password',
        'Error',
        callback,
        errorCallback,
      )
    })
  }

  const device = function(json, callback, errorCallback) {
    log('device API call')
    encryptProtocol('account.device', json, message => {
      postJsonProtocol(
        message,
        'account/device',
        'Error',
        callback,
        errorCallback,
      )
    })
  }

  const updateGeneralSettings = function(json, callback, errorCallback) {
    log('changePassword API call')
    encryptProtocol('settings.setgeneral', json, message => {
      postJsonProtocol(
        message,
        'account/settings',
        'Error',
        callback,
        errorCallback,
      )
    })
  }

  const setupTfa = function(json, callback, errorCallback) {
    const password = json.pwd
    KRYPTOS.deriveAccountPassword(
      KRYPTOS.session.getItem('username'),
      password,
      KRYPTOS.session.getItem('domain'),
      accountPassword => {
        json.pwd = accountPassword
        encryptProtocol('account.setupTfa', json, message => {
          postJsonProtocol(
            message,
            'account/setup-tfa',
            'Two-factor Error',
            callback,
            errorCallback,
          )
        })
      },
    )
  }

  const disableTfa = function(json, callback, errorCallback) {
    const password = json.pwd
    KRYPTOS.deriveAccountPassword(
      KRYPTOS.session.getItem('username'),
      password,
      KRYPTOS.session.getItem('domain'),
      accountPassword => {
        json.pwd = accountPassword
        encryptProtocol('account.disableTfa', json, message => {
          postJsonProtocol(
            message,
            'account/disable-tfa',
            'Two-factor Error',
            callback,
            errorCallback,
          )
        })
      },
    )
  }

  const activateTfa = function(json, callback, errorCallback) {
    encryptProtocol('account.activateTfa', json, message => {
      postJsonProtocol(
        message,
        'account/activate-tfa',
        'Two-factor Error',
        callback,
        errorCallback,
      )
    })
  }

  //    let showQr = function (json, callback, errorCallback) {
  //        encryptProtocol('account.showQr', json, function (message) {
  //            postJsonProtocol(message, 'account/show-qr', 'Two-factor Error', callback, errorCallback);
  //        });
  //    };

  const saveEmailSignature = function(json, callback, errorCallback) {
    encryptProtocol('settings.setEmailSignature', json, message => {
      postJsonProtocol(
        message,
        'users/signature',
        'Email Signature Error',
        callback,
        errorCallback,
      )
    })
  }

  const getEmailSignature = function(json, callback, errorCallback) {
    encryptProtocol('settings.getEmailSignature', json, message => {
      postJsonProtocol(
        message,
        'users/signature',
        'Email Signature Error',
        callback,
        errorCallback,
      )
    })
  }

  const enableEmail = function(json, callback, errorCallback) {
    encryptProtocol('account.enableEmail', json, message => {
      postJsonProtocol(
        message,
        'account/enable-email',
        'Two-factor Error',
        callback,
        errorCallback,
      )
    })
  }

  const disableEmail = function(json, callback, errorCallback) {
    encryptProtocol('account.disableEmail', json, message => {
      postJsonProtocol(
        message,
        'account/disable-email',
        'Two-factor Error',
        callback,
        errorCallback,
      )
    })
  }

  const wsPing = function(json, callback, errorCallback) {
    encryptProtocol('ws.ping', json, message => {
      sendWebsocket(message)
    })
  }

  const wsRegister = function(json, callback, errorCallback) {
    encryptProtocol('ws.register', json, message => {
      sendWebsocket(message)
    })
  }

  const wsReceiveData = function(data, callback) {
    decryptProtocol(data, callback)
  }

  const makeGroupCall = function(json, callback, errorCallback) {
    encryptProtocol('groupcall.make', json, message => {
      sendWebsocket(message)
    })
  }

  const checkGroupCalls = function(json, callback, errorCallback) {
    encryptProtocol('groupcall.check', json, message => {
      sendWebsocket(message)
    })
  }

  const declineGroupCall = function(json, callback, errorCallback) {
    encryptProtocol('groupcall.decline', json, message => {
      sendWebsocket(message)
    })
  }

  const joinGroupCall = function(json, callback, errorCallback) {
    encryptProtocol('groupcall.join', json, message => {
      sendWebsocket(message)
    })
  }

  const leaveGroupCall = function(json, callback, errorCallback) {
    encryptProtocol('groupcall.leave', json, message => {
      sendWebsocket(message)
    })
  }

  const requestPhoneChange = function(json, callback, errorCallback) {
    const password = json.pwd
    KRYPTOS.deriveAccountPassword(
      KRYPTOS.session.getItem('username'),
      password,
      KRYPTOS.session.getItem('domain'),
      accountPassword => {
        json.pwd = accountPassword
        encryptProtocol('account.requestPhoneChange', json, message => {
          postJsonProtocol(
            message,
            'account/change-phone-request',
            'Get Error',
            callback,
            errorCallback,
          )
        })
      },
    )
  }

  const confirmPhoneChange = function(json, callback, errorCallback) {
    encryptProtocol('account.confirmPhoneChange', json, message => {
      postJsonProtocol(
        message,
        'account/change-phone-confirm',
        'Get Error',
        callback,
        errorCallback,
      )
    })
  }

  const requestEmailChange = function(json, callback, errorCallback) {
    const password = json.pwd
    KRYPTOS.deriveAccountPassword(
      KRYPTOS.session.getItem('username'),
      password,
      KRYPTOS.session.getItem('domain'),
      accountPassword => {
        json.pwd = accountPassword
        encryptProtocol('account.requestEmailChange', json, message => {
          postJsonProtocol(
            message,
            'account/email-request',
            'Get Error',
            callback,
            errorCallback,
          )
        })
      },
    )
  }

  const confirmEmailChange = function(json, callback, errorCallback) {
    encryptProtocol('account.confirmEmailChange', json, message => {
      postJsonProtocol(
        message,
        'account/email-confirm',
        'Get Error',
        callback,
        errorCallback,
      )
    })
  }

  const removeEmail = function(json, callback, errorCallback) {
    encryptProtocol('account.removeEmail', json, message => {
      postJsonProtocol(
        message,
        'account/remove-email',
        'Get Error',
        callback,
        errorCallback,
      )
    })
  }
  let getJson = function(
    json,
    resource,
    method,
    errorTitle,
    callback,
    errorCallback,
  ) {
    KU.getJson(json, resource, method, (success, response) => {
      if (success === false) {
        if (errorCallback) {
          errorCallback(response)
        } else {
          KU.error(errorHandler, errorTitle, response)
        }
      } else {
        callback(response)
      }
    })
  }

  let postJson = function(
    json,
    resource,
    errorTitle,
    callback,
    errorCallback,
    suppressError,
  ) {
    KU.sendJson(json, resource, (success, response) => {
      if (success === false) {
        if (!suppressError) {
          KU.error(errorHandler, errorTitle, response)
        }
        if (errorCallback) {
          errorCallback(response, true)
        }
      } else {
        callback(response)
      }
    })
  }

  let postJsonProtocol = function(
    json,
    resource,
    errorTitle,
    callback,
    errorCallback,
  ) {
    KU.sendJson(json, resource, (success, response) => {
      if (success === false) {
        //                KU.error(errorHandler, errorTitle, response);
        decryptProtocol(response, errorCallback, true, false, true)
      } else {
        decryptProtocol(response, callback, false, false, false)
      }
    })
  }

  const sendData = function(
    data,
    resource,
    callback,
    errorCallback,
    uploadCallback,
  ) {
    return KU.sendData(
      data,
      resource,
      (success, response) => {
        if (success) {
          callback(response)
        } else {
          KU.error(errorCallback, 'Upload Error', response)
          // errorCallback(response);
        }
      },
      uploadCallback,
    )
  }

  let uploadFile = function(
    data,
    resource,
    callback,
    errorCallback,
    uploadCallback,
  ) {
    return sendData(data, resource, callback, errorCallback, uploadCallback)
  }

  let sendWebsocket = function(message) {
    KRYPTOS.WS.send(JSON.stringify(message))
  }

  const setKeyStore = function(serviceKeyStore) {
    keyStore = serviceKeyStore
  }

  let log = function(msg) {
    return false
  }

  const protocol = function(json, callback, errorCallback) {
    log('--- getNote ---')
    encryptProtocol('notes.get', json, message => {
      postJsonProtocol(
        message,
        'notes/get',
        'Protocol Error',
        callback,
        errorCallback,
      )
    })
  }

  const addCallLog = function(json, callback, errorCallback) {
    log('--- addCallLog ---')
    encryptProtocol('call.add', json, message => {
      postJsonProtocol(
        message,
        'call/log/add',
        'CallLog Error',
        callback,
        errorCallback,
      )
    })
  }

  const deleteCallLog = function(json, callback, errorCallback) {
    log('--- deleteCallLog ---')
    encryptProtocol('call.delete', json, message => {
      postJsonProtocol(
        message,
        'call/log/delete',
        'CallLog Error',
        callback,
        errorCallback,
      )
    })
  }

  const deleteAllCallLog = function(json, callback, errorCallback) {
    log('--- deleteAllCallLog ---')
    encryptProtocol('call.deleteall', json, message => {
      postJsonProtocol(
        message,
        'call/log/delete-all',
        'CallLog Error',
        callback,
        errorCallback,
      )
    })
  }

  const listCallLog = function(json, callback, errorCallback) {
    log('--- listCallLog ---')
    encryptProtocol('call.list', json, message => {
      postJsonProtocol(
        message,
        'call/log/list',
        'CallLog Error',
        callback,
        errorCallback,
      )
    })
  }

  const getSyncCallLog = function(json, callback, errorCallback) {
    log('--- getSyncCallLog ---')
    encryptProtocol('call.sync', json, message => {
      postJsonProtocol(
        message,
        'call/log/sync',
        'CallLog Error',
        callback,
        errorCallback,
      )
    })
  }

  const getInbox = function(json, callback, errorHandler) {
    loadInbox(json, 'inbox', callback, errorHandler)
  }

  const getSent = function(json, callback, errorHandler) {
    loadInbox(json, 'sent', callback, errorHandler)
  }

  const getDrafts = function(json, callback, errorHandler) {
    loadInbox(json, 'drafts', callback, errorHandler)
  }

  const getStarred = function(json, callback, errorHandler) {
    loadInbox(json, 'starred', callback, errorHandler)
  }

  const getTrashed = function(json, callback, errorHandler) {
    loadInbox(json, 'trash', callback, errorHandler)
  }

  const sendMail = function(data, callback, errorHandler) {
    return sendData(data, 'messages/message', callback, errorHandler)
  }

  const draftMail = function(data, callback, errorHandler) {
    return sendData(data, 'messages/draft', callback, errorHandler)
  }

  let loadInbox = function(json, mailbox, callback, errorHandler) {
    KU.getJson(json, `mail/${mailbox}`, (success, response) => {
      if (success === false) {
        KU.error(errorHandler, 'Get Error', response)
      } else {
        callback(response)
      }
    })
  }

  const readMail = function(json, callback, errorCallback) {
    postJson(json, 'mail/read', 'Error', callback, errorCallback)
  }

  const unreadMail = function(json, callback, errorCallback) {
    postJson(json, 'mail/unread', 'Error', callback, errorCallback)
  }

  const starMail = function(json, callback, errorCallback) {
    postJson(json, 'mail/star', 'Error', callback, errorCallback)
  }

  const unstarMail = function(json, callback, errorCallback) {
    postJson(json, 'mail/unstar', 'Error', callback, errorCallback)
  }

  const trashMail = function(json, callback, errorCallback) {
    postJson(json, 'mail/trash', 'Error', callback, errorCallback)
  }

  const restoreMail = function(json, callback, errorCallback) {
    postJson(json, 'mail/restore', 'Error', callback, errorCallback)
  }

  const deleteMail = function(json, callback, errorCallback) {
    postJson(json, 'mail/delete', 'Error', callback, errorCallback)
  }

  const checkMail = function(callback, errorHandler) {
    KU.getJson(null, 'messages/check?active', (success, response) => {
      if (success === false) {
        KU.error(errorHandler, 'Get Error', response)
      } else {
        callback(response)
      }
    })
  }

  const searchMail = function(json, callback, errorHandler) {
    KU.getJson(null, `mail/${json.type}${json.params}`, (success, response) => {
      if (success === false) {
        KU.error(errorHandler, 'Get Error', response)
      } else {
        callback(response)
      }
    })
  }

  return {
    setErrorHandler() {
      errorHandler = function(error) {}
    },

    setKeyStore,
    setUserId,
    setNodeId,
    nodePrefix,

    postJson,
    getJson,

    // Error report
    errorReport,

    // Keys
    getPublicKeys,
    getUsersPublicKeys,

    // Account
    requestPhoneChange,
    confirmPhoneChange,
    requestEmailChange,
    confirmEmailChange,
    removeEmail,
    device,

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
    request,
    register,
    setup,
    adminSetup,
    unlockServer,
    authenticate,
    changePassword,
    updateGeneralSettings,
    setupTfa,
    disableTfa,
    activateTfa,
    // showQr: showQr,
    saveEmailSignature,
    getEmailSignature,
    enableEmail,
    disableEmail,

    /* Avatar */
    uploadProfilePicture,
    deleteProfilePicture,

    /* Admin */
    addUser,
    inviteUsers,
    inviteUserBySMS,

    /* Only Admin */
    getUsers,
    updateUser,
    disableUser,
    enableUser,
    changeUserRole,
    getAdminActivityStats,
    getAdminActivity,
    getAdminFilteredActivity,

    /* Storage */
    getRoot,
    getShares,
    getManageShares,
    getManageShare,
    unshareItem,
    acceptShare,
    getItem,
    addItem,
    addItems,
    updateItem,
    deleteItem,
    moveItem,
    copyItem,
    shareItem,
    updateShareItem,
    downloadItem,

    downloadFileTransfer,

    /* Chat */
    createGroupChat,
    getGroupChat: getGroup,
    getGroupChats: getGroups,
    deleteGroupChat,
    leaveGroupChat,
    addGroupChatMembers,
    deleteGroupChatMember,
    changeGroupChatSubject,
    getRecentChats,
    uploadGroupPicture,
    deleteGroupPicture,
    getGroupsSync,
    /* Call */
    offlinePush,

    uploadChatAttachment,

    downloadFile,

    /* Contacts */
    getContacts,
    getContact,
    getContactByEmail,
    getContactByUsername,
    getContactByPhone,
    getContactByReferral,
    searchContacts,
    searchUsers,
    addContact,
    declineContact,
    delectContact: deleteContact,
    getInvitedUsers,
    getPendingInvitedUsers,
    getContactSync,
    blockContact,
    unblockContact,

    /* WebSocket */
    wsRegister,
    wsPing,
    wsReceiveData,

    /* Group Call (ws) */
    makeGroupCall,
    checkGroupCalls,
    declineGroupCall,
    joinGroupCall,
    leaveGroupCall,

    testProtocol,
    protocol,

    /** Call Log * */
    addCallLog,
    deleteAllCallLog,
    deleteCallLog,

    listCallLog,

    getSyncCallLog,

    /** Mail * */
    getInbox,
    getSent,
    getDrafts,
    getStarred,
    getTrashed,
    readMail,
    unreadMail,
    starMail,
    unstarMail,
    trashMail,
    restoreMail,
    deleteMail,
    downloadAttachment,
    uploadAttachment,
    sendMail,
    draftMail,
    checkMail,
    searchMail,
  }
})()
