/* global sjcl, ES6Promise, Uint8Array, Token, Contacts, jsxc */

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
 * The KRYPTOS Core module.
 */
var KRYPTOS = KRYPTOS || {
  /**
   * 256 bytes length
   */
  LENGTH_256: 256,

  /**
   * SHA-256 hashing algorithm
   */
  SHA_256: {
    name: 'SHA-256',
  },

  /**
   * RSA-PSS signing alogrithm
   */
  RSA_PSS: {
    name: 'RSS-PSS',
  },

  RSA_OAEP: {
    name: 'RSA-OAEP',
  },

  AES_CBC: {
    name: 'AES-CBC',
  },

  AES_KW: {
    name: 'AES-KW',
  },

  AES_GCM: {
    name: 'AES-GCM',
  },

  HMAC: {
    name: 'HMAC',
  },

  RSASSA_PKCS1_v1_5: {
    name: 'RSASSA-PKCS1-v1_5',
  },

  RSASSA_PKCS1_v1_5_ALGO: {
    name: 'RSASSA-PKCS1-v1_5',
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]), // 24 bit representation of 65537
    hash: {
      name: 'SHA-256',
    },
  },

  /**
   * Asymmetric encryption algorithm
   */
  RSA_OAEP_ALGO: {
    name: 'RSA-OAEP',
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]), // 24 bit representation of 65537
    hash: {
      name: 'SHA-256',
    },
  },

  ECDH_ALGO: {
    name: 'ECDH',
    namedCurve: 'P-521',
  },

  ECDSA_ALGO: {
    name: 'ECDSA',
    namedCurve: 'P-521',
  },

  /**
   * Symmetric encryption algorithm
   */
  AES_CBC_ALGO: {
    name: 'AES-CBC',
    length: 256,
  },

  /**
   * Symmetric encryption algorithm
   */
  AES_GCM_ALGO: {
    name: 'AES-GCM',
    length: 256,
  },

  /**
   * Key wrap algorithm
   */
  AES_KW_ALGO: {
    name: 'AES-KW',
    length: 256,
  },

  HMAC_ALGO: {
    name: 'HMAC',
    hash: {
      name: 'SHA-256',
    },
  },

  /**
   * Indicates if crypto library fallback
   */
  MSR: false,

  MS: false,

  SF: false,

  EXTRACTABLE: true,

  NONEXTRACTABLE: false,

  ENCRYPT_USAGE: ['encrypt', 'decrypt'],

  SIGN_USAGE: ['sign', 'verify'],

  WRAP_USAGE: ['wrapKey', 'unwrapKey'],

  DERIVE_USAGE: ['deriveBits', 'deriveKey'],

  crypto: null,

  cryptoSubtle: null,

  Promise: null,

  session: window.sessionStorage,

  store: window.localStorage,

  rawIntermediateKey: null,

  intermediateKey: null,

  encryptKeyPair: null,

  signKeyPair: null,

  wrappedPrivateEncryptKey: null,

  wrappedPrivateSignKey: null,

  exportedPublicEncryptKey: null,

  exportedPublicSignKey: null,

  // setupInitialProtectedKey: null,
  //
  // setupInitialProtectedKeyIV: null,

  tokenProtector: null,

  aesKey: null,

  ivIAK: null,

  ivEncIAK: null,

  keyProtector: null,

  ivPDK: null,

  ivPSK: null,

  setupData: null,

  setupCallback: null,

  mailPassword: null,

  accountPassword: null,

  cachePdk: null,

  nonce() {
    return KRYPTOS.randomValue(16)
  },

  randomValue(bytes) {
    return KRYPTOS.crypto.getRandomValues(new Uint8Array(bytes))
  },

  uniqueId(length) {
    return KRYPTOS.utils.ab2hex(KRYPTOS.randomValue(length))
  },

  uniqueFileId() {
    return KRYPTOS.uniqueId(4)
  },

  format() {
    if (KRYPTOS.MSR) {
      return 'jwk'
    }
    return 'jwk'
  },

  cryptoBox(data, owner, algo, metaData) {
    const box = {
      data: data.m,
      metaData: metaData ? JSON.stringify(metaData) : '',
      iv: data.iv,
      signature: data.s,
      signatureOwner: owner,
      protectType: algo,
      protectors: [],
    }
    for (let i = 0; i < data.keys.length; i++) {
      box.protectors.push({
        username: data.keys[i].u,
        type: 'asymmetric', // assymetric old changed 06-03-2017
        encryptedKey: data.keys[i].k,
      })
    }
    return box
  },

  getAlgo(algo) {
    switch (algo) {
      case 'AES-GCM-256':
      case 'AES-GCM':
      case 'A256GCM':
        return { name: 'AES-GCM', length: 256 }
        break
      case 'AES-CBC':
      case 'AES-CBC-256':
      case 'A256CBC':
        return { name: 'AES-CBC', length: 256 }
        break
      case 'RSA2048':
        return { name: 'RSA-OAEP', hash: { name: 'SHA-256' } }
        break
      case 'RSASSA-PKCS1-v1_5-2048':
        return { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } }
        break
      case 'RSA-OAEP-256':
      case 'RSA-OAEP-2048':
        return { name: 'RSA-OAEP', hash: { name: 'SHA-256' } }
        break
      case 'RS256':
        return { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } }
        break

      case 'ECDSA':
      case 'ES512':
      case 'ECDSA-P521':
        return {
          name: 'ECDSA',
          namedCurve: 'P-521', // can be "P-256", "P-384", or "P-521"
        }
        break
      case 'ES512':
      case 'ECDH':
      case 'ECDH-P521':
        return {
          name: 'ECDH',
          namedCurve: 'P-521', // can be "P-256", "P-384", or "P-521"
        }
        break
    }
    throw new Error('Invalid algorithm2')
  },

  getECAlgo(crv) {
    switch (crv) {
      case 'P-521':
        return 'ES512'
      case 'P-384':
        return 'ES384'
      case 'P-256':
        return 'ES256'
    }
    throw new Error('Invalid curve.')
  },

  getSignAlgo(algo) {
    switch (algo) {
      case 'RSASSA-PKCS1-v1_5':
        return KRYPTOS.RSASSA_PKCS1_v1_5
        break
      case 'ECDSA':
        return { name: 'ECDSA', hash: { name: 'SHA-256' } }
        break
      case 'HMAC':
        return KRYPTOS.HMAC
        break
    }
    throw new Error('Invalid sign algorithm')
  },

  getImportAlgo(algo) {
    switch (algo) {
      case 'RSA':
      case 'RSASSA-PKCS1-v1_5':
        return { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } }
        break
      case 'EC':
      case 'ECDSA':
        return { name: 'ECDSA', namedCurve: 'P-521' }
        break
      case 'HMAC':
        return KRYPTOS.HMAC_ALGO
        break
    }
    throw new Error('Invalid import algorithm')
  },

  getAsymmetricModeByAlgo(algo) {
    if (algo.length && algo.length >= 2) {
      if (algo.substring(0, 2).toUpperCase() === 'EC') {
        return 'EC'
      }
    }
    return 'RSA'
  },

  clear() {
    //        KRYPTOS.mailPassword = null;
    //        KRYPTOS.accountPassword = null;
    //        KRYPTOS.rawIntermediateKey = null;
    //        KRYPTOS.intermediateKey = null;
    //        KRYPTOS.encryptKeyPair = null;
    //        KRYPTOS.signKeyPair = null;
    //        KRYPTOS.wrappedPrivateEncryptKey = null;
    //        KRYPTOS.wrappedPrivateSignKey = null;
    //        KRYPTOS.exportedPublicEncryptKey = null;
    //        KRYPTOS.exportedPublicSignKey = null;
    //        KRYPTOS.aesKey = null;
    //        KRYPTOS.ivPDK = null;
    //        KRYPTOS.ivPSK = null;
    //        KRYPTOS.setupData = null;
    KRYPTOS.session.clear()
  },

  /**
   * Derives a 256 bit key based on a password, using the PBKDF2 algorithm
   * with 5000 rounds.
   *
   * @param {type} salt
   * @param {type} password
   * @returns {String}
   */
  getDerivedPassword(salt, password) {
    let start = new Date().getTime(),
      end = 0
    return new KRYPTOS.Promise((resolve, reject) => {
      const rounds = 50000
      const length = 256
      const derivedKey = sjcl.misc.pbkdf2(
        password,
        sjcl.codec.utf8String.toBits(salt),
        rounds,
        length,
      )
      end = new Date().getTime()
      resolve(sjcl.codec.hex.fromBits(derivedKey))
    })
  },

  deriveAccountPassword(username, password, domain, callback) {
    let start = new Date().getTime(),
      end = 0
    const salt = `${username.toLowerCase()}@${domain}`
    const deriveKeyAlgo = {
      name: 'PBKDF2',
      salt: KRYPTOS.utils.str2ab(salt),
      iterations: 50000,
      hash: 'SHA-256',
    }
    return KRYPTOS.cryptoSubtle
      .importKey(
        'raw',
        KRYPTOS.utils.str2ab(password),
        { name: 'PBKDF2' },
        false,
        KRYPTOS.DERIVE_USAGE,
      )
      .then(key =>
        KRYPTOS.cryptoSubtle
          .deriveKey(
            deriveKeyAlgo,
            key,
            KRYPTOS.AES_KW_ALGO,
            KRYPTOS.EXTRACTABLE,
            KRYPTOS.WRAP_USAGE,
          )
          .then(derivedKey =>
            KRYPTOS.cryptoSubtle
              .exportKey('raw', derivedKey)
              .then(exportedKey => {
                end = new Date().getTime()
                callback(KRYPTOS.utils.ab2hex(exportedKey))
              }),
          ),
      )
      .catch(error =>
        // PBKDF2 fallback
        KRYPTOS.getDerivedPassword(salt, password).then(derivedPassword => {
          callback(derivedPassword)
        }),
      )
  },

  changePassword(
    keyStores,
    username,
    oldPassword,
    newPassword,
    domain,
    callback,
  ) {
    const promises = []
    KRYPTOS.deriveAccountPassword(
      username,
      oldPassword,
      domain,
      oldPassword => {
        KRYPTOS.deriveAccountPassword(
          username,
          newPassword,
          domain,
          password => {
            for (const prop in keyStores) {
              promises.push(keyStores[prop].lock(newPassword))
            }

            KRYPTOS.Promise.all(promises)
              .then(result => {
                const data = {
                  password: oldPassword,
                  newPassword: password,
                  keyContainers: [],
                }
                for (let i = 0; i < result.length; i++) {
                  for (const prop in result[i]) {
                    data.keyContainers[i] = {}
                    data.keyContainers[i][prop] = result[i][prop]
                  }
                }

                callback(true, data)
              })
              .catch(error => {
                callback(false, error)
              })
          },
        )
      },
    )
  },

  /**
   * Compute the account password and the private key password based on hashes
   * of the plain password and the username@domain. The private key password
   * is stored in session storage. If a callback function is provided it will
   * be called when all digest Promises have completed successfully.
   *
   * The init function is used for both the sign-in and registration flow.
   *
   * @param {string} username plain text
   * @param {string} password plain text
   * @param {string} domain plain text
   * @param {type} callback
   * @returns {void}
   */
  init(username, password, domain, callback) {
    return KRYPTOS.getDerivedPassword(`${username}@${domain}`, password)
      .then(accountPassword => {
        KRYPTOS.accountPassword = accountPassword
        return KRYPTOS.getDerivedPassword(
          `${username}@${domain}${username}`,
          password,
        )
      })
      .then(mailPassword => {
        KRYPTOS.mailPassword = mailPassword
        if (callback) {
          callback(username, KRYPTOS.accountPassword, KRYPTOS.mailPassword)
        }
      })
      .catch(error => {
        KRYPTOS.utils.log(error)
      })
  },

  /** NEW KRYPTOS * */

  firstLogin: false,
  selfContact: {
    contact: {
      user_id: null,
      contact_user_id: null,
      username: null,
      country_code: null,
      phone: null,
      first_name: null,
      last_name: null,
      display_name: null,
      company_name: null,
      email: null,
      jid: null,
      contacts_keys_hmac: null,
      created_at: null,
      updated_at: null,
    },
    contact_keys: {
      contact_keys: null,
    },
    contact_signature: null,
  },

  authenticate(credentials, domain, callback, errorCallback) {
    const password = credentials.password
    KRYPTOS.deriveAccountPassword(
      credentials.username,
      password,
      domain,
      accountPassword => {
        credentials.password = accountPassword
        if (
          credentials.sessioninfo !== undefined &&
          credentials.sessioninfo !== null
        ) {
          prepareSession(credentials.sessioninfo)
        } else {
          KRYPTOS.API.authenticate(
            credentials,
            response => {
              prepareSession(response)
            },
            error => {
              KRYPTOS.utils.error(
                (title, message) => {
                  errorCallback(message)
                },
                '',
                error,
              )
            },
          )
        }
      },
    )

    function prepareSession(response) {
      // console.log(response)
      if (response.tfa === true) {
        callback(true)
        return
      }

      if (response.tfa === false) {
        callback(false)
        return
      }

      for (const prop in response) {
        if (response.hasOwnProperty(prop) && prop !== 'keys') {
          // console.log(response[prop]);
          if (response[prop] === null) {
            response[prop] = ''
          }
          KRYPTOS.session.setItem(prop, response[prop])
        }
      }

      let keys = JSON.parse(response.keys)

      // Set node public keys
      KRYPTOS.session.setItem(
        KRYPTOS.API.nodePrefix('pvk'),
        JSON.stringify(keys.nodeKeys.pvk),
      )
      KRYPTOS.session.setItem(
        KRYPTOS.API.nodePrefix('pek'),
        JSON.stringify(keys.nodeKeys.pek),
      )

      if (response.keyContainers) {
        keys = response.keyContainers
      }

      const promises = []

      for (const prop in keys) {
        if (keys.hasOwnProperty(prop) && prop !== 'nodeKeys') {
          promises.push(
            new KRYPTOS.KeyStore(prop, keys[prop].pdk, keys[prop].psk).unlock(
              password,
              keys[prop].pek,
              keys[prop].pvk,
              keys[prop].signature,
            ),
          )
        }
      }

      KRYPTOS.Promise.all(promises)
        .then(result => {
          if (KRYPTOS.firstLogin) {
            const userId = KRYPTOS.session.getItem('id')
            KRYPTOS.selfContact.contact.user_id = userId
            KRYPTOS.selfContact.contact.contact_user_id = userId
            KRYPTOS.selfContact.contact.username = KRYPTOS.session.getItem(
              'username',
            )
            KRYPTOS.selfContact.contact.display_name = KRYPTOS.session.getItem(
              'display_name',
            )
            KRYPTOS.selfContact.contact.country_code = KRYPTOS.session.getItem(
              'phone_country_code',
            )
            KRYPTOS.selfContact.contact.phone = KRYPTOS.session.getItem('phone')
            KRYPTOS.selfContact.contact.jid = KRYPTOS.session.getItem('jid')
            const keyStores = []
            keyStores.identity = new KRYPTOS.KeyStore('identity')
            keyStores.identity.init()
            keyStores.storage = new KRYPTOS.KeyStore('storage')
            keyStores.storage.init()
            keyStores.mail = new KRYPTOS.KeyStore('mail')
            keyStores.mail.init()
            keyStores.protocol = new KRYPTOS.KeyStore('protocol')
            keyStores.protocol.init()
            KRYPTOS.API.setUserId(KRYPTOS.session.getItem('id'))
            KRYPTOS.API.setNodeId(KRYPTOS.session.getItem('node_id'))
            KRYPTOS.API.setKeyStore(keyStores.protocol)
            const publicKeys = {
              identity: keyStores.identity.getRecipientPublicKeys(userId),
              mail: keyStores.mail.getRecipientPublicKeys(userId),
              storage: keyStores.storage.getRecipientPublicKeys(userId),
            }
            KRYPTOS.selfContact.contact_keys.contact_keys = JSON.stringify(
              publicKeys,
            )
            Contacts.initKeys(keyStores)
            Contacts.addContact(KRYPTOS.selfContact, signedContact => {
              KRYPTOS.API.addContact(
                signedContact,
                data => {
                  callback()
                },
                error => {
                  callback(error)
                },
              )
            })
          } else {
            callback()
          }
        })
        .catch(error => {
          KRYPTOS.utils.log(error)
          KRYPTOS.utils.error(
            (title, message) => {
              errorCallback(message)
            },
            '',
            error,
          )
        })
    }
  },
}

/**
 * The KRYPTOS Messages module.
 *
 */
// KRYPTOS.Messages = {
//    mails: [],
//
//    add: function(uuid, mail) {
//        this.mails[uuid] = mail;
//    },
//
//    get: function(uuid) {
//        if (!this.mails[uuid]) {
//            return false;
//        }
//
//        return this.mails[uuid];
//    },
//
//    read: function(uuid, callback) {
//        KRYPTOS.utils.sendJson({message_id: uuid}, 'mail', 'read', callback); //function(json, resource, type, callback)
//    },
//
//    unread: function(uuid, callback) {
//        KRYPTOS.utils.sendJson({message_id: uuid}, 'mail', 'unread', callback); //function(json, resource, type, callback)
//    },
//
//    star: function(uuid, callback) {
//        KRYPTOS.utils.sendJson({message_id: uuid}, 'mail', 'star', callback);
//    },
//
//    unstar: function(uuid, callback) {
//        KRYPTOS.utils.sendJson({message_id: uuid}, 'mail', 'unstar', callback);
//    },
//
//    trash: function(uuid, callback) {
//        //this.remove(uuid);
//        KRYPTOS.utils.sendJson({message_id: uuid}, 'mail', 'trash', callback); //function(json, resource, type, callback)
//    },
//    restore: function(uuid, callback) {
//        //this.remove(uuid);
//        KRYPTOS.utils.sendJson({message_id: uuid}, 'mail', 'restore', callback); //function(json, resource, type, callback)
//    },
//    delete: function(uuid, callback) {
//        //this.remove(uuid);
//        KRYPTOS.utils.sendJson({message_id: uuid}, 'mail', 'delete', callback); //function(json, resource, type, callback)
//    },
//    remove: function(uuid) {
//        delete this.mails[uuid];
//    },
//
//    getMails: function() {
//
//    },
//
//    saveDraft: function(callback) {
//
//    }
// };

/**
 * KRYPTOS utilities.
 * Contains varios utility and conversions functions.
 */
KRYPTOS.utils = {
  logContainer: '#logContainer',
  logType: 3,
  mailSignature: null,

  /**
   * This is the KRYPTOS logger.
   * Set logType = 1 to log to //console.
   * Set logType = 2 to log to the a HTML container or define it above.
   * Set logType = 0 to disable logging completely.
   *
   * @param {type} msg
   * @returns {undefined}
   */
  log(msg) {
    if (this.logType === 1) {
    } else if (this.logType === 2) {
      $(logContainer).append(`<p>${msg}</p>`)
    } else if (this.logType === 3) {
      if (msg.message) {
      }
      if (msg.stack) {
      }
      console.error(msg)
    }
  },

  error(handler, title, errorObj) {
    let message = ''
    if (!errorObj) {
      handler(title, message)
      return
    }
    const obj = errorObj.errors || errorObj
    for (const prop in obj) {
      if (obj.hasOwnProperty(prop)) {
        message += obj[prop]
      }
    }
    if (message === '') {
      message = 'An un-expected error happened'
    }
    handler(title, message)
  },

  getUsernamesByIds(ids, callback) {
    const contacts = Contacts.getContacts()
    const usernames = []
    if (contacts.length) {
      for (let j = 0; j < ids.length; j++) {
        for (let i = 0; i < contacts.length; i++) {
          if (contacts[i].contact.contact_user_id === ids[j]) {
            usernames.push(contacts[i].contact.username)
          }
        }
      }
    }
    callback(usernames)
  },

  getUsernameById(id) {
    const uid = KRYPTOS.utils.e2u(id)
    const contacts = Contacts.getContacts()
    if (contacts.length) {
      for (let i = 0; i < contacts.length; i++) {
        if (contacts[i].contact.contact_user_id === uid) {
          //                if (contacts[i].id === uid) {
          return contacts[i].contact.username
        }
      }
    }
    return null
  },

  getIdByUsername(username) {
    const contacts = Contacts.getContacts()
    if (contacts.length) {
      for (let i = 0; i < contacts.length; i++) {
        if (contacts[i].contact.username === username) {
          return contacts[i].contact.contact_user_id
        }
      }
    }
    return null
  },

  getDisplayNameById(id, callback) {
    const uid = KRYPTOS.utils.e2u(id)
    const contacts = Contacts.getContacts() || []
    if (contacts.length) {
      for (let i = 0; i < contacts.length; i++) {
        if (contacts[i].contact.contact_user_id === uid) {
          // let dn = KRYPTOS.utils.decodeURIComp(null, contacts[i].contact.display_name, 'subj');
          const dn = contacts[i].contact.username
          if (callback) {
            callback(dn)
          } else {
            return dn
          }
        }
      }
    }
    if (callback) {
      // 8fa1006ab99cfec3e7538af431f277cbcab4fffc1fc6a79d34efa80c486e4408

      Contacts.getContact(uid, contact => {
        callback(
          KRYPTOS.utils.decodeURIComp(null, contact.display_name, 'subj'),
        )
      })

      //            KRYPTOS.API.getContact({user_id: uid}, function(contact) {
      //                   contacts.push({
      //                       id: contact.id,
      //                       username: contact.username,
      //                       email: contact.username,
      //                       display_name: contact.display_name,
      //                       picture: contact.profile_pic
      //                   });
      //                   KRYPTOS.session.setItem('contacts', JSON.stringify(contacts));
      //                   callback(contact.display_name);
      //                }, function(error) {
      //                    callback("(no name)");
      //                });
    } else {
      return '(no name)'
    }
  },

  getDisplayNameByUsername(username) {
    const contacts = Contacts.getContacts()
    if (contacts.length) {
      for (let i = 0; i < contacts.length; i++) {
        if (contacts[i].contact.username === username) {
          return KRYPTOS.utils.decodeURIComp(
            null,
            contacts[i].contact.display_name,
            'subj',
          )
        }
      }
    }
    return `(${username})`
  },

  roleDisplay(role) {
    //        return KRYPTOS.utils.ucwords(role.replace(/_/gi, " "));
    switch (role) {
      case 'employee':
        return 'Employee'
      case 'external_user':
        return 'External User'
      case 'admin':
        return 'Admin'
      case 'external_user_storage_only':
        return 'External User (Files only)'
      case 'external_user (storage only)':
        return 'External User (Files only)'
      case 'external_user (Storage only)':
        return 'External User (Files only)'
      default:
        return KRYPTOS.utils.ucwords(role.replace(/_/gi, ' '))
    }
  },

  resetFormElement(e) {
    const form = e
      .wrap('<form>')
      .closest('form')
      .get(0)
    form.reset()
    $(form)
      .find('.form-group')
      .removeClass('has-success')
    e.unwrap()
  },

  cachedProfilePics: [],

  getAvatar(jid) {
    const id = KRYPTOS.utils.e2u(jid)
    let avatar = KRYPTOS.utils.cachedProfilePics[id]

    if (!avatar) {
      avatar = `/avatar/get?uid=${id}&t=${new Date().getTime()}`
      KRYPTOS.utils.cachedProfilePics[id] = avatar
    }

    return avatar
  },

  checkImage(imageSrc, good, bad) {
    const img = new Image()
    img.onload = good
    img.onerror = bad
    img.src = imageSrc
  },

  //    getProfilePicture: function(jid) {
  //        let id = KRYPTOS.utils.e2u(jid);
  //        let contacts = Contacts.getContacts();
  //        if (contacts.length) {
  //            for (let i = 0; i < contacts.length; i++) {
  //                if (contacts[i].contact.contact_user_id === id) {
  //                    if (contacts[i].profile_pic) {
  //                        return "/avatar/show?pid=" + contacts[i].profile_pic + "&uid=" + id;
  //                    }
  //                }
  //            }
  //        }
  //        return "/img/default-avatar.png";
  //    },

  getGroupProfilePicture(bid) {
    if (bid) {
      const data = jsxc.storage.getUserItem('buddy', bid)
      if (data.avatar) {
        const id = KRYPTOS.utils.e2u(bid)
        return `/chat/group/avatar/get?id=${id}&aid=${data.avatar}`
      }
    }
    return '/chat/jsxc/img/group_white.svg'
  },

  updatedProfilePicture(jid, pid) {
    const id = KRYPTOS.utils.e2u(jid)
    const contacts = Contacts.getContacts()
    let avatar = ''
    if (contacts.length) {
      for (let i = 0; i < contacts.length; i++) {
        if (contacts[i].contact.contact_user_id === id) {
          if (pid === 'delete') {
            contacts[i].contact.profile_pic = null
            avatar = '/img/default-avatar.png'
          } else if (pid) {
            contacts[i].contact.profile_pic = pid
            avatar = `/avatar/show?pid=${pid}&uid=${id}`
          } else {
            return '/img/default-avatar.png'
          }
          //                    KRYPTOS.session.setItem('contacts', JSON.stringify(contacts));
          return avatar
        }
      }
    }
    return '/img/default-avatar.png'
  },

  rsa() {
    return new KRYPTOS.RSA()
  },

  formatSubject(sanatizer, subject, type) {
    const str = KRYPTOS.utils.decodeURIComp(sanatizer, subject, type)
    if (str.length > 50) {
      return `${str.substring(0, 50)}...`
    }
    return str
  },

  formatLine(line, length) {
    if (line.length > length) {
      return `${line.substring(0, length)}...`
    }
    return line
  },

  extractMessage(data, callback) {
    const keyLength = new Uint16Array(data, 0, 2)[0] // First 16 bit integer
    const signatureLength = new Uint16Array(data, 2, 2)[0]
    const encryptedKey = new Uint8Array(data, 4, keyLength)
    const signature = new Uint8Array(data, 4 + keyLength, signatureLength)
    const iv = new Uint8Array(data, 4 + signatureLength + keyLength, 16)
    const cipherText = new Uint8Array(
      data,
      4 + signatureLength + keyLength + 16,
    )
    callback(encryptedKey, iv, cipherText, signature)
  },

  //
  //    getAttachment: function(messageId, attachmentId, hexKey, hexSignature, callback, downloadCallback) {
  //        let xhr = new XMLHttpRequest();
  //        xhr.open('GET', '/messages/attachment?message_id=' + messageId + '&attachment_id='+attachmentId, true); //1421776555890 - 1421776532206
  //        xhr.responseType = 'blob';
  //        xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
  //        xhr.setRequestHeader('X-CSRF-Token', Token.getToken());
  //        xhr.onload = function(e) {
  //            if (xhr.status === 200) {
  //                let blob = new Blob([xhr.response], {type: "application/octet-stream"});
  //                KRYPTOS.utils.readBlob(blob, function() {
  //                    let reader          = this;
  //                    let data            = reader.result;
  //                    let ivLength        = 16;
  //                    let iv              = new Uint8Array(data, 0, ivLength);
  //                    let attachment      = new Uint8Array(data, ivLength);
  //                    let key             = KRYPTOS.utils.hex2ab(hexKey);
  //                    let signature       = KRYPTOS.utils.hex2ab(hexSignature);
  //                    new KRYPTOS.Decrypter(null, key, iv, attachment, signature, null, null, callback).decryptFile();
  //                });
  //            }
  //            else {
  //                callback(false);
  //            }
  //        };
  //        xhr.addEventListener('progress', downloadCallback, false);
  //
  //        xhr.onerror = function(e) {
  //            callback(false);
  //        };
  //        xhr.send();
  //    },
  //
  //    getChatFileTransfer: function(fileId, hexKey, hexSignature, callback, downloadCallback) {
  //        let xhr = new XMLHttpRequest();
  //        xhr.open('GET', '/filetransfer/transfer?file_id=' + fileId, true); //1421776555890 - 1421776532206
  //        xhr.responseType = 'blob';
  //        xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
  //        xhr.setRequestHeader('X-CSRF-Token', Token.getToken());
  //        xhr.onload = function(e) {
  //            if (xhr.status === 200) {
  //                let blob = new Blob([xhr.response], {type: "application/octet-stream"});
  //                KRYPTOS.utils.readBlob(blob, function() {
  //                    let reader          = this;
  //                    let data            = reader.result;
  //                    let ivLength        = 16;
  //                    let iv              = new Uint8Array(data, 0, ivLength);
  //                    let attachment      = new Uint8Array(data, ivLength);
  //                    let key             = KRYPTOS.utils.hex2ab(hexKey);
  //                    let signature       = KRYPTOS.utils.hex2ab(hexSignature);
  //                    new KRYPTOS.Decrypter(null, key, iv, attachment, signature, null, null, callback).decryptFile();
  //                });
  //            }
  //            else {
  //                callback(false);
  //            }
  //        };
  //        xhr.addEventListener('progress', downloadCallback, false);
  //        xhr.onerror = function(e) {
  //            callback(false);
  //        };
  //        xhr.send();
  //    },

  getSignature(username, settings, callback) {
    if (settings['settings.mail.signatures.enable'] === 1) {
      if (KRYPTOS.utils.mailSignature !== null) {
        callback(KRYPTOS.utils.mailSignature)
      } else {
        const messageObj = JSON.parse(settings['settings.mail.signatures'])
        KRYPTOS.getPrivateDecryptionKey((success, pdk) => {
          if (success) {
            messageObj.key = KRYPTOS.utils.b642ab(messageObj.k)
            messageObj.iv = KRYPTOS.utils.b642ab(messageObj.iv)
            messageObj.message = KRYPTOS.utils.b642ab(messageObj.m)
            messageObj.signature = KRYPTOS.utils.b642ab(messageObj.s)
            KRYPTOS.Keys.getPublicKey(username, 'verify', pvk => {
              new KRYPTOS.Decrypter(
                null,
                messageObj.key,
                messageObj.iv,
                messageObj.message,
                messageObj.signature,
                pvk,
                pdk,
                plainText => {
                  KRYPTOS.utils.mailSignature = plainText.text
                    ? plainText.text
                    : ''
                  callback(KRYPTOS.utils.mailSignature)
                },
              ).decrypt()
            })
          } else {
            callback('')
          }
        })
      }
    } else {
      callback('')
    }
  },

  isConference(bid) {
    return bid && bid.indexOf('@conference') !== -1
  },

  isEmail(str) {
    return str && str.indexOf('@') !== -1
  },

  /**
   * Read a Blob and handle a handler to handle it :)
   *
   * @param {Blob} blob
   * @param {function} handler
   * @returns {undefined}
   */
  readBlob(blob, handler) {
    const reader = new FileReader()
    reader.onload = handler
    reader.onerror = function(event) {
      handler(event)
    }
    reader.readAsArrayBuffer(blob)
  },

  /**
   * Read a File and handle a handler to handle it :)
   *
   * @param {File} file
   * @param {function} handler
   * @returns {undefined}
   */
  readFile(file, handler) {
    const size = parseInt(file.size)
    const meta = {
      id: null,
      uuid: null,
      name: KRYPTOS.utils.eURI(KRYPTOS.utils.cleanString(file.name)),
      // bytes: size,
      size,
      type: KRYPTOS.utils.eURI(KRYPTOS.utils.cleanString(file.type)),
      hmac: null,
      key: null,
      // bjFile: file
    }

    KRYPTOS.utils.readBlob(file, function() {
      const reader = this
      meta.id = KRYPTOS.uniqueFileId()
      handler(reader.result, meta)
    })
  },

  attachment(meta) {
    return {
      uuid: meta.uuid,
      name: meta.name,
      size: meta.size,
      type: meta.type,
      hmac: meta.hmac,
      key: meta.key,
      thumbnail: meta.thumbnail || null,
    }
  },

  validName(name) {
    return (
      name &&
      name !== '' &&
      KRYPTOS.utils.strpbrk(name, '\\/?%*:|\'"<>&;') === false
    ) // \, /, ?, %, *, :, |, ', &quot;, &lt;, &gt;, &amp; and ;
  },

  strpbrk(haystack, charList) {
    for (let i = 0; i < haystack.length; ++i) {
      if (charList.indexOf(haystack.charAt(i)) >= 0) {
        return haystack.slice(i)
      }
    }
    return false
  },

  ucwords(str) {
    return str.replace(
      /\w\S*/g,
      txt => txt.charAt(0).toUpperCase() + txt.substr(1).toLowerCase(),
    )
  },

  /**
   * I dont really like this function, but seems to be necessary for JavaScript
   * to handle JSON from a string correctly.
   *
   * @param {type} json
   * @returns {Array|Object}
   */
  formatJson(json) {
    $('#textarea').html(json)
    const formattedJson = JSON.parse($('#textarea').html())
    return formattedJson
  },

  escapeHTML(s) {
    const entityMap = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      '\'': '&#39;',
      '/': '&#x2F;',
    }
    return String(s).replace(/[&<>"'\/]/g, s => entityMap[s])
    // return s.toString().replace(/</g, "&lt;").replace(/>/g, "&gt;");
  },

  escapeHTML2(s) {
    if (s) {
      s = s
        .replace(/&amp;/g, '&')
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
      return s
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
    }
    return ''
  },

  dot2us(s) {
    return s.toString().replace('.', '_')
  },

  safeOpen(click) {
    console.log('safeOpen')
    const url = click.attr('href')
    const win = window.open(url, '_blank')
    win.focus()
    win.opener = null // Certain phishing attacks prevention
  },

  cleanString(s, strict) {
    if (s === null) return s
    let regex = null
    if (strict) {
      regex = /\<|\>|\"|\'|\%|\;|\(|\)|\&|\+|\-/g
    } else {
      regex = /\<|\>|\"|\'|\%|\;|\&/g
    }
    return `${s}`.replace(regex, '')
  },

  ba2dataUrl(byteArray) {
    let binaryString = ''
    for (let i = 0; i < byteArray.byteLength; i++) {
      binaryString += String.fromCharCode(byteArray[i])
    }
    return `data:application/octet-stream;base64,${btoa(binaryString)}`
  },

  escapeJson(s) {
    return s
      .replace(/\r?\n/g, '\\n')
      .replace(/"/g, '"')
      .replace(/'/g, '\'')
      .replace(/“/g, '“')
      .replace(/”/g, '”')
      .replace(/’/g, '’')
  },

  unescapeJson(s) {
    if (s) {
      return s
        .replace(/\\n/g, '<br />')
        .replace(/\"/g, '"')
        .replace(/\'/g, '\'')
        .replace(/\“/g, '“')
        .replace(/\”/g, '”')
        .replace(/\’/g, '’')
    }
    return ''
  },

  sanitize(sanitizer, content) {
    const parsed = $('<div></div>')
    parsed.append($.trim(content))
    let sanitized = null
    $.each(parsed, (i, el) => {
      if (el.childNodes && el.childNodes.length > 0) {
        sanitized = sanitizer.clean_node(parsed[i])
      }
    })
    const div = document.createElement('div')
    if (sanitized) {
      div.appendChild(sanitized.cloneNode(true))
    }
    return div.innerHTML
  },

  hasImgUrls(content) {
    return content.indexOf('disabled-src="') !== -1
  },

  isType(type, isMatch) {
    if (type) {
      return type.match(isMatch)
    }
    return false
  },

  isSupportedImage(type) {
    // return isType(type, /^image\//) && !isType(type, /tiff/);
    return (
      KRYPTOS.utils.isType(type, /^image\/jpeg/) ||
      KRYPTOS.utils.isType(type, /^image\/gif/) ||
      KRYPTOS.utils.isType(type, /^image\/png/)
    )
  },

  isImage(type) {
    // return isType(type, /^image\//) && !isType(type, /tiff/);
    return KRYPTOS.utils.isType(type, /^image\//)
  },

  isVideo(type) {
    return KRYPTOS.utils.isType(type, /^video\//)
  },

  isAudio(type) {
    return KRYPTOS.utils.isType(type, /^audio\//)
  },

  isPdf(type) {
    return KRYPTOS.utils.isType(type, /^application\/pdf/)
  },

  /**
   * Converts BigInteger hex to base64 from ArrayBuffer
   *
   * @param {type} bigInteger
   * @returns {String}
   */
  bi2b64(bigInteger) {
    return KRYPTOS.utils.d2b64(
      KRYPTOS.utils.hex2ab(bigInteger.toString(16)),
      true,
    )
  },

  d2b64(data, base64Url) {
    let output = ''
    if (data.pop || data.subarray) {
      data = String.fromCharCode.apply(null, data)
    }
    output = btoa(data)
    if (base64Url) {
      return output
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/\=/g, '')
    }
    return output
  },

  /**
   * Converts an ArrayBuffer to a string of hexadecimal numbers.
   *
   * @param {ArrayBuffer} arrayBuffer
   * @returns {String}
   */
  ab2hex(arrayBuffer) {
    const byteArray = new Uint8Array(arrayBuffer)
    let hexString = ''
    let nextHexByte

    for (let i = 0; i < byteArray.byteLength; i++) {
      nextHexByte = byteArray[i].toString(16) // Integer to base 16
      if (nextHexByte.length < 2) {
        nextHexByte = `0${nextHexByte}` // Otherwise 10 becomes just a instead of 0a
      }
      hexString += nextHexByte
    }
    return hexString
  },

  /**
   * Converts a hexadecimal number string to an ArrayBuffer.
   *
   * @param {String} hexString
   * @returns {ArrayBuffer}
   */
  hex2ab(hexString) {
    if (hexString.length % 2 !== 0) {
      // throw Error("Must have an even number of hex digits to convert to bytes");
      hexString = `0${hexString}`
    }
    const numBytes = hexString.length / 2
    const byteArray = new Uint8Array(numBytes)
    for (let i = 0; i < numBytes; i++) {
      byteArray[i] = parseInt(hexString.substr(i * 2, 2), 16)
    }
    return byteArray
  },

  /**
   * Converts an ArrayBuffer to a String.
   *
   * @param {ArrayBuffer} buf
   * @returns {String}
   */
  ab2str(buf) {
    let str = ''
    const byteArray = new Uint8Array(buf)
    for (let i = 0; i < byteArray.length; i++) {
      str += String.fromCharCode(byteArray[i])
    }
    return str
  },

  /**
   * Converts a String to an ArrayBuffer.
   *
   * @param {type} str
   * @returns {ArrayBuffer}
   */
  str2ab(str) {
    const buf = new ArrayBuffer(str.length)
    const bufView = new Uint8Array(buf)
    for (let i = 0, strLen = str.length; i < strLen; i++) {
      bufView[i] = str.charCodeAt(i)
    }
    return buf
  },

  /**
   * Converts an ArrayBuffer to a String.
   *
   * @param {ArrayBuffer} buf
   * @param {boolean} base64Url
   * @returns {String}
   */
  ab2b64(buf, base64Url) {
    let data = ''
    if (buf === '') {
      return ''
    }
    const byteArray = new Uint8Array(buf)
    for (let i = 0; i < byteArray.length; i++) {
      data += String.fromCharCode(byteArray[i])
    }
    const output = btoa(data)
    if (base64Url) {
      return output
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/\=/g, '')
    }
    return output
  },

  b642ab(base64, base64Url) {
    if (base64Url) {
      base64 = base64
        .replace(/\-/g, '+')
        .replace(/\_/g, '/')
        .replace(/\=/g, '')
    }
    if (!base64) {
      base64 = ''
    }
    const binaryString = window.atob(base64)
    const len = binaryString.length
    const bytes = new Uint8Array(len)
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i)
    }
    return bytes.buffer
  },

  b642str(base64) {
    return KRYPTOS.utils.ab2str(KRYPTOS.utils.b642ab(base64))
  },

  hex2b64(hex, base64Url) {
    return KRYPTOS.utils.ab2b64(KRYPTOS.utils.hex2ab(hex), base64Url)
  },

  b642hex(base64, base64Url) {
    return KRYPTOS.utils.ab2hex(
      KRYPTOS.utils.b642ab(base64, base64Url),
      base64Url,
    )
  },

  /**
   * Convert a JWK to an ArrayBuffer.
   *
   * @param {JWK} jwk
   * @returns {ArrayBuffer}
   */
  jwk2ab(jwk) {
    return KRYPTOS.utils.str2ab(JSON.stringify(jwk))
  },

  /**
   * Convert ArrayBuffer to JWK.
   *
   * @param {ArrayBuffer} ab
   * @returns {JWK}
   */
  ab2jwk(ab) {
    const str = KRYPTOS.utils.ab2str(ab)
    return JSON.parse(str)
  },

  /**
   * Convert ArrayBuffer to JSON.
   *
   * @param {ArrayBuffer} ab
   * @returns {JSON}
   */
  ab2json(ab) {
    const sab = KRYPTOS.utils.ab2str(ab)
    if (sab === null || sab === '') {
      return JSON.parse('{}')
    }
    return JSON.parse(KRYPTOS.utils.ab2str(ab))
    //        return KRYPTOS.utils.formatJson((KRYPTOS.utils.ab2str(ab)));
  },

  /**
   * Converts a base64 encoded JSON object to a Javascript object
   * @param {atring} base64
   * @returns {Object}
   */
  b642obj(base64) {
    const str = window.atob(base64)
    return JSON.parse(str)
  },

  obj2b64(obj) {
    const str = JSON.stringify(obj)
    return window.btoa(str)
  },

  /**
   * Convert dataURL to blob
   *
   * @param {type} dataurl
   * @returns {Blob}
   */
  du2b(dataurl) {
    let arr = dataurl.split(','),
      mime = arr[0].match(/:(.*?);/)[1],
      bstr = atob(arr[1]),
      n = bstr.length,
      u8arr = new Uint8Array(n)
    while (n--) {
      u8arr[n] = bstr.charCodeAt(n)
    }
    return new Blob([u8arr], { type: mime })
  },

  byteLength(publicKey) {
    const ab = KRYPTOS.utils.b642ab(publicKey.n, true)
    return new Uint8Array(ab).length
  },

  bitLength(publicKey) {
    return KRYPTOS.utils.byteLength(publicKey) * 8
  },

  /**
   * Convert Blob to dataUrl.
   *
   * @param {type} blob
   * @param {type} callback
   * @returns {undefined}
   */
  b2du(blob, callback) {
    const a = new FileReader()
    a.onload = function(e) {
      callback(e.target.result)
    }
    a.readAsDataURL(blob)
  },

  aesKey2Jwk(key, extractable) {
    let dataType = Object.prototype.toString.call(key)
    dataType = dataType.substring(8, dataType.length - 1)
    let k = null
    if (dataType === 'String') {
      k = KRYPTOS.utils.hex2ab(key)
    } else {
      k = key
    }
    const jwk = {
      alg: 'A256CBC',
      extractable, // MS
      ext: extractable, // Web Crypto API
      k: KRYPTOS.utils.d2b64(k, true),
      kty: 'oct',
    }
    return JSON.stringify(jwk)
  },

  rsaJwk(jwk) {
    return {
      alg: jwk.alg,
      e: jwk.e,
      // ext: jwk.ext || true,
      key_ops: jwk.key_ops,
      kty: jwk.kty,
      n: jwk.n,
    }
  },

  ecJwk(jwk) {
    return {
      crv: jwk.crv,
      // ext: jwk.ext || true,
      key_ops: jwk.key_ops,
      kty: jwk.kty,
      x: jwk.x,
      y: jwk.y,
    }
  },

  intermediateAesKey2Jwk(key, extractable) {
    let dataType = Object.prototype.toString.call(key)
    dataType = dataType.substring(8, dataType.length - 1)
    let k = null
    if (dataType === 'String') {
      k = KRYPTOS.utils.hex2ab(key)
    } else {
      k = key
    }
    const jwk = {
      alg: 'A256CBC',
      extractable, // MS
      ext: extractable, // Web Crypto API
      k: KRYPTOS.utils.d2b64(k, true),
      key_ops: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'],
      kty: 'oct',
    }
    return JSON.stringify(jwk)
  },

  hmacKey2Jwk(key, extractable) {
    let dataType = Object.prototype.toString.call(key)
    dataType = dataType.substring(8, dataType.length - 1)
    let k = null
    if (dataType === 'String') {
      k = KRYPTOS.utils.hex2ab(key)
    } else {
      k = key
    }
    const jwk = {
      alg: 'HS256',
      extractable, // MS
      ext: extractable, // Web Crypto API
      k: KRYPTOS.utils.d2b64(k, true),
      kty: 'oct',
    }
    return JSON.stringify(jwk)
  },

  /**
   * Converts Arrays, ArrayBuffers, TypedArrays, and Strings to to either a
   * Uint8Array or a regular Array depending on browser support.
   * You should use this when passing byte data in or out of crypto functions.
   *
   * @param {mixed} data
   * @returns {Uint8Array|Array}
   */
  toSupportedArray(data) {
    // does this browser support Typed Arrays?
    const typedArraySupport = typeof Uint8Array !== 'undefined'

    // get the data type of the parameter
    let dataType = Object.prototype.toString.call(data)
    dataType = dataType.substring(8, dataType.length - 1)

    // determine the type
    switch (dataType) {
      // Regular JavaScript Array. Convert to Uint8Array if supported
      // else do nothing and return the array
      case 'Array':
        return typedArraySupport ? new Uint8Array(data) : data

      // ArrayBuffer. IE11 Web Crypto API returns ArrayBuffers that you have to convert
      // to Typed Arrays. Convert to a Uint8Arrays and return;
      case 'ArrayBuffer':
        return new Uint8Array(data)

      // Already Uint8Array. Obviously there is support.
      case 'Uint8Array':
        return data

      case 'Uint16Array':
      case 'Uint32Array':
        return new Uint8Array(data)

      // String. Convert the string to a byte array using Typed Arrays if
      // supported.
      case 'String':
        const newArray = typedArraySupport
          ? new Uint8Array(data.length)
          : new Array(data.length)
        for (let i = 0; i < data.length; i += 1) {
          newArray[i] = data.charCodeAt(i)
        }
        return newArray

      // Some other type. Just return the data unchanged.
      default:
        throw new Error(`toSupportedArray : unsupported data type ${dataType}`)
    }
  },

  bytesToSize(bytes) {
    if (bytes === 0) return '0 Bytes'
    const k = 1000
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return `${(bytes / Math.pow(k, i)).toPrecision(3)} ${sizes[i]}`
  },

  /**
   * Send JSON data.
   *
   * @param {type} json
   * @param {type} resource
   * @param {type} callback
   * @returns {void}
   */
  sendJson(json, resource, callback) {
    if (resource !== 'node') {
      json._token = Token.getToken()
    }
    return $.ajax({
      url: `/${resource}`,
      type: 'POST',
      data: JSON.stringify(json),
      dataType: 'json',
      contentType: 'application/json; charset=UTF-8',
      success(response) {
        if (response._token) {
          $('meta[name=_token]').attr('content', response._token)
          KRYPTOS.session.setItem('_token', response._token)
          document.dispatchEvent(new Event('onresettoken'))
        }
        if (callback) {
          callback(true, response)
        }
      },
      error(jqXHR, textStatus, errorMessage) {
        if (jqXHR.status === 401) {
          return false
        }

        if (callback) {
          let response = ''
          try {
            response = $.parseJSON(jqXHR.responseText)
            callback(false, response)
          } catch (error) {
            //                        callback(false, {error: response});
          }
        }
      },
    })
  },

  getJson(params, resource, callback) {
    const queryString = params ? `?${$.param(params)}` : ''
    const jqxhr = $.getJSON(`/${resource}${queryString}`, data => {
      callback(true, data)
    })
    jqxhr.fail(error => {
      callback(false, $.parseJSON(jqxhr.responseText))
    })
  },

  timestamp(unixTimestamp) {
    return `${new Date(unixTimestamp).toDateString()} ${new Date(
      unixTimestamp,
    ).toLocaleTimeString()}`
  },

  localDateTime(timestamp) {
    return `${new Date(timestamp).toLocaleDateString()} ${new Date(
      timestamp,
    ).toLocaleTimeString()}`
  },

  ua2ea(u) {
    const emails = []
    for (let i = 0; i < u.length; i++) {
      emails[i] = this.u2e(u[i])
    }
    return emails
  },

  ea2ue(e) {
    const usernames = []
    for (let i = 0; i < e.length; i++) {
      usernames[i] = this.e2u(e[i])
    }
    return usernames
  },

  e2u(e) {
    if (!e) {
      return ''
    }
    return KRYPTOS.utils.escapeHTML(e.replace(/@.*/gi, '')) // .toLowerCase();
  },

  id2fid(id) {
    return `${id}@${KRYPTOS.session.getItem('chat_host')}`
  },

  rid2fid(rid) {
    if (rid.indexOf('@') !== -1) {
      return rid
    }
    return `${rid}@${KRYPTOS.session.getItem('group_chat_host')}`
  },

  eName2u(e) {
    const myArr = /^.+\<(.+)\>/.exec(e)
    if (myArr && myArr[1]) {
      return KRYPTOS.utils.e2u(myArr[1])
    }
    return KRYPTOS.utils.e2u(e)
  },

  formatEmails(emails) {
    let formatted = ''
    if (emails) {
      for (let i = 0; i < emails.length; i++) {
        if (emails.length - 1 === i) {
          formatted += `${emails[i]}`
        } else {
          formatted += `${emails[i]}, `
        }
      }
    }
    return formatted
  },

  isItAnEmail(NameEmail) {
    let email = KRYPTOS.utils.extractEmailFromFullName(NameEmail)
    if (!email) email = NameEmail
    // let re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    const re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
    return re.test(email)
  },

  extractEmailFromFullName(text) {
    const myArr = /^.+\<(.+)\>/.exec(text)
    if (myArr && myArr[1]) {
      return $.trim(myArr[1])
    }
    return text
  },

  extractUsernameFromFullName(text) {
    const myArr = /^.+\@(.+)/.exec(text)
    if (myArr && myArr[1]) {
      return $.trim(myArr[1])
    }
    return text
  },

  extractDisplayNameFromFullName(text) {
    const myArr = /^(.+)\s?\<.+\>/.exec(text)
    if (myArr && myArr[1]) {
      if ($.trim(myArr[1]) === '') {
        return KRYPTOS.utils.extractEmailFromFullName(text)
      }
      return $.trim(myArr[1])
    }
    return text
  },

  mixed2ab(data, callback) {
    const mixed = []
    for (const prop in data) {
      mixed.push(prop)
      mixed.push(data[prop])
    }
    const blob = new Blob(mixed, { type: 'application/octet-stream' })
    KRYPTOS.utils.readBlob(blob, function() {
      const reader = this
      callback(reader.result)
    })
  },

  joinBuffers(buffer1, buffer2) {
    const tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength)
    tmp.set(new Uint8Array(buffer1), 0)
    tmp.set(new Uint8Array(buffer2), buffer1.byteLength)
    return tmp.buffer
  },

  getNodePvk() {
    const keys = KRYPTOS.session.getItem('nodeKeys')
    return JSON.parse(keys).verify
  },

  getNodePek() {
    const keys = KRYPTOS.session.getItem('nodeKeys')
    return JSON.parse(keys).encrypt
  },

  getNodeKeys() {
    return KRYPTOS.session.getItem('nodeKeys')
  },

  setNodeKeys(nodeKeys) {
    KRYPTOS.session.setItem('nodeKeys', nodeKeys)
  },

  /**
   * Send a Blob file to the server.
   *
   * @param {Object} data
   * @param {String} resource
   * @param {function} callback
   * @param {function} uploadCallback
   * @returns {void}
   */
  sendData(data, resource, callback, uploadCallback) {
    const fd = new FormData()
    data._token = Token.getToken()
    if (data) {
      for (const prop in data) {
        if (data.hasOwnProperty(prop)) {
          fd.append(prop, data[prop])
        }
      }
    }
    const url = `/${resource}`
    return $.ajax({
      url,
      type: 'POST',
      data: fd,
      cache: false,
      processData: false,
      contentType: false,
      success(response) {
        if (response._token) {
          $('meta[name=_token]').attr('content', response._token)
          KRYPTOS.session.setItem('_token', response._token)
          Token.resetToken()
        }
        if (callback) {
          callback(true, response)
        }
      },
      xhr() {
        // Custom XMLHttpRequest
        const myXhr = $.ajaxSettings.xhr()
        if (myXhr.upload) {
          // Check if upload property exists
          myXhr.upload.addEventListener('progress', uploadCallback, false) // For handling the progress of the upload
        }
        return myXhr
      },
      error(jqXHR, textStatus, errorMessage) {
        if (callback) {
          let response = ''
          try {
            response = $.parseJSON(jqXHR.responseText)
            callback(false, response)
          } catch (error) {
            callback(false, { error: response })
          }
        }
      },
    })
  },

  uploadFile(data, resource, type) {
    const fd = new FormData()
    data._token = Token.getToken()
    if (data) {
      for (const prop in data) {
        if (data.hasOwnProperty(prop)) {
          fd.append(prop, data[prop])
        }
      }
    }
    const url = `/${resource}/${type}`
    return $.ajax({
      url,
      type: 'POST',
      data: fd,
      cache: false,
      processData: false,
      contentType: false,
    })
  },

  isEmpty(obj) {
    if (KRYPTOS.utils.isObject(obj)) {
      return obj === null || obj === undefined || Object.keys(obj).length === 0
    }
    return false

    // return obj === null || obj === undefined || Object.keys(obj).length === 0;
  },

  isObject(obj) {
    return typeof obj === 'object'
  },

  arr2obj(arr) {
    return Object.assign({}, arr)
  },

  encodeURI(str) {
    if (str === null) {
      return null
    }
    if (str === '') {
      return str
    }
    return encodeURIComponent(str)
  },

  eURI(str) {
    return KRYPTOS.utils.encodeURI(str)
  },

  decodeURIComp(sanitizer, str, type) {
    if (str === '' || str === null) {
      return ''
    }
    try {
      if (type === 'subj' || type === 'system') {
        return decodeURIComponent(str)
      }
      return KRYPTOS.utils.sanitize(sanitizer, decodeURIComponent(str), true)
    } catch (error) {
      if (type === 'subj' || type === 'system') {
        return unescape(str)
      }
      return KRYPTOS.utils.sanitize(sanitizer, unescape(str), true)
    }
  },

  dURI(str) {
    if (str === '' || str === null) {
      return ''
    }
    try {
      return decodeURIComponent(str)
    } catch (error) {
      return unescape(str)
    }
  },
}

/**
 * KRYPTOS checks if the browser is supported based on the browser features.
 * The crypto support is defined here.
 *
 * @type type
 */
KRYPTOS.check = {
  UA: null,

  parseUA() {
    const parser = new UAParser()
    this.UA = parser.getResult()
  },

  support() {
    this.promiseSupport()
    //        this.msrCryptoSupport();
    //        return true;
    if (!this.cryptoSupport()) {
      this.msrCryptoSupport()
    }

    return true
  },

  indexedDBSupport() {
    return window.indexedDB
  },

  userMediaSupport() {
    return !!(
      navigator.getUserMedia ||
      navigator.webkitGetUserMedia ||
      navigator.mozGetUserMedia ||
      navigator.msGetUserMedia
    )
  },

  /**
   * User native browser Promises if the browser supports it else use the
   * Promise polyfill
   *
   * @returns {void}
   */
  promiseSupport() {
    KRYPTOS.Promise = window.Promise // || ES6Promise.Promise;
  },

  /**
   * Use Web Crypto API if the browser supports it.
   *
   * @returns {Boolean}
   */
  cryptoSupport() {
    KRYPTOS.crypto = window.crypto || window.msCrypto
    if (!KRYPTOS.crypto) {
      return false
    }
    if (window.crypto.webkitSubtle) {
      KRYPTOS.SF = true
    }
    KRYPTOS.cryptoSubtle = KRYPTOS.crypto.subtle || KRYPTOS.crypto.webkitSubtle
    if (!KRYPTOS.cryptoSubtle) {
      return false
    }
    return true
  },

  // Not used
  isNative() {
    if (window.msCrypto) {
      return true
    }
    return false
  },

  // not used
  forceNative() {
    return false
    // Try and force IE 11 old Web Crypto API implementation
    //        if (window.msCrypto) {
    //            KRYPTOS.crypto =  window.msCrypto;
    //            KRYPTOS.cryptoSubtle = KRYPTOS.crypto.subtle;
    //            return true;
    //        }
    // TODO: Try and force SF 7+ incompleted Web Crypto API implementation
  },

  resetMsrCryptoSupport() {
    KRYPTOS.crypto = window.msrCrypto
    KRYPTOS.cryptoSubtle = KRYPTOS.crypto.subtle
  },

  /**
   * Load in the MSR Crypto Library
   *
   * @returns {void}
   */
  msrCryptoSupport() {
    KRYPTOS.crypto = window.msrCrypto
    KRYPTOS.cryptoSubtle = KRYPTOS.crypto.subtle
    KRYPTOS.MSR = true
    // TODO: move to session storage.
    let E = KRYPTOS.session.getItem('_e') // Get some external entropy
    if (E) {
      E = KRYPTOS.utils.toSupportedArray(E)
      const entropy = []
      for (let i = 0; i < E.length; i += 1) {
        entropy.push(E[i])
      }
      KRYPTOS.crypto.initPrng(entropy)
    } else {
    }
  },
}

// KRYPTOS.perms = {
//
//    CHAT_EMAIL        : 1 << 0, // 00000001 (1)  Chat, Email, Contacts, Groups, App
//    CALLING           : 1 << 1, // 00000010 (2)  Calling dependency (1)
//    CALENDAR          : 1 << 2, // 00000100 (4)  Calendar
//    NOTES             : 1 << 3, // 00001000 (8)  Notes
//    FILE_STORAGE      : 1 << 4, // 00010000 (16) File Storage
//
//    userPerm : KRYPTOS.session.getItem('component_permissions'),
//
//    canChatEmail : function () {
//        if (!KRYPTOS.perms.userPerm) return false;
//        return KRYPTOS.perms.userPerm & KRYPTOS.perms.CHAT_EMAIL;
//    },
//
//    canCalling : function() {
//        if (!KRYPTOS.perms.userPerm) return false;
//        return KRYPTOS.perms.userPerm & KRYPTOS.perms.CALLING;
//    },
//
//    canCalendar : function() {
//        if (!KRYPTOS.perms.userPerm) return false;
//        return KRYPTOS.perms.userPerm & KRYPTOS.perms.CALENDAR;
//    },
//
//    canNotes : function() {
//        if (!KRYPTOS.perms.userPerm) return false;
//        return KRYPTOS.perms.userPerm & KRYPTOS.perms.NOTES;
//    },
//
//    canStorage : function() {
//        if (!KRYPTOS.perms.userPerm) return false;
//        return KRYPTOS.perms.userPerm & KRYPTOS.perms.FILE_STORAGE;
//    }
//
// };

// Load KRYPTOS when script is loaded.
// document.addEventListener("DOMContentLoaded", function() {
//    "use strict";
//    KRYPTOS.check.support();
// });
KRYPTOS.check.support()
