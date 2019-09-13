/* eslint-disable max-lines */
import { KRYPTOS } from './kryptos.core'
import {
  nonce,
  getKeyType,
  arrayBufferToHex,
  arrayBufferToBase64,
  stringToArrayBuffer,
  objectToArrayBuffer,
  base64ToArrayBuffer,
  arrayBufferToObject,
  ecJwk,
  rsaJwk,
} from '../kryptos/utils'
import { PROTECTOR_TYPES } from '../kryptos/constants'
import * as algorithms from '../kryptos/algorithms'
import * as formats from '../kryptos/formats'

/**
 * KRYPTOS is a cryptographic library wrapping and implementing the
 * Web Cryptography API. It supports both symmetric keys and asymmetric key pair
 * generation, encryption, decryption, signing and verification.
 *
 * @name KRYPTOS
 * @copyright Copyright © FortKnoxster Ltd. 2014 - 2019.
 * @license Apache License, Version 2.0 http://www.apache.org/licenses/LICENSE-2.0
 * @author MJ <mj@fortknoxster.com>
 * @version 4.0
 */

/**
 * The KRYPTOS KeyStore module.
 *
 * @param {String} serviceType
 * @param {Object} containerPDK
 * @param {Object} containerPSK
 */
export const KeyStore = function KeyStore(
  serviceType,
  containerPDK,
  containerPSK,
  keyMode,
) {
  const KU = KRYPTOS.utils
  const service = serviceType

  /**
   * Can be RSA or EC. Determines whether RSA keypairs or EC keypairs are
   * being used for this key store. Default is RSA.
   */
  let mode = keyMode || algorithms.RSA

  const publicKeyPrefix = `${service}:pub:`

  const prefixPDK = `${service}:pdk:kc`

  const prefixPSK = `${service}:psk:kc`

  const prefixPEK = `${service}:pek`

  const prefixPVK = `${service}:pvk`

  const prefixIAKPDK = `${service}:pdk:iak`

  const prefixIAKPSK = `${service}:psk:iak`

  let encryptKeyPair = null

  let signKeyPair = null

  let wrappedPDK = null

  let wrappedPSK = null

  let ivPDK = null

  let ivPSK = null

  let exportedPublicEncryptKey = null

  let exportedPublicVerifyKey = null

  let IAKPSK = null // Intermediate key for protecting the PSK

  let IAKPDK = null // Intermediate key for protecting the PDK

  let wrappedIAKPSK = null

  let wrappedIAKPDK = null

  let cachedPSK = null

  let cachedPDK = null

  let keyContainerPDK = containerPDK

  let keyContainerPSK = containerPSK

  let importedPassword = null

  let derivedKey = null

  let deriveKeyAlgo = null

  const setMode = keyStoreMode => {
    switch (keyStoreMode) {
      case 'RSA':
      case 'EC':
        break
      default:
        throw new Error('Invalid algorithm3')
    }
    mode = keyStoreMode
  }

  const getMode = () => mode

  const isEC = () => mode === 'EC'

  const isRSA = () => mode === 'RSA'

  const isLoaded = () => (ivPDK && ivPSK && wrappedPDK && wrappedPSK) !== null

  const generateIAK = () =>
    KRYPTOS.cryptoSubtle.generateKey(
      algorithms.AES_GCM_ALGO,
      KRYPTOS.EXTRACTABLE,
      KRYPTOS.WRAP_USAGE.concat(KRYPTOS.ENCRYPT_USAGE),
    )

  const saveIAKPSK = iak => {
    IAKPSK = iak
  }

  const saveIAKPDK = iak => {
    IAKPDK = iak
  }

  const extractKeyProtector = (keyType, protectorType) => {
    let protectors = null
    if (keyType === 'PDK') {
      if (keyContainerPDK.keyProtectors) {
        protectors = keyContainerPDK.keyProtectors
      } else {
        throw new Error('Missing key protector.')
      }
    } else if (keyType === 'PSK') {
      if (keyContainerPSK.keyProtectors) {
        protectors = keyContainerPSK.keyProtectors
      } else {
        throw new Error('Missing key protector.')
      }
    } else {
      throw new Error('Invalid key type.')
    }
    const index = protectors.findIndex(
      protector => protector.type === protectorType,
    )
    if (index === -1) {
      throw new Error(`No key protector found for ${protectorType}.`)
    }
    return protectors[index]
  }

  const storeKeys = (pek, pvk, signature) => {
    if (keyContainerPDK) {
      KRYPTOS.session.setItem(prefixPDK, JSON.stringify(keyContainerPDK))
    }
    if (keyContainerPSK) {
      KRYPTOS.session.setItem(prefixPSK, JSON.stringify(keyContainerPSK))
    }
    const publicKeys = {}
    if (pek) {
      KRYPTOS.session.setItem(prefixPEK, JSON.stringify(pek))
      publicKeys.encrypt = pek
    }
    if (pvk) {
      KRYPTOS.session.setItem(prefixPVK, JSON.stringify(pvk))
      publicKeys.verify = pvk
    }
    if (signature) {
      publicKeys.signature = signature
    }

    KRYPTOS.session.setItem(
      publicKeyPrefix + KRYPTOS.session.getItem('id'),
      JSON.stringify(publicKeys),
    )
  }

  const packageKeyContainers = signedKeys =>
    new Promise(resolve => {
      const data = {}
      data[service] = {
        pdk: keyContainerPDK,
        psk: keyContainerPSK,
        pek: exportedPublicEncryptKey,
        pvk: exportedPublicVerifyKey,
        signature: signedKeys.signature,
      }
      storeKeys(
        exportedPublicEncryptKey,
        exportedPublicVerifyKey,
        signedKeys.signature,
      )
      resolve(data)
    })

  const packageSignKeyContainer = hash =>
    new Promise(resolve => {
      const data = {}
      data[service] = {
        psk: keyContainerPSK,
        pvk: exportedPublicVerifyKey,
        fingerprint: arrayBufferToHex(hash),
      }
      storeKeys(null, exportedPublicVerifyKey)
      resolve(data)
    })

  const packageEncryptKeyContainer = () =>
    new Promise(resolve => {
      const data = {}
      data[service] = {
        pdk: keyContainerPDK,
        pek: exportedPublicEncryptKey,
      }
      resolve(data)
    })

  const signPublicKeys = identity => {
    const publicKeys = {
      pek: isEC()
        ? ecJwk(exportedPublicEncryptKey)
        : rsaJwk(exportedPublicEncryptKey),
      pvk: isEC()
        ? ecJwk(exportedPublicVerifyKey)
        : rsaJwk(exportedPublicVerifyKey),
    }
    return new Promise((resolve, reject) => {
      const Encrypter = new KRYPTOS.Encrypter(
        identity,
        null,
        null,
        (success, signedKeys) => {
          if (!success) {
            reject()
          } else {
            resolve(signedKeys)
          }
        },
      )
      Encrypter.signIt(publicKeys, true)
    })
  }

  /**
   * Generate the signing key pair using the RSASSA-PKCS1-v1_5 or the ECDSA algorithm.
   *
   * @returns {Promise} of generateKey
   */
  const generateSigningKeyPair = () => {
    if (isEC()) {
      return KRYPTOS.cryptoSubtle.generateKey(
        algorithms.ECDSA_ALGO,
        KRYPTOS.EXTRACTABLE,
        KRYPTOS.SIGN_USAGE,
      )
    }
    return KRYPTOS.cryptoSubtle.generateKey(
      algorithms.RSASSA_PKCS1_V1_5_ALGO,
      KRYPTOS.EXTRACTABLE,
      KRYPTOS.SIGN_USAGE,
    )
  }

  /**
   * Generate the encryption key pair using the RSA OAEP or the ECDH algorithm.
   *
   * @returns {Promise} of generateKey
   */
  const generateEncryptionKeyPair = () => {
    if (isEC()) {
      return KRYPTOS.cryptoSubtle.generateKey(
        algorithms.ECDH_ALGO,
        KRYPTOS.EXTRACTABLE,
        KRYPTOS.DERIVE_USAGE,
      )
    }
    return KRYPTOS.cryptoSubtle.generateKey(
      algorithms.RSA_OAEP_ALGO,
      KRYPTOS.EXTRACTABLE,
      KRYPTOS.ENCRYPT_USAGE.concat(KRYPTOS.WRAP_USAGE),
    )
  }

  /**
   * Save the signing key pair.
   *
   * @param {raw} keyPair
   * @returns {void}
   */
  const saveSigningKeyPair = keyPair => {
    signKeyPair = keyPair
    cachedPSK = signKeyPair.privateKey
  }

  /**
   * Save the encryption key pair.
   *
   * @param {raw} keyPair
   * @returns {void}
   */
  const saveEncryptionKeyPair = keyPair => {
    encryptKeyPair = keyPair
    cachedPDK = encryptKeyPair.privateKey
  }

  /**
   * Wrap the private decryption key.
   *
   * @returns {unresolved}
   */
  const wrapPDK = () =>
    KRYPTOS.cryptoSubtle.wrapKey(
      formats.JWK,
      encryptKeyPair.privateKey,
      IAKPDK,
      {
        name: algorithms.AES_GCM.name,
        iv: ivPDK,
      },
    )

  /**
   * Wrape the private sign key.
   *
   * @returns {Promise} of wrapKey
   */
  const wrapPSK = () =>
    KRYPTOS.cryptoSubtle.wrapKey(formats.JWK, signKeyPair.privateKey, IAKPSK, {
      name: algorithms.AES_GCM.name,
      iv: ivPSK,
    })

  const addPasswordProtector = (
    keyContainer,
    wrappedKey,
    typeProtector = PROTECTOR_TYPES.password,
  ) => {
    if (!keyContainer) {
      return
    }
    keyContainer.keyProtectors.push({
      encryptedKey: arrayBufferToBase64(wrappedKey),
      type: typeProtector,
      name: deriveKeyAlgo.name,
      salt: arrayBufferToBase64(deriveKeyAlgo.salt),
      iterations: deriveKeyAlgo.iterations,
      hash: deriveKeyAlgo.hash,
    })
  }

  const addAsymmetricProtector = (keyContainer, wrappedKey) => {
    keyContainer.keyProtectors.push({
      encryptedKey: arrayBufferToBase64(wrappedKey),
      type: 'asymmetric',
      name: deriveKeyAlgo.name,
    })
  }

  const addProtector = (keyContainer, wrappedKey) => {
    if (derivedKey.type === 'public') {
      addAsymmetricProtector(keyContainer, wrappedKey)
    } else {
      addPasswordProtector(keyContainer, wrappedKey)
    }
  }

  const saveWrappedPDK = wrappedKey => {
    if (keyContainerPDK === null) {
      keyContainerPDK = {
        encryptedKey: null,
        iv: arrayBufferToBase64(ivPDK),
        keyType: getKeyType(mode, 'PDK'),
        protectType: 'AES-GCM-256',
        keyProtectors: [],
      }
      addProtector(keyContainerPDK, wrappedIAKPDK)
    }
    keyContainerPDK.encryptedKey = arrayBufferToBase64(wrappedKey)
  }

  const saveWrappedPSK = wrappedKey => {
    if (keyContainerPSK === null) {
      keyContainerPSK = {
        encryptedKey: null,
        iv: arrayBufferToBase64(ivPSK),
        keyType: getKeyType(mode, 'PSK'),
        protectType: 'AES-GCM-256',
        keyProtectors: [],
      }
      addPasswordProtector(keyContainerPSK, wrappedIAKPSK)
    }
    keyContainerPSK.encryptedKey = arrayBufferToBase64(wrappedKey)
  }

  const unwrapIAK = (wrappedKey, algo) => {
    const usage = KRYPTOS.WRAP_USAGE.concat(KRYPTOS.ENCRYPT_USAGE)
    if (derivedKey.type === 'private') {
      return KRYPTOS.cryptoSubtle
        .decrypt({ name: derivedKey.algorithm.name }, derivedKey, wrappedKey)
        .then(keyBytes =>
          KRYPTOS.cryptoSubtle.importKey(
            formats.RAW,
            keyBytes,
            KRYPTOS.getAlgo(algo),
            KRYPTOS.EXTRACTABLE,
            usage,
          ),
        )
    }
    return KRYPTOS.cryptoSubtle.unwrapKey(
      formats.RAW,
      wrappedKey,
      derivedKey,
      algorithms.AES_KW,
      { name: algo },
      KRYPTOS.EXTRACTABLE,
      usage,
    )
  }

  const exportIAK = key => KRYPTOS.cryptoSubtle.exportKey(formats.JWK, key)

  const wrapIAKPSK = key =>
    KRYPTOS.cryptoSubtle.wrapKey(
      formats.RAW,
      IAKPSK || key,
      derivedKey,
      algorithms.AES_KW,
    )

  const saveWrappedIAKPSK = wrappedKey => {
    wrappedIAKPSK = wrappedKey
  }

  const wrapIAKPDK = key => {
    if (derivedKey.type === 'public') {
      return KRYPTOS.cryptoSubtle
        .exportKey(formats.RAW, IAKPDK || key)
        .then(exportedKey =>
          KRYPTOS.cryptoSubtle.encrypt(
            derivedKey.algorithm,
            derivedKey,
            exportedKey,
          ),
        )
    }
    return KRYPTOS.cryptoSubtle.wrapKey(
      formats.RAW,
      IAKPDK || key,
      derivedKey,
      algorithms.AES_KW,
    )
  }

  const saveWrappedIAKPDK = wrappedKey => {
    wrappedIAKPDK = wrappedKey
  }

  // TODO
  const replacePasswordProtector = (keyContainer, type, wrappedKey) => {
    let updated = false

    const index = keyContainer.keyProtectors.findIndex(
      protector => protector.type === type,
    )
    if (index !== -1) {
      // eslint-disable-next-line no-param-reassign
      keyContainer.keyProtectors[index] = {
        encryptedKey: arrayBufferToBase64(wrappedKey),
        type,
        name: deriveKeyAlgo.name,
        salt: arrayBufferToBase64(deriveKeyAlgo.salt),
        iterations: deriveKeyAlgo.iterations,
        hash: deriveKeyAlgo.hash,
      }
      updated = true
    }
    if (!updated) {
      if (type === PROTECTOR_TYPES.recovery) {
        addPasswordProtector(keyContainer, wrappedKey, type)
      } else {
        throw new Error(`No key protector found for ${type} to updated.`)
      }
    }
  }

  const saveImportedPassword = password => {
    importedPassword = password
    return importedPassword
  }

  const deriveKey = key =>
    KRYPTOS.cryptoSubtle.deriveKey(
      deriveKeyAlgo,
      key,
      KRYPTOS.AES_KW_ALGO,
      KRYPTOS.NONEXTRACTABLE,
      KRYPTOS.WRAP_USAGE,
    )

  const saveDerivedKey = key => {
    derivedKey = key
  }

  const importPassword = password =>
    KRYPTOS.cryptoSubtle
      .importKey(
        formats.RAW,
        stringToArrayBuffer(password),
        algorithms.PBKDF2,
        false,
        KRYPTOS.DERIVE_USAGE,
      )
      .then(saveImportedPassword)
      .then(deriveKey)
      .then(saveDerivedKey)
      .catch(error => {
        console.error(error)
      })

  const importPek = (publicKey, usages) => {
    let { alg } = publicKey
    if (publicKey.kty === 'EC') {
      alg = 'ECDH'
      // eslint-disable-next-line no-param-reassign
      delete publicKey.alg
      // eslint-disable-next-line no-param-reassign
      delete publicKey.key_ops
    }
    const algo = KRYPTOS.getAlgo(alg)
    return KRYPTOS.cryptoSubtle.importKey(
      formats.JWK,
      publicKey,
      algo,
      false,
      usages,
    )
  }

  const setDeriveKeyAlgo = algo => {
    deriveKeyAlgo = algo
  }

  const deriveKeyFromAsymmetric = (keyStore, username) => {
    setDeriveKeyAlgo(KRYPTOS.RSA_OAEP_ALGO)
    let operation = null
    if (username) {
      operation = keyStore
        .getPublicKey(username, 'encrypt')
        .then(pKey => importPek(pKey, ['encrypt']))
    } else {
      operation = keyStore.getPek()
    }

    return operation.then(saveDerivedKey).catch(error => {
      console.error(error)
    })
  }

  const deriveKeyFromPassword = password => {
    setDeriveKeyAlgo({
      name: algorithms.PBKDF2.name,
      salt: KRYPTOS.randomValue(32),
      iterations: 20000,
      hash: algorithms.SHA_256.name,
    })
    return importPassword(password)
  }

  const importAsymmetric = keyStore =>
    keyStore
      .getPdk()
      .then(saveDerivedKey)
      .catch(error => {
        console.error(error)
      })

  const importDerivedKey = derivedPassword =>
    KRYPTOS.cryptoSubtle
      .importKey(
        formats.RAW,
        KU.hex2ab(derivedPassword),
        algorithms.AES_KW,
        KRYPTOS.NONEXTRACTABLE,
        KRYPTOS.WRAP_USAGE,
      )
      .then(saveDerivedKey)

  /**
   * Export the public encryption key
   *
   * @returns {Promise} of exportKey
   */
  const exportPEK = () =>
    KRYPTOS.cryptoSubtle.exportKey(formats.JWK, encryptKeyPair.publicKey)

  /**
   * Save the public encryption key.
   *
   * @param {Object} key
   * @returns {void}
   */
  const savePEK = key => {
    exportedPublicEncryptKey = key
    if (key.kty === 'EC') {
      delete exportedPublicEncryptKey.ext
    }
  }

  /**
   * Export the public sign key.
   *
   * @returns {Promise} of exportKey
   */
  const exportPVK = () =>
    KRYPTOS.cryptoSubtle.exportKey(formats.JWK, signKeyPair.publicKey)

  /**
   * Save the public sign key.
   *
   * @param {Object} key
   * @returns {void}
   */
  const savePVK = key =>
    new Promise(resolve => {
      exportedPublicVerifyKey = key
      if (key.kty === 'EC') {
        delete exportedPublicVerifyKey.ext
      }
      resolve(exportedPublicVerifyKey)
    })

  const fingerprint = key =>
    KRYPTOS.cryptoSubtle.digest(KRYPTOS.SHA_256.name, objectToArrayBuffer(key))

  const importIAK = (jwk, extractable) => {
    const unwrapAlgo = KRYPTOS.getAlgo(keyContainerPSK.protectType)
    return KRYPTOS.cryptoSubtle.importKey(
      formats.JWK,
      jwk,
      unwrapAlgo.name,
      extractable,
      ['unwrapKey', 'wrapKey', 'decrypt'],
    )
  }

  const importIAKPDK = extractable => {
    const jwk = JSON.parse(KRYPTOS.session.getItem(prefixIAKPDK))
    return importIAK(jwk, extractable)
  }

  const importIAKPSK = extractable => {
    const jwk = JSON.parse(KRYPTOS.session.getItem(prefixIAKPSK))
    return importIAK(jwk, extractable)
  }

  const unwrapPDK = key => {
    wrappedPDK = base64ToArrayBuffer(keyContainerPDK.encryptedKey)
    ivPDK = base64ToArrayBuffer(keyContainerPDK.iv)
    const unwrapAlgo = KRYPTOS.getAlgo(keyContainerPDK.protectType)
    const unwrappedKeyAlgo = KRYPTOS.getAlgo(keyContainerPDK.keyType)
    const usages = isEC()
      ? ['deriveKey', 'deriveBits']
      : ['decrypt', 'unwrapKey']
    if (isEC()) {
      // Firefox fix for missing AES-GCM unwrapKey for ECDH
      return KRYPTOS.cryptoSubtle
        .decrypt({ name: unwrapAlgo.name, iv: ivPDK }, key, wrappedPDK)
        .then(result => {
          const decryptedKey = arrayBufferToObject(result)
          return KRYPTOS.cryptoSubtle.importKey(
            formats.JWK,
            decryptedKey,
            unwrappedKeyAlgo,
            false,
            usages,
          )
        })
    }
    return KRYPTOS.cryptoSubtle.unwrapKey(
      formats.JWK,
      wrappedPDK,
      key,
      { name: unwrapAlgo.name, iv: ivPDK },
      unwrappedKeyAlgo,
      KRYPTOS.NONEXTRACTABLE,
      usages,
    )
  }

  const getPdk = () => {
    if (cachedPDK !== null) {
      return new Promise(resolve => {
        resolve(cachedPDK)
      })
    }
    return importIAKPDK(KRYPTOS.NONEXTRACTABLE)
      .then(unwrapPDK)
      .then(pdk => {
        cachedPDK = pdk
        return cachedPDK
      })
      .catch(error => {
        console.error(error)
      })
  }

  const unwrapPSK = key => {
    wrappedPSK = base64ToArrayBuffer(keyContainerPSK.encryptedKey)
    ivPSK = base64ToArrayBuffer(keyContainerPSK.iv)
    const unwrapAlgo = KRYPTOS.getAlgo(keyContainerPSK.protectType)
    const unwrappedKeyAlgo = KRYPTOS.getAlgo(keyContainerPSK.keyType)
    if (isEC()) {
      // Firefox fix for missing AES-GCM unwrapKey for ECDSA
      return KRYPTOS.cryptoSubtle
        .decrypt({ name: unwrapAlgo.name, iv: ivPSK }, key, wrappedPSK)
        .then(result => {
          const decryptedKey = arrayBufferToObject(result)
          return KRYPTOS.cryptoSubtle.importKey(
            formats.JWK,
            decryptedKey,
            unwrappedKeyAlgo,
            false,
            ['sign'],
          )
        })
    }
    return KRYPTOS.cryptoSubtle.unwrapKey(
      formats.JWK,
      wrappedPSK,
      key,
      { name: unwrapAlgo.name, iv: ivPSK },
      unwrappedKeyAlgo,
      KRYPTOS.NONEXTRACTABLE,
      ['sign'],
    )
  }

  const getPsk = () => {
    if (cachedPSK !== null) {
      return new Promise(resolve => {
        resolve(cachedPSK)
      })
    }
    if (!KRYPTOS.session.getItem(prefixIAKPSK)) {
      return ''
    }
    return importIAKPSK(KRYPTOS.NONEXTRACTABLE)
      .then(unwrapPSK)
      .then(psk => {
        cachedPSK = psk
        return cachedPSK
      })
  }

  const getPek = () => {
    const pek = JSON.parse(KRYPTOS.session.getItem(prefixPEK))
    return importPek(pek, ['encrypt'])
  }

  const importPvk = publicKey => {
    let { alg } = publicKey
    if (publicKey.kty === 'EC') {
      alg = 'ECDSA'
      // eslint-disable-next-line no-param-reassign
      delete publicKey.alg
    }
    const algo = KRYPTOS.getAlgo(alg)
    return KRYPTOS.cryptoSubtle.importKey(formats.JWK, publicKey, algo, false, [
      'verify',
    ])
  }

  const getPvk = jwk => {
    const pvk = JSON.parse(KRYPTOS.session.getItem(prefixPVK))
    if (jwk) {
      return pvk
    }
    return importPvk(pvk, ['verify'])
  }

  const setPek = pek => {
    exportedPublicEncryptKey = pek
  }

  const setPvk = pvk => {
    exportedPublicVerifyKey = pvk
  }

  const setPublicKeys = (username, publicKeys) => {
    KRYPTOS.session.setItem(publicKeyPrefix + username, publicKeys)
  }

  const getPublicKey = (userId, type, callback) =>
    new Promise(resolve => {
      if (typeof userId === 'object') {
        // TODO check consistency with LEGACY
        const contact = userId
        const { encrypt, verify } = contact.keys[service]
        const publicKey = type === 'verify' ? verify : encrypt
        if (callback) callback(publicKey)
        return resolve(publicKey)
      }
      const publicKeys = KRYPTOS.session.getItem(publicKeyPrefix + userId)
      let publicKey = {}
      if (publicKeys) {
        const keys = JSON.parse(publicKeys)
        if (type === 'verify') {
          publicKey = keys.verify
        } else {
          publicKey = keys.encrypt
        }
        if (callback) {
          callback(publicKey)
        }
        resolve(publicKey)
      } else {
        // TODO: Clean up here
        const Contacts = {}
        Contacts.getContactFromCache(userId, () => {
          const contactPublicKeys = KRYPTOS.session.getItem(
            publicKeyPrefix + userId,
          )
          let contactPublicKey = {}
          if (contactPublicKeys) {
            const keys = JSON.parse(contactPublicKeys)
            if (type === 'verify') {
              contactPublicKey = keys.verify
            } else {
              contactPublicKey = keys.encrypt
            }
            if (callback) {
              callback(contactPublicKey)
            }
            resolve(contactPublicKey)
          }
        })
      }
      return null
    })

  const getRecipientPublicKeys = username =>
    JSON.parse(KRYPTOS.session.getItem(publicKeyPrefix + username))

  /**
   * Retrieve the public keys.
   *
   * @param {String} emails
   * @param {function} callback
   * @returns {undefined}
   */
  const getRecipientsPublicKeys = (emails, callback) => {
    if (KRYPTOS.utils.isEmpty(emails)) {
      return callback(false, 'No emails provided.')
    }
    let usernames = ''
    const temp = []
    // eslint-disable-next-line no-plusplus
    for (let i = 0; i < emails.length; i++) {
      const username = emails[i]

      if (
        !(
          KRYPTOS.session.getItem(publicKeyPrefix + username) || username === ''
        )
      )
        temp.push(encodeURIComponent(username))
    }
    if (temp.length === 0) {
      return callback(true, 'Done!')
    }
    usernames = temp.join(',')
    KRYPTOS.API.getPublicKeys(
      { service, usernames },
      data => {
        if (data) {
          // eslint-disable-next-line no-plusplus
          for (let i = 0; i < data.length; i++) {
            KRYPTOS.session.setItem(
              publicKeyPrefix + data[i].username,
              data[i].public_keys,
            )
          }
        }
        return callback(true, '')
      },
      error => {
        console.error(error)
        callback(false, error)
      },
    )
    return null
  }

  const unlockPrivateKey = (
    protector,
    keyContainer,
    keyContainerType,
    protectorTypeParam = PROTECTOR_TYPES.password,
  ) => {
    let protectorType = protectorTypeParam
    let derivedKeyProtector = null

    // From derived CryptoKey
    if (protector instanceof Object) {
      protectorType = 'asymmetric'
      derivedKeyProtector = importAsymmetric(protector)
    } else {
      derivedKeyProtector = importPassword(protector)
    }

    const keyProtector = extractKeyProtector(keyContainerType, protectorType)
    if (
      keyProtector.type === PROTECTOR_TYPES.password ||
      keyProtector.type === PROTECTOR_TYPES.recovery
    ) {
      setDeriveKeyAlgo({
        name: keyProtector.name,
        salt: base64ToArrayBuffer(keyProtector.salt),
        iterations: keyProtector.iterations,
        hash: keyProtector.hash,
      })
    }
    const algo = KRYPTOS.getAlgo(keyContainer.protectType)
    return derivedKeyProtector
      .then(() =>
        unwrapIAK(base64ToArrayBuffer(keyProtector.encryptedKey), algo.name),
      )
      .then(exportIAK)
      .catch(error => {
        console.error(error)
        return new Promise((resolve, reject) => {
          reject(error)
        })
      })
  }

  const unlockPdk = (protector, protectorType) =>
    new Promise((resolve, reject) => {
      if (!keyContainerPDK) {
        resolve()
        return null
      }

      return unlockPrivateKey(protector, keyContainerPDK, 'PDK', protectorType)
        .then(exportedKey => {
          KRYPTOS.session.setItem(prefixIAKPDK, JSON.stringify(exportedKey))
          resolve()
        })
        .catch(error => {
          console.error(error)
          reject(error)
        })
    })

  const unlockPsk = (protector, protectorType) =>
    new Promise((resolve, reject) => {
      if (!keyContainerPSK) {
        resolve()
        return null
      }

      return unlockPrivateKey(protector, keyContainerPSK, 'PSK', protectorType)
        .then(exportedKey => {
          KRYPTOS.session.setItem(prefixIAKPSK, JSON.stringify(exportedKey))
          resolve()
        })
        .catch(error => {
          console.error(error)
          reject(error)
        })
    })

  function unlock(
    protector,
    pek,
    pvk,
    signature,
    protectorType = PROTECTOR_TYPES.password,
  ) {
    return new Promise((resolve, reject) => {
      storeKeys(pek, pvk, signature)

      return unlockPsk(protector, protectorType)
        .then(() =>
          unlockPdk(protector, protectorType)
            .then(() => {
              resolve(this)
            })
            .catch(error => {
              console.error(error)
              reject(error)
            }),
        )
        .catch(error => {
          console.error(error)
          reject(error)
        })
    })
  }

  const verifyProtector = (
    protector,
    protectorType = PROTECTOR_TYPES.password,
  ) =>
    new Promise((resolve, reject) => {
      unlockPsk(protector, protectorType)
        .then(() => unlockPdk(protector, protectorType))
        .then(() => {
          resolve()
        })
        .catch(error => {
          console.error(error)
          reject(error)
        })
    })

  const unlockFromDerivedKey = (protector, pek, pvk) =>
    importDerivedKey(protector).then(() => unlock(derivedKey, pek, pvk))

  const lockPsk = (type = PROTECTOR_TYPES.password) =>
    new Promise((resolve, reject) => {
      if (!keyContainerPSK) {
        resolve()
        return null
      }
      return importIAKPSK(KRYPTOS.EXTRACTABLE)
        .then(wrapIAKPSK)
        .then(wrappedKey => {
          replacePasswordProtector(keyContainerPSK, type, wrappedKey)
          resolve()
        })
        .catch(error => {
          console.error(error)
          reject(error)
        })
    })

  const lockPdk = (type = PROTECTOR_TYPES.password) =>
    new Promise((resolve, reject) => {
      if (!keyContainerPDK) {
        resolve()
        return null
      }
      return importIAKPDK(KRYPTOS.EXTRACTABLE)
        .then(wrapIAKPDK)
        .then(wrappedKey => {
          replacePasswordProtector(keyContainerPDK, type, wrappedKey)
          resolve()
        })
        .catch(error => {
          console.error(error)
          reject(error)
        })
    })

  const lock = (password, type = PROTECTOR_TYPES.password) =>
    new Promise((resolve, reject) =>
      deriveKeyFromPassword(password)
        .then(() => lockPsk(type))
        .then(() => lockPdk(type))
        .then(() => {
          const data = {}
          data[service] = {
            pdk: keyContainerPDK,
            psk: keyContainerPSK,
          }
          resolve(data)
        })
        .catch(error => {
          console.error(error)
          reject(error)
        }),
    )

  const addMemberProtector = (keyStore, username, callback) =>
    deriveKeyFromAsymmetric(keyStore, username)
      .then(() => importIAKPDK(KRYPTOS.EXTRACTABLE))
      .then(wrapIAKPDK)
      .then(wrappedKey => {
        callback(true, {
          encryptedKey: arrayBufferToBase64(wrappedKey),
          username,
          type: 'asymmetric',
          name: deriveKeyAlgo.name,
        })
      })
      .catch(error => {
        callback(false, error)
      })

  const setupKeys = (password, identity) => {
    ivPSK = nonce()
    ivPDK = nonce()
    return deriveKeyFromPassword(password)
      .then(generateIAK)
      .then(saveIAKPSK)
      .then(wrapIAKPSK)
      .then(saveWrappedIAKPSK)
      .then(generateSigningKeyPair)
      .then(saveSigningKeyPair)
      .then(wrapPSK)
      .then(saveWrappedPSK)
      .then(exportPVK)
      .then(savePVK)
      .then(generateIAK)
      .then(saveIAKPDK)
      .then(wrapIAKPDK)
      .then(saveWrappedIAKPDK)
      .then(generateEncryptionKeyPair)
      .then(saveEncryptionKeyPair)
      .then(wrapPDK)
      .then(saveWrappedPDK)
      .then(exportPEK)
      .then(savePEK)
      .then(() => signPublicKeys(identity))
      .then(packageKeyContainers)
      .catch(error => {
        console.error(error)
      })
  }

  const setupSignKeys = password => {
    ivPSK = nonce()
    return deriveKeyFromPassword(password)
      .then(generateIAK)
      .then(saveIAKPSK)
      .then(wrapIAKPSK)
      .then(saveWrappedIAKPSK)
      .then(generateSigningKeyPair)
      .then(saveSigningKeyPair)
      .then(wrapPSK)
      .then(saveWrappedPSK)
      .then(exportPVK)
      .then(savePVK)
      .then(fingerprint)
      .then(packageSignKeyContainer)
      .catch(error => {
        console.error(error)
      })
  }

  const setupEncryptKeys = protector => {
    ivPDK = nonce()
    let keyProtector = null
    if (protector instanceof Object) {
      keyProtector = deriveKeyFromAsymmetric(protector)
    } else {
      keyProtector = deriveKeyFromPassword(protector)
    }
    return keyProtector
      .then(generateIAK)
      .then(saveIAKPDK)
      .then(wrapIAKPDK)
      .then(saveWrappedIAKPDK)
      .then(generateEncryptionKeyPair)
      .then(saveEncryptionKeyPair)
      .then(wrapPDK)
      .then(saveWrappedPDK)
      .then(exportPEK)
      .then(savePEK)
      .then(packageEncryptKeyContainer)
      .catch(error => {
        console.error(error)
      })
  }

  const init = () => {
    keyContainerPDK = JSON.parse(KRYPTOS.session.getItem(prefixPDK))
    keyContainerPSK = JSON.parse(KRYPTOS.session.getItem(prefixPSK))
    setMode(KRYPTOS.getAsymmetricModeByAlgo(keyContainerPSK.keyType))
  }

  return {
    init,
    setMode,
    getMode,
    isEC,
    isRSA,
    isLoaded,
    setupKeys,
    setupSignKeys,
    setupEncryptKeys,
    unlock,
    lock,
    verifyProtector,
    getPek,
    getPvk,
    getPdk,
    getPsk,
    setPek,
    setPvk,
    getPublicKey,
    setPublicKeys,
    importPvk,
    importPek,
    getRecipientPublicKeys,
    getRecipientsPublicKeys,
    deriveKeyFromPassword,
    addMemberProtector,
    unlockFromDerivedKey,
    id: service,
  }
}
