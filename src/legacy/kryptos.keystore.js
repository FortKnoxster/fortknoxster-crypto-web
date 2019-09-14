/* eslint-disable max-lines */
import { kryptos } from '../kryptos/kryptos'
import { Encrypter } from './kryptos.encrypter'
import {
  PROTECTOR_TYPES,
  EXTRACTABLE,
  NONEXTRACTABLE,
} from '../kryptos/constants'
import * as utils from '../kryptos/utils'
import * as algorithms from '../kryptos/algorithms'
import * as usage from '../kryptos/usages'
import * as formats from '../kryptos/formats'

/**
 * Kryptos is a cryptographic library wrapping and implementing the
 * Web Cryptography API. It supports both symmetric keys and asymmetric key pair
 * generation, encryption, decryption, signing and verification.
 *
 * @name kryptos.KeyStore
 * @copyright Copyright © FortKnoxster Ltd. 2014 - 2019.
 * @license Apache License, Version 2.0 http://www.apache.org/licenses/LICENSE-2.0
 * @author MJ <mj@fortknoxster.com>
 * @version 4.0
 */

/**
 * The kryptos KeyStore module.
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
        throw new Error('Invalid algorithm in setMode.')
    }
    mode = keyStoreMode
  }

  const getMode = () => mode

  const isEC = () => mode === 'EC'

  const isRSA = () => mode === 'RSA'

  const isLoaded = () => (ivPDK && ivPSK && wrappedPDK && wrappedPSK) !== null

  const generateIAK = () =>
    kryptos.subtle.generateKey(
      algorithms.AES_GCM_ALGO,
      EXTRACTABLE,
      usage.WRAP.concat(usage.ENCRYPT),
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
      sessionStorage.setItem(prefixPDK, JSON.stringify(keyContainerPDK))
    }
    if (keyContainerPSK) {
      sessionStorage.setItem(prefixPSK, JSON.stringify(keyContainerPSK))
    }
    const publicKeys = {}
    if (pek) {
      sessionStorage.setItem(prefixPEK, JSON.stringify(pek))
      publicKeys.encrypt = pek
    }
    if (pvk) {
      sessionStorage.setItem(prefixPVK, JSON.stringify(pvk))
      publicKeys.verify = pvk
    }
    if (signature) {
      publicKeys.signature = signature
    }

    sessionStorage.setItem(
      publicKeyPrefix + sessionStorage.getItem('id'),
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
        fingerprint: utils.arrayBufferToHex(hash),
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
        ? utils.ecJwk(exportedPublicEncryptKey)
        : utils.rsaJwk(exportedPublicEncryptKey),
      pvk: isEC()
        ? utils.ecJwk(exportedPublicVerifyKey)
        : utils.rsaJwk(exportedPublicVerifyKey),
    }
    return new Promise((resolve, reject) => {
      const encrypter = new Encrypter(
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
      encrypter.signIt(publicKeys, true)
    })
  }

  /**
   * Generate the signing key pair using the RSASSA-PKCS1-v1_5 or the ECDSA algorithm.
   *
   * @returns {Promise} of generateKey
   */
  const generateSigningKeyPair = () => {
    if (isEC()) {
      return kryptos.subtle.generateKey(
        algorithms.ECDSA_ALGO,
        EXTRACTABLE,
        usage.SIGN,
      )
    }
    return kryptos.subtle.generateKey(
      algorithms.RSASSA_PKCS1_V1_5_ALGO,
      EXTRACTABLE,
      usage.SIGN,
    )
  }

  /**
   * Generate the encryption key pair using the RSA OAEP or the ECDH algorithm.
   *
   * @returns {Promise} of generateKey
   */
  const generateEncryptionKeyPair = () => {
    if (isEC()) {
      return kryptos.subtle.generateKey(
        algorithms.ECDH_ALGO,
        EXTRACTABLE,
        usage.DERIVE,
      )
    }
    return kryptos.subtle.generateKey(
      algorithms.RSA_OAEP_ALGO,
      EXTRACTABLE,
      usage.ENCRYPT.concat(usage.WRAP),
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
    kryptos.subtle.wrapKey(formats.JWK, encryptKeyPair.privateKey, IAKPDK, {
      name: algorithms.AES_GCM.name,
      iv: ivPDK,
    })

  /**
   * Wrape the private sign key.
   *
   * @returns {Promise} of wrapKey
   */
  const wrapPSK = () =>
    kryptos.subtle.wrapKey(formats.JWK, signKeyPair.privateKey, IAKPSK, {
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
      encryptedKey: utils.arrayBufferToBase64(wrappedKey),
      type: typeProtector,
      name: deriveKeyAlgo.name,
      salt: utils.arrayBufferToBase64(deriveKeyAlgo.salt),
      iterations: deriveKeyAlgo.iterations,
      hash: deriveKeyAlgo.hash,
    })
  }

  const addAsymmetricProtector = (keyContainer, wrappedKey) => {
    keyContainer.keyProtectors.push({
      encryptedKey: utils.arrayBufferToBase64(wrappedKey),
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
        iv: utils.arrayBufferToBase64(ivPDK),
        keyType: utils.getKeyType(mode, 'PDK'),
        protectType: 'AES-GCM-256',
        keyProtectors: [],
      }
      addProtector(keyContainerPDK, wrappedIAKPDK)
    }
    keyContainerPDK.encryptedKey = utils.arrayBufferToBase64(wrappedKey)
  }

  const saveWrappedPSK = wrappedKey => {
    if (keyContainerPSK === null) {
      keyContainerPSK = {
        encryptedKey: null,
        iv: utils.arrayBufferToBase64(ivPSK),
        keyType: utils.getKeyType(mode, 'PSK'),
        protectType: 'AES-GCM-256',
        keyProtectors: [],
      }
      addPasswordProtector(keyContainerPSK, wrappedIAKPSK)
    }
    keyContainerPSK.encryptedKey = utils.arrayBufferToBase64(wrappedKey)
  }

  const unwrapIAK = (wrappedKey, algo) => {
    const usages = usage.WRAP.concat(usage.ENCRYPT)
    if (derivedKey.type === 'private') {
      return kryptos.subtle
        .decrypt({ name: derivedKey.algorithm.name }, derivedKey, wrappedKey)
        .then(keyBytes =>
          kryptos.subtle.importKey(
            formats.RAW,
            keyBytes,
            algorithms.getAlgorithm(algo),
            EXTRACTABLE,
            usages,
          ),
        )
    }
    return kryptos.subtle.unwrapKey(
      formats.RAW,
      wrappedKey,
      derivedKey,
      algorithms.AES_KW,
      { name: algo },
      EXTRACTABLE,
      usages,
    )
  }

  const exportIAK = key => kryptos.subtle.exportKey(formats.JWK, key)

  const wrapIAKPSK = key =>
    kryptos.subtle.wrapKey(
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
      return kryptos.subtle
        .exportKey(formats.RAW, IAKPDK || key)
        .then(exportedKey =>
          kryptos.subtle.encrypt(derivedKey.algorithm, derivedKey, exportedKey),
        )
    }
    return kryptos.subtle.wrapKey(
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
        encryptedKey: utils.arrayBufferToBase64(wrappedKey),
        type,
        name: deriveKeyAlgo.name,
        salt: utils.arrayBufferToBase64(deriveKeyAlgo.salt),
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
    kryptos.subtle.deriveKey(
      deriveKeyAlgo,
      key,
      algorithms.AES_KW_ALGO,
      NONEXTRACTABLE,
      usage.WRAP,
    )

  const saveDerivedKey = key => {
    derivedKey = key
  }

  const importPassword = password =>
    kryptos.subtle
      .importKey(
        formats.RAW,
        utils.stringToArrayBuffer(password),
        algorithms.PBKDF2,
        false,
        usage.DERIVE,
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
    const algo = algorithms.getAlgorithm(alg)
    return kryptos.subtle.importKey(formats.JWK, publicKey, algo, false, usages)
  }

  const setDeriveKeyAlgo = algo => {
    deriveKeyAlgo = algo
  }

  const deriveKeyFromAsymmetric = (keyStore, username) => {
    setDeriveKeyAlgo(algorithms.RSA_OAEP_ALGO)
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
      salt: utils.randomValue(32),
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
    kryptos.subtle
      .importKey(
        formats.RAW,
        utils.hexToArrayBuffer(derivedPassword),
        algorithms.AES_KW,
        NONEXTRACTABLE,
        usage.WRAP,
      )
      .then(saveDerivedKey)

  /**
   * Export the public encryption key
   *
   * @returns {Promise} of exportKey
   */
  const exportPEK = () =>
    kryptos.subtle.exportKey(formats.JWK, encryptKeyPair.publicKey)

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
    kryptos.subtle.exportKey(formats.JWK, signKeyPair.publicKey)

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
    kryptos.subtle.digest(
      algorithms.SHA_256.name,
      utils.objectToArrayBuffer(key),
    )

  const importIAK = (jwk, extractable) => {
    const unwrapAlgo = algorithms.getAlgorithm(keyContainerPSK.protectType)
    return kryptos.subtle.importKey(
      formats.JWK,
      jwk,
      unwrapAlgo.name,
      extractable,
      ['unwrapKey', 'wrapKey', 'decrypt'],
    )
  }

  const importIAKPDK = extractable => {
    const jwk = JSON.parse(sessionStorage.getItem(prefixIAKPDK))
    return importIAK(jwk, extractable)
  }

  const importIAKPSK = extractable => {
    const jwk = JSON.parse(sessionStorage.getItem(prefixIAKPSK))
    return importIAK(jwk, extractable)
  }

  const unwrapPDK = key => {
    wrappedPDK = utils.base64ToArrayBuffer(keyContainerPDK.encryptedKey)
    ivPDK = utils.base64ToArrayBuffer(keyContainerPDK.iv)
    const unwrapAlgo = algorithms.getAlgorithm(keyContainerPDK.protectType)
    const unwrappedKeyAlgo = algorithms.getAlgorithm(keyContainerPDK.keyType)
    const usages = isEC() ? usage.DERIVE : ['decrypt', 'unwrapKey']
    if (isEC()) {
      // Firefox fix for missing AES-GCM unwrapKey for ECDH
      return kryptos.subtle
        .decrypt({ name: unwrapAlgo.name, iv: ivPDK }, key, wrappedPDK)
        .then(result => {
          const decryptedKey = utils.arrayBufferToObject(result)
          return kryptos.subtle.importKey(
            formats.JWK,
            decryptedKey,
            unwrappedKeyAlgo,
            false,
            usages,
          )
        })
    }
    return kryptos.subtle.unwrapKey(
      formats.JWK,
      wrappedPDK,
      key,
      { name: unwrapAlgo.name, iv: ivPDK },
      unwrappedKeyAlgo,
      NONEXTRACTABLE,
      usages,
    )
  }

  const getPdk = () => {
    if (cachedPDK !== null) {
      return new Promise(resolve => {
        resolve(cachedPDK)
      })
    }
    return importIAKPDK(NONEXTRACTABLE)
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
    wrappedPSK = utils.base64ToArrayBuffer(keyContainerPSK.encryptedKey)
    ivPSK = utils.base64ToArrayBuffer(keyContainerPSK.iv)
    const unwrapAlgo = algorithms.getAlgorithm(keyContainerPSK.protectType)
    const unwrappedKeyAlgo = algorithms.getAlgorithm(keyContainerPSK.keyType)
    if (isEC()) {
      // Firefox fix for missing AES-GCM unwrapKey for ECDSA
      return kryptos.subtle
        .decrypt({ name: unwrapAlgo.name, iv: ivPSK }, key, wrappedPSK)
        .then(result => {
          const decryptedKey = utils.arrayBufferToObject(result)
          return kryptos.subtle.importKey(
            formats.JWK,
            decryptedKey,
            unwrappedKeyAlgo,
            false,
            ['sign'],
          )
        })
    }
    return kryptos.subtle.unwrapKey(
      formats.JWK,
      wrappedPSK,
      key,
      { name: unwrapAlgo.name, iv: ivPSK },
      unwrappedKeyAlgo,
      NONEXTRACTABLE,
      ['sign'],
    )
  }

  const getPsk = () => {
    if (cachedPSK !== null) {
      return new Promise(resolve => {
        resolve(cachedPSK)
      })
    }
    if (!sessionStorage.getItem(prefixIAKPSK)) {
      return ''
    }
    return importIAKPSK(NONEXTRACTABLE)
      .then(unwrapPSK)
      .then(psk => {
        cachedPSK = psk
        return cachedPSK
      })
  }

  const getPek = () => {
    const pek = JSON.parse(sessionStorage.getItem(prefixPEK))
    return importPek(pek, ['encrypt'])
  }

  const importPvk = publicKey => {
    let { alg } = publicKey
    if (publicKey.kty === 'EC') {
      alg = 'ECDSA'
      // eslint-disable-next-line no-param-reassign
      delete publicKey.alg
    }
    const algo = algorithms.getAlgorithm(alg)
    return kryptos.subtle.importKey(formats.JWK, publicKey, algo, false, [
      'verify',
    ])
  }

  const getPvk = jwk => {
    const pvk = JSON.parse(sessionStorage.getItem(prefixPVK))
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
    sessionStorage.setItem(publicKeyPrefix + username, publicKeys)
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
      const publicKeys = sessionStorage.getItem(publicKeyPrefix + userId)
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
          const contactPublicKeys = sessionStorage.getItem(
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
    JSON.parse(sessionStorage.getItem(publicKeyPrefix + username))

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
        salt: utils.base64ToArrayBuffer(keyProtector.salt),
        iterations: keyProtector.iterations,
        hash: keyProtector.hash,
      })
    }
    const algo = algorithms.getAlgorithm(keyContainer.protectType)
    return derivedKeyProtector
      .then(() =>
        unwrapIAK(
          utils.base64ToArrayBuffer(keyProtector.encryptedKey),
          algo.name,
        ),
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
          sessionStorage.setItem(prefixIAKPDK, JSON.stringify(exportedKey))
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
          sessionStorage.setItem(prefixIAKPSK, JSON.stringify(exportedKey))
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
      return importIAKPSK(EXTRACTABLE)
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
      return importIAKPDK(EXTRACTABLE)
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
      .then(() => importIAKPDK(EXTRACTABLE))
      .then(wrapIAKPDK)
      .then(wrappedKey => {
        callback(true, {
          encryptedKey: utils.arrayBufferToBase64(wrappedKey),
          username,
          type: 'asymmetric',
          name: deriveKeyAlgo.name,
        })
      })
      .catch(error => {
        callback(false, error)
      })

  const setupKeys = (password, identity) => {
    ivPSK = utils.nonce()
    ivPDK = utils.nonce()
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
    ivPSK = utils.nonce()
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
    ivPDK = utils.nonce()
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
    keyContainerPDK = JSON.parse(sessionStorage.getItem(prefixPDK))
    keyContainerPSK = JSON.parse(sessionStorage.getItem(prefixPSK))
    setMode(utils.getKeyMode(keyContainerPSK.keyType))
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
    deriveKeyFromPassword,
    addMemberProtector,
    unlockFromDerivedKey,
    id: service,
  }
}
