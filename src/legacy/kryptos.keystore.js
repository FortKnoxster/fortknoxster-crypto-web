import { KRYPTOS } from './kryptos.core'

/**
 * KRYPTOS is a cryptographic library wrapping and implementing the
 * Web Cryptography API. It supports both symmetric keys and asymmetric key pair
 * generation, encryption, decryption, signing and verification.
 *
 * If the Web Cryptography API is not supported by the browser, it falls back
 * to the an implementation of the MSR JavaScript Cryptography Library.
 *
 *
 * @name KRYPTOS
 * @copyright Copyright © FortKnoxster Ltd. 2014 - 2019.
 * @license Apache License, Version 2.0 http://www.apache.org/licenses/LICENSE-2.0
 * @author MJ <mj@fortknoxster.com>
 * @version 4.0
 */

/**
 * The KRYPTOS Key Store module.
 *
 * @param {String} service
 * @param {Object} containerPDK
 * @param {Object} containerPSK
 * @returns {KRYPTOS.Encrypter} the public methods
 */
export const KeyStore = function(serviceType, containerPDK, containerPSK) {
  const KU = KRYPTOS.utils
  const service = serviceType

  /**
   * Can be RSA or EC. Determines whether RSA keypairs or EC keypairs are
   * being used for this key store. Default is RSA.
   */
  let mode = 'RSA'

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

  let setupData = null

  let cachePSK = false

  let cachedPSK = null

  let cachePDK = false

  let cachedPDK = null

  let keyContainerPDK = containerPDK

  let keyContainerPSK = containerPSK

  let importedPassword = null

  let derivedKey = null

  let deriveKeyAlgo = null

  let confirmationToken = null

  const isLoaded = function() {
    return (ivPDK && ivPSK && wrappedPDK && wrappedPSK) !== null
  }

  const justSetUp = function() {
    return setupData !== null
  }

  const setSetUp = function() {
    setupData = null
  }

  const setCachePsk = function(cache) {
    cachePSK = cache
    if (cache === false) {
      cachedPSK = null
    }
  }

  const setCachePdk = function(cache) {
    cachePDK = cache
    if (cache === false) {
      cachedPDK = null
    }
  }

  const setupKeys = function(password, keyType, identity) {
    setMode(keyType)
    ivPSK = KRYPTOS.nonce()
    ivPDK = KRYPTOS.nonce()
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
        KU.log(error)
      })
  }

  const setupSignKeys = function(password, mode) {
    setMode(mode)
    ivPSK = KRYPTOS.nonce()
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
        KU.log(error)
      })
  }

  const addMemberProtector = function(keyStore, username, callback) {
    return deriveKeyFromAsymmetric(keyStore, username)
      .then(() => importIAKPDK(KRYPTOS.EXTRACTABLE))
      .then(wrapIAKPDK)
      .then(wrappedKey => {
        callback(true, {
          encryptedKey: KU.ab2b64(wrappedKey),
          username,
          type: 'asymmetric',
          name: deriveKeyAlgo.name,
        })
      })
      .catch(error => {
        callback(false, error)
      })
  }

  const setupEncryptKeys = function(protector, mode) {
    setMode(mode)
    ivPDK = KRYPTOS.nonce()
    let keyProtector = null
    if (protector instanceof Object) {
      keyProtector = deriveKeyFromAsymmetric(protector)
    } else {
      keyProtector = deriveKeyFromPassword(protector)
    }
    return (
      keyProtector
        .then(generateIAK)
        .catch(error => {
          log('c1')
          log(error)
          KU.log(error)
        })
        .then(saveIAKPDK)
        .then(wrapIAKPDK)
        .then(saveWrappedIAKPDK)
        .then(generateEncryptionKeyPair)
        .catch(error => {
          log('c2')
          log(error)
          KU.log(error)
        })
        .then(saveEncryptionKeyPair)
        .then(wrapPDK)
        .catch(error => {
          log('c3')
          log(error)
          KU.log(error)
        })
        .then(saveWrappedPDK)
        .then(exportPEK) // .catch(function (error) {log('c7'); log(error); KU.log(error);})
        .then(savePEK)
        .then(packageEncryptKeyContainer)
        // .then(unwrapKeyProtector)//.then(function(result) {log(result)})
        .catch(error => {
          log(error)
          //                    alert(error);
        })
    )
  }

  let generateIAK = function() {
    log(' --- generateIAK --- ')
    return KRYPTOS.cryptoSubtle.generateKey(
      KRYPTOS.AES_GCM_ALGO,
      KRYPTOS.EXTRACTABLE,
      KRYPTOS.WRAP_USAGE.concat(KRYPTOS.ENCRYPT_USAGE),
    )
  }

  let saveIAKPSK = function(iak) {
    log(' --- saveIAKPSK --- ')
    log(iak)
    IAKPSK = iak
  }

  let saveIAKPDK = function(iak) {
    log(' --- saveIAKPDK --- ')
    log(iak)
    IAKPDK = iak
  }

  const extractTokenKeyProtector = function() {
    log(' --- extractTokenKeyProtector --- ')
    return extractKeyProtector('PDK', 'token')
  }

  // TODO!!! KeyProtector has algorithm name?
  const importKeyFromKeyProtector = function(keyProtector) {
    log(' --- importKeyFromKeyProtector --- ')
    log(keyProtector)
    log(confirmationToken)
    log(KU.str2ab(confirmationToken))
    const key = new Uint8Array(KU.str2ab(confirmationToken), 0, 32)
    return KRYPTOS.cryptoSubtle
      .importKey(
        'raw',
        key,
        'AES-GCM',
        KRYPTOS.NONEXTRACTABLE,
        KRYPTOS.ENCRYPT_USAGE,
      )
      .then(importedKey => {
        log(' --- decrypt key protecter --- ')
        log(importedKey)

        const iv = KU.b642ab(keyProtector.iv)
        const encryptedKey = KU.b642ab(keyProtector.encryptedKey)
        log(encryptedKey)
        return KRYPTOS.cryptoSubtle.decrypt(
          { name: 'AES-GCM', iv },
          importedKey,
          encryptedKey,
        )
        // return KRYPTOS.cryptoSubtle.unwrapKey("raw", encryptedKey, key, {name: "AES-GCM", iv: iv}, {name: "AES-KW"}, KRYPTOS.NONEXTRACTABLE, KRYPTOS.WRAP_USAGE);
      })
      .then(key => {
        log(' --- encrypted PSK intermediate key --- ')
        log(key)
        return KRYPTOS.cryptoSubtle.importKey(
          'raw',
          key,
          'AES-GCM',
          KRYPTOS.EXTRACTABLE,
          KRYPTOS.WRAP_USAGE,
        )
      })
      .catch(error => {
        KU.log(error)
      })
  }

  let extractKeyProtector = function(keyType, protectorType) {
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
    for (let i = 0; i < protectors.length; i++) {
      if (protectors[i].type && protectors[i].type === protectorType) {
        return protectors[i]
      }
    }
    throw new Error(`No key protector found for ${protectorType}.`)
  }

  let packageKeyContainers = function(signedKeys) {
    log(' --- packageKeyContainers --- ')
    return new Promise((resolve, reject) => {
      const data = {}
      data[service] = {
        pdk: keyContainerPDK,
        psk: keyContainerPSK,
        pek: exportedPublicEncryptKey,
        pvk: exportedPublicVerifyKey,
        signature: signedKeys.signature,
      }
      resolve(data)
    })
  }

  let packageSignKeyContainer = function(hash) {
    return new Promise((resolve, reject) => {
      const data = {}
      data[service] = {
        psk: keyContainerPSK,
        pvk: exportedPublicVerifyKey,
        fingerprint: KU.ab2hex(hash),
      }
      resolve(data)
    })
  }

  let packageEncryptKeyContainer = function() {
    return new Promise((resolve, reject) => {
      const data = {}
      data[service] = {
        pdk: keyContainerPDK,
        pek: exportedPublicEncryptKey,
      }
      resolve(data)
    })
  }

  let signPublicKeys = function(identity) {
    const publicKeys = {
      pek: isEC()
        ? KU.ecJwk(exportedPublicEncryptKey)
        : KU.rsaJwk(exportedPublicEncryptKey),
      pvk: isEC()
        ? KU.ecJwk(exportedPublicVerifyKey)
        : KU.rsaJwk(exportedPublicVerifyKey),
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
  let generateSigningKeyPair = function() {
    log(' --- generateSigningKeyPair --- ')
    if (isEC()) {
      return KRYPTOS.cryptoSubtle.generateKey(
        KRYPTOS.ECDSA_ALGO,
        KRYPTOS.EXTRACTABLE,
        KRYPTOS.SIGN_USAGE,
      )
    }
    return KRYPTOS.cryptoSubtle.generateKey(
      KRYPTOS.RSASSA_PKCS1_v1_5_ALGO,
      KRYPTOS.EXTRACTABLE,
      KRYPTOS.SIGN_USAGE,
    )
  }

  /**
   * Generate the encryption key pair using the RSA OAEP or the ECDH algorithm.
   *
   * @returns {Promise} of generateKey
   */
  let generateEncryptionKeyPair = function() {
    log(' --- generateEncryptionKeyPair- -- ')
    if (isEC()) {
      return KRYPTOS.cryptoSubtle.generateKey(
        KRYPTOS.ECDH_ALGO,
        KRYPTOS.EXTRACTABLE,
        KRYPTOS.DERIVE_USAGE,
      )
    }
    return KRYPTOS.cryptoSubtle.generateKey(
      KRYPTOS.RSA_OAEP_ALGO,
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
  let saveSigningKeyPair = function(keyPair) {
    log(' --- saveSigningKeyPair --- ')
    log(keyPair)
    signKeyPair = keyPair
    if (cachePSK) {
      cachedPSK = signKeyPair.privateKey
    }
  }

  /**
   * Save the encryption key pair.
   *
   * @param {raw} keyPair
   * @returns {void}
   */
  let saveEncryptionKeyPair = function(keyPair) {
    log(' --- saveEncryptionKeyPair --- ')
    log(keyPair)
    encryptKeyPair = keyPair
    if (cachePDK) {
      cachedPDK = encryptKeyPair.privateKey
    }
  }

  /**
   * Wrap the private decryption key.
   *
   * @returns {unresolved}
   */
  let wrapPDK = function() {
    log(' --- wrapPDK --- ')
    return KRYPTOS.cryptoSubtle.wrapKey(
      'jwk',
      encryptKeyPair.privateKey,
      IAKPDK,
      { name: 'AES-GCM', iv: ivPDK },
    )
  }

  /**
   * Wrape the private sign key.
   *
   * @returns {Promise} of wrapKey
   */
  let wrapPSK = function() {
    log(' --- wrapPSK --- ')
    return KRYPTOS.cryptoSubtle.wrapKey('jwk', signKeyPair.privateKey, IAKPSK, {
      name: 'AES-GCM',
      iv: ivPSK,
    })
  }

  let saveWrappedPDK = function(wrappedKey) {
    log(' --- saveWrappedPDK --- ')
    log(wrappedKey)
    if (keyContainerPDK === null) {
      keyContainerPDK = {
        encryptedKey: null,
        iv: KU.ab2b64(ivPDK),
        keyType: getKeyType('PDK'),
        protectType: 'AES-GCM-256',
        keyProtectors: [],
      }
      addProtector(keyContainerPDK, wrappedIAKPDK)
    }
    keyContainerPDK.encryptedKey = KU.ab2b64(wrappedKey)
    log(keyContainerPDK)
    // wrappedPSK = wrappedKey;
  }

  let saveWrappedPSK = function(wrappedKey) {
    log(' --- saveWrappedPSK --- ')
    log(wrappedKey)
    if (keyContainerPSK === null) {
      keyContainerPSK = {
        encryptedKey: null,
        iv: KU.ab2b64(ivPSK),
        keyType: getKeyType('PSK'),
        protectType: 'AES-GCM-256',
        keyProtectors: [],
      }
      addPasswordProtector(keyContainerPSK, wrappedIAKPSK)
    }
    keyContainerPSK.encryptedKey = KU.ab2b64(wrappedKey)
    log(keyContainerPSK)
    // wrappedPSK = wrappedKey;
  }

  let getKeyType = function(type) {
    if (type === 'PSK') {
      if (mode === 'RSA') {
        return 'RSASSA-PKCS1-v1_5-2048'
      }
      if (mode === 'EC') {
        return 'ECDSA-P521'
      }
    } else if (type === 'PDK') {
      if (mode === 'RSA') {
        return 'RSA-OAEP-2048'
      }
      if (mode === 'EC') {
        return 'ECDH-P521'
      }
    }
    throw new Error('Invalid key type')
  }
  //    log(' --- wrapIAKPDK --- ');
  //        log(derivedKey);
  //        log(IAKPDK);
  //        if (derivedKey.type === 'public') {
  //            return KRYPTOS.cryptoSubtle.exportKey("raw", IAKPDK || key).then(function(exportedKey) {
  //                return KRYPTOS.cryptoSubtle.encrypt(derivedKey.algorithm, derivedKey, exportedKey);
  //            });
  //        }
  //        return KRYPTOS.cryptoSubtle.wrapKey("raw", IAKPDK || key, derivedKey, {name: "AES-KW"});
  //
  const unwrapIAK = function(wrappedKey, algo) {
    const usage = KRYPTOS.WRAP_USAGE.concat(KRYPTOS.ENCRYPT_USAGE)
    if (derivedKey.type === 'private') {
      return KRYPTOS.cryptoSubtle
        .decrypt({ name: derivedKey.algorithm.name }, derivedKey, wrappedKey)
        .then(keyBytes =>
          KRYPTOS.cryptoSubtle.importKey(
            'raw',
            keyBytes,
            KRYPTOS.getAlgo(algo),
            KRYPTOS.EXTRACTABLE,
            usage,
          ),
        )
    }
    return KRYPTOS.cryptoSubtle.unwrapKey(
      'raw',
      wrappedKey,
      derivedKey,
      { name: 'AES-KW' },
      { name: algo },
      KRYPTOS.EXTRACTABLE,
      usage,
    )
  }

  const exportIAK = function(key) {
    return KRYPTOS.cryptoSubtle.exportKey('jwk', key)
  }

  let wrapIAKPSK = function(key) {
    log(' --- wrapIAKPSK --- ')
    log(IAKPSK || key)
    log(derivedKey)
    return KRYPTOS.cryptoSubtle.wrapKey('raw', IAKPSK || key, derivedKey, {
      name: 'AES-KW',
    })
  }

  let saveWrappedIAKPSK = function(wrappedKey) {
    log(' --- saveWrappedIAKPSK --- ')
    wrappedIAKPSK = wrappedKey
    log(wrappedKey)
  }

  let wrapIAKPDK = function(key) {
    log(' --- wrapIAKPDK --- ')
    log(derivedKey)
    log(IAKPDK)
    if (derivedKey.type === 'public') {
      return KRYPTOS.cryptoSubtle
        .exportKey('raw', IAKPDK || key)
        .then(exportedKey =>
          KRYPTOS.cryptoSubtle.encrypt(
            derivedKey.algorithm,
            derivedKey,
            exportedKey,
          ),
        )
    }
    return KRYPTOS.cryptoSubtle.wrapKey('raw', IAKPDK || key, derivedKey, {
      name: 'AES-KW',
    })
  }

  let saveWrappedIAKPDK = function(wrappedKey) {
    log(' --- saveWrappedIAKPDK --- ')
    wrappedIAKPDK = wrappedKey
    log(wrappedKey)
    // addPasswordProtector(keyContainerPDK, wrappedKey);
  }

  let addProtector = function(keyContainer, wrappedKey) {
    log(' --- addProtector --- ')
    if (derivedKey.type === 'public') {
      addAsymmetricProtector(keyContainer, wrappedKey)
    } else {
      addPasswordProtector(keyContainer, wrappedKey)
    }
  }

  let addPasswordProtector = function(keyContainer, wrappedKey) {
    if (!keyContainer) {
      return
    }
    keyContainer.keyProtectors.push({
      encryptedKey: KU.ab2b64(wrappedKey),
      type: 'password',
      name: deriveKeyAlgo.name,
      salt: KU.ab2b64(deriveKeyAlgo.salt),
      iterations: deriveKeyAlgo.iterations,
      hash: deriveKeyAlgo.hash,
    })
  }

  let addAsymmetricProtector = function(keyContainer, wrappedKey) {
    keyContainer.keyProtectors.push({
      encryptedKey: KU.ab2b64(wrappedKey),
      type: 'asymmetric',
      name: deriveKeyAlgo.name,
    })
  }

  // TODO
  const replacePasswordProtector = function(keyContainer, type, wrappedKey) {
    log('--- replacePasswordProtector ---')
    log(wrappedKey)
    log(KU.ab2b64(wrappedKey))
    let updated = false
    for (let i = 0; i < keyContainer.keyProtectors.length; i++) {
      if (
        keyContainer.keyProtectors[i].type &&
        keyContainer.keyProtectors[i].type === type
      ) {
        log('key container replaced!!!!!')
        keyContainer.keyProtectors[i] = {
          encryptedKey: KU.ab2b64(wrappedKey),
          type,
          name: deriveKeyAlgo.name,
          salt: KU.ab2b64(deriveKeyAlgo.salt),
          iterations: deriveKeyAlgo.iterations,
          hash: deriveKeyAlgo.hash,
        }
        updated = true
      }
    }
    if (!updated) {
      throw new Error(`No key protector found for ${type} to updated.`)
    }
  }

  let deriveKeyFromAsymmetric = function(keyStore, username) {
    log(' --- deriveKeyFromAsymmetric --- ')
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
      log(' --- deriveKeyFromAsymmetric error --- ')
      log(error)
    })
  }

  let deriveKeyFromPassword = function(password) {
    log(' --- deriveKeyFromPassword --- ')
    setDeriveKeyAlgo({
      name: 'PBKDF2',
      salt: KRYPTOS.randomValue(32),
      iterations: 20000,
      hash: 'SHA-256',
    })
    return importPassword(password)
  }

  let setDeriveKeyAlgo = function(algo) {
    deriveKeyAlgo = algo
  }

  const importAsymmetric = function(keyStore) {
    return keyStore
      .getPdk()
      .then(saveDerivedKey)
      .catch(error => {
        log(' --- importPassword error --- ')
        log(error)
      })
  }

  let importPassword = function(password) {
    log(' --- importPassword --- ')
    return KRYPTOS.cryptoSubtle
      .importKey(
        'raw',
        KU.str2ab(password),
        { name: 'PBKDF2' },
        false,
        KRYPTOS.DERIVE_USAGE,
      )
      .then(saveImportedPassword)
      .then(deriveKey)
      .then(saveDerivedKey)
      .catch(error => {
        log(' --- importPassword error --- ')
        log(error)
      })
  }

  let saveImportedPassword = function(password) {
    log(' --- saveImportedPassword --- ')
    importedPassword = password
    return importedPassword
  }

  let deriveKey = function(key) {
    log(' --- deriveKey --- ')
    log(key)
    return KRYPTOS.cryptoSubtle.deriveKey(
      deriveKeyAlgo,
      key,
      KRYPTOS.AES_KW_ALGO,
      KRYPTOS.NONEXTRACTABLE,
      KRYPTOS.WRAP_USAGE,
    )
  }

  const importDerivedKey = function(derivedPassword) {
    return KRYPTOS.cryptoSubtle
      .importKey(
        'raw',
        KU.hex2ab(derivedPassword),
        { name: 'AES-KW' },
        KRYPTOS.NONEXTRACTABLE,
        KRYPTOS.WRAP_USAGE,
      )
      .then(saveDerivedKey)
  }

  let saveDerivedKey = function(key) {
    derivedKey = key
  }

  /**
   * Export the public encryption key
   *
   * @returns {Promise} of exportKey
   */
  let exportPEK = function() {
    log(' --- exportPVK --- ')
    return KRYPTOS.cryptoSubtle.exportKey('jwk', encryptKeyPair.publicKey)
  }

  /**
   * Save the public encryption key.
   *
   * @param {Object} key
   * @returns {void}
   */
  let savePEK = function(key) {
    exportedPublicEncryptKey = key
    if (key.kty === 'EC') {
      // exportedPublicEncryptKey.alg = KRYPTOS.getECAlgo(key.crv);
      delete exportedPublicEncryptKey.ext
    }
  }

  /**
   * Export the public sign key.
   *
   * @returns {Promise} of exportKey
   */
  let exportPVK = function() {
    log(' --- exportPVK --- ')
    return KRYPTOS.cryptoSubtle.exportKey('jwk', signKeyPair.publicKey)
  }

  /**
   * Save the public sign key.
   *
   * @param {Object} key
   * @returns {void}
   */
  let savePVK = function(key) {
    return new Promise((resolve, reject) => {
      exportedPublicVerifyKey = key
      if (key.kty === 'EC') {
        // exportedPublicVerifyKey.alg = KRYPTOS.getECAlgo(key.crv);
        delete exportedPublicVerifyKey.ext
      }
      resolve(exportedPublicVerifyKey)
    })
  }

  let fingerprint = function(key) {
    return KRYPTOS.cryptoSubtle.digest(KRYPTOS.SHA_256.name, KU.jwk2ab(key))
  }

  let importIAKPDK = function(extractable) {
    log(' --- importIAKPDK --- ')
    const jwk = JSON.parse(KRYPTOS.session.getItem(prefixIAKPDK))
    log(jwk)
    return importIAK(jwk, extractable)
  }

  const importIAKPSK = function(extractable) {
    const jwk = JSON.parse(KRYPTOS.session.getItem(prefixIAKPSK))
    return importIAK(jwk, extractable)
  }

  let importIAK = function(jwk, extractable) {
    const unwrapAlgo = KRYPTOS.getAlgo(keyContainerPSK.protectType)
    return KRYPTOS.cryptoSubtle.importKey(
      'jwk',
      jwk,
      unwrapAlgo.name,
      extractable,
      ['unwrapKey', 'wrapKey', 'decrypt'],
    )
  }

  const getPdk = function(callback) {
    log(' --- getPdk --- ')
    if (cachePDK) {
      if (cachedPDK !== null) {
        log('cachedPDK')
        return new Promise((resolve, reject) => {
          resolve(cachedPDK)
        })
        // return cachedPDK;
      }
      return importIAKPDK(KRYPTOS.NONEXTRACTABLE)
        .then(unwrapPDK)
        .then(pdk => {
          cachedPDK = pdk
          log(cachedPDK)
          return cachedPDK
        })
        .catch(error => {
          KU.log(error)
          //                    callback(false, error.message ? error.message : error);
        })
    }
  }

  let unwrapPDK = function(key) {
    log(' --- unwrapPDK --- ')
    log(key)
    wrappedPDK = KU.b642ab(keyContainerPDK.encryptedKey)
    ivPDK = KU.b642ab(keyContainerPDK.iv)
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
          const decryptedKey = KU.ab2json(result)
          return KRYPTOS.cryptoSubtle.importKey(
            'jwk',
            decryptedKey,
            unwrappedKeyAlgo,
            false,
            usages,
          )
        })
    }
    return KRYPTOS.cryptoSubtle.unwrapKey(
      'jwk',
      wrappedPDK,
      key,
      { name: unwrapAlgo.name, iv: ivPDK },
      unwrappedKeyAlgo,
      KRYPTOS.NONEXTRACTABLE,
      usages,
    )
  }

  const getPsk = function() {
    if (cachePSK) {
      if (cachedPSK !== null) {
        return new Promise((resolve, reject) => {
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
          log(cachedPSK)
          return cachedPSK
        })
    }
  }

  let unwrapPSK = function(key) {
    log(' --- unwrapPSK --- ')
    log(key)
    wrappedPSK = KU.b642ab(keyContainerPSK.encryptedKey)
    ivPSK = KU.b642ab(keyContainerPSK.iv)
    const unwrapAlgo = KRYPTOS.getAlgo(keyContainerPSK.protectType)
    const unwrappedKeyAlgo = KRYPTOS.getAlgo(keyContainerPSK.keyType)
    if (isEC()) {
      // Firefox fix for missing AES-GCM unwrapKey for ECDSA
      return KRYPTOS.cryptoSubtle
        .decrypt({ name: unwrapAlgo.name, iv: ivPSK }, key, wrappedPSK)
        .then(result => {
          const decryptedKey = KU.ab2json(result)
          return KRYPTOS.cryptoSubtle.importKey(
            'jwk',
            decryptedKey,
            unwrappedKeyAlgo,
            false,
            ['sign'],
          )
        })
    }
    return KRYPTOS.cryptoSubtle.unwrapKey(
      'jwk',
      wrappedPSK,
      key,
      { name: unwrapAlgo.name, iv: ivPSK },
      unwrappedKeyAlgo,
      KRYPTOS.NONEXTRACTABLE,
      ['sign'],
    )
  }

  const getPek = function() {
    log('--- getPek ---')
    const pek = JSON.parse(KRYPTOS.session.getItem(prefixPEK))
    log(pek)
    return importPek(pek, ['encrypt'])
  }

  const getPvk = function(jwk) {
    log('--- getPvk ---')
    const pvk = JSON.parse(KRYPTOS.session.getItem(prefixPVK))
    if (jwk) {
      return pvk
    }
    log(pvk)
    return importPvk(pvk, ['verify'])
  }

  const setPek = function(pek) {
    exportedPublicEncryptKey = pek
  }

  const setPvk = function(pvk) {
    exportedPublicVerifyKey = pvk
  }

  const setPublicKeys = function(username, publicKeys) {
    KRYPTOS.session.setItem(publicKeyPrefix + username, publicKeys)
  }

  let importPvk = function(publicKey) {
    let alg = publicKey.alg
    if (publicKey.kty === 'EC') {
      alg = 'ECDSA'
      delete publicKey.alg
    }
    const algo = KRYPTOS.getAlgo(alg)
    return KRYPTOS.cryptoSubtle.importKey('jwk', publicKey, algo, false, [
      'verify',
    ])
  }

  let importPek = function(publicKey, usages) {
    let alg = publicKey.alg
    if (publicKey.kty === 'EC') {
      alg = 'ECDH'
      delete publicKey.alg
      delete publicKey.key_ops
    }
    const algo = KRYPTOS.getAlgo(alg)
    return KRYPTOS.cryptoSubtle.importKey('jwk', publicKey, algo, false, usages)
  }

  const getPublicKey = function(userId, type, callback) {
    return new Promise((resolve, reject) => {
      if (KU.isObject(userId)) {
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
        // let pub_keys = JSON.parse(keys.public_keys);
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
        Contacts.getContactFromCache(userId, contact => {
          console.log('retrieved contact')
          console.dir(contact)
          const publicKeys = KRYPTOS.session.getItem(publicKeyPrefix + userId)
          let publicKey = {}
          if (publicKeys) {
            const keys = JSON.parse(publicKeys)
            // let pub_keys = JSON.parse(keys.public_keys);
            if (type === 'verify') {
              publicKey = keys.verify
            } else {
              publicKey = keys.encrypt
            }
            if (callback) {
              callback(publicKey)
            }
            resolve(publicKey)
          }
        })
        //                KRYPTOS.Contacts.getServicePublicKeys([userId], service, function() {
        //                    return getPublicKey(userId, type, callback);
        //                });
      }
    })
  }

  /**
   * Retrieve the public keys.
   *
   * @param {String} emails
   * @param {function} callback
   * @returns {undefined}
   */
  const getPublicKeys = function(emails, callback) {
    if (KU.isEmpty(emails)) {
      callback(false, 'No emails provided.')
      return
    }
    let usernames = ''
    if (emails.length > 10) {
      callback(false, 'Max 10 recipients allowed.')
      return
    }
    for (let i = 0; i < emails.length; i++) {
      const username = emails[i]
      if (
        KRYPTOS.session.getItem(publicKeyPrefix + username) ||
        username === ''
      )
        continue // Skip if we already got the public keys in sessionStorage
      usernames += `${username},`
    }
    if (usernames === '') {
      callback(true, 'Done!')
      return
    }

    const jqxhr = $.getJSON(
      `/keys/public?service=${service}&usernames=${usernames}`,
      data => {
        if (data) {
          for (let i = 0; i < data.length; i++) {
            KRYPTOS.session.setItem(
              publicKeyPrefix + data[i].username,
              data[i].public_keys,
            )
          }
        }
        callback(true, '')
      },
    )
    jqxhr.fail(response => {
      const $er = $.parseJSON(jqxhr.responseText)
      callback(false, $er.errors.username)
    })
  }

  const getRecipientPublicKeys = function(username) {
    return JSON.parse(KRYPTOS.session.getItem(publicKeyPrefix + username))
  }

  /**
   * Retrieve the public keys.
   *
   * @param {String} emails
   * @param {function} callback
   * @returns {undefined}
   */
  const getRecipientsPublicKeys = function(emails, callback) {
    if (KRYPTOS.utils.isEmpty(emails)) {
      callback(false, 'No emails provided.')
      return
    }
    let usernames = ''
    //        let maxRecipients = parseInt(KRYPTOS.session.getItem('max_recipients'));
    //        if (emails.length > maxRecipients) {
    //            callback(false, "Max " + maxRecipients + " recipients allowed.");
    //            return;
    //        }
    //          TODO: cleanup
    //        for (let i = 0; i < emails.length; i++) {
    //            let username = emails[i];
    //            if (KRYPTOS.session.getItem(KRYPTOS.Keys.prefix + username) || username === '') continue; // Skip if we already got the public keys in sessionStorage
    //            log(emails[i]);
    //            emails[i] = encodeURIComponent(username);
    //            log(emails[i]);
    //        }
    const temp = []
    for (let i = 0; i < emails.length; i++) {
      const username = emails[i]

      if (
        KRYPTOS.session.getItem(publicKeyPrefix + username) ||
        username === ''
      )
        continue // Skip if we already got the public keys in sessionStorage
      temp.push(encodeURIComponent(username))
      //            usernames += encodeURIComponent(username) + ",";
    }
    if (temp.length === 0) {
      return callback(true, 'Done!')
      // return;
    }
    usernames = temp.join(',')
    KRYPTOS.API.getPublicKeys(
      { service, usernames },
      data => {
        if (data) {
          for (let i = 0; i < data.length; i++) {
            KRYPTOS.session.setItem(
              publicKeyPrefix + data[i].username,
              data[i].public_keys,
            )
          }
        }
        callback(true, '')
      },
      error => {
        log(error)
        callback(false, error)
      },
    )
  }

  const setToken = function(token) {
    confirmationToken = token
  }

  const unlockFromDerivedKey = function(protector, pek, pvk) {
    return importDerivedKey(protector).then(() => unlock(derivedKey, pek, pvk))
  }

  let unlock = function(protector, pek, pvk, signature) {
    return new Promise((resolve, reject) => {
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

      return unlockPsk(protector)
        .then(() =>
          unlockPdk(protector)
            .then(() => {
              resolve({ success: true, keyStore: this })
            })
            .catch(error => {
              KU.log(error)
              reject({})
            }),
        )
        .catch(error => {
          KU.log(error)
          reject({})
        })
    })
  }

  const unlockPrivateKey = function(protector, keyContainer, keyContainerType) {
    let protectorType = 'password'

    let derivedKeyProtector = null

    // From derived CryptoKey
    // derivedKeyProtector = importDerivedKey(protector);
    if (protector instanceof Object) {
      protectorType = 'asymmetric'
      derivedKeyProtector = importAsymmetric(protector)
    } else {
      derivedKeyProtector = importPassword(protector)
    }

    const keyProtector = extractKeyProtector(keyContainerType, protectorType)
    if (keyProtector.type === 'password') {
      setDeriveKeyAlgo({
        name: keyProtector.name,
        salt: KU.b642ab(keyProtector.salt),
        iterations: keyProtector.iterations,
        hash: keyProtector.hash,
      })
    }
    const algo = KRYPTOS.getAlgo(keyContainer.protectType)
    return derivedKeyProtector
      .then(() => unwrapIAK(KU.b642ab(keyProtector.encryptedKey), algo.name))
      .then(exportIAK)
      .catch(error => {
        KU.log(error)
        return new Promise((resolve, reject) => {
          reject(error)
        })
      })
  }

  let unlockPdk = function(protector) {
    return new Promise((resolve, reject) => {
      if (!keyContainerPDK) {
        resolve()
        return
      }

      return unlockPrivateKey(protector, keyContainerPDK, 'PDK')
        .then(exportedKey => {
          KRYPTOS.session.setItem(prefixIAKPDK, JSON.stringify(exportedKey))
          resolve()
        })
        .catch(error => {
          KU.log(error)
          reject(error)
        })
    })
  }

  let unlockPsk = function(protector) {
    return new Promise((resolve, reject) => {
      if (!keyContainerPSK) {
        resolve()
        return
      }

      return unlockPrivateKey(protector, keyContainerPSK, 'PSK')
        .then(exportedKey => {
          log('exportedKey')
          log(exportedKey)
          KRYPTOS.session.setItem(prefixIAKPSK, JSON.stringify(exportedKey))
          resolve()
        })
        .catch(error => {
          KU.log(error)
          reject(error)
        })
    })
  }

  const lockPsk = function() {
    return new Promise((resolve, reject) => {
      if (!keyContainerPSK) {
        resolve()
        return
      }
      return importIAKPSK(KRYPTOS.EXTRACTABLE)
        .then(wrapIAKPSK)
        .then(wrappedKey => {
          replacePasswordProtector(keyContainerPSK, 'password', wrappedKey)
          resolve()
        })
        .catch(error => {
          KU.log(error)
          reject(error)
        })
    })
  }

  const lockPdk = function() {
    return new Promise((resolve, reject) => {
      if (!keyContainerPDK) {
        resolve()
        return
      }
      return importIAKPDK(KRYPTOS.EXTRACTABLE)
        .then(wrapIAKPDK)
        .then(wrappedKey => {
          replacePasswordProtector(keyContainerPDK, 'password', wrappedKey)
          resolve()
        })
        .catch(error => {
          KU.log(error)
          reject(error)
        })
    })
  }

  const lock = function(password, type = 'password') {
    return new Promise((resolve, reject) =>
      deriveKeyFromPassword(password)
        .then(() => {
          lockPsk(type)
        })
        .then(() => {
          lockPdk(type)
        })
        .then(() => {
          const data = {}
          data[service] = {
            pdk: keyContainerPDK,
            psk: keyContainerPSK,
          }
          resolve(data)
        })
        .catch(error => {
          KU.log(error)
          reject({ success: false })
        }),
    ).catch(error => {
      KU.log(error)
      reject({})
    })
  }

  let setMode = function(keyStoreMode) {
    switch (keyStoreMode) {
      case 'RSA':
      case 'EC':
        break
      default:
        throw new Error('Invalid algorithm3')
    }
    mode = keyStoreMode
  }

  const getMode = function() {
    return mode
  }

  let isEC = function() {
    return mode === 'EC'
  }

  const isRSA = function() {
    return mode === 'RSA'
  }

  const init = function() {
    keyContainerPDK = JSON.parse(KRYPTOS.session.getItem(prefixPDK))
    keyContainerPSK = JSON.parse(KRYPTOS.session.getItem(prefixPSK))
    setMode(KRYPTOS.getAsymmetricModeByAlgo(keyContainerPSK.keyType))
    setCachePsk(true)
    setCachePdk(true)
  }

  return {
    init,
    setMode,
    getMode,
    isEC,
    isRSA,
    justSetUp,
    setSetUp,
    setToken,
    isLoaded,
    setCachePsk,
    setCachePdk,
    setupKeys,
    setupSignKeys,
    setupEncryptKeys,
    unlock,
    lock,
    getPek,
    getPvk,
    getPdk,
    getPsk,
    setPek,
    setPvk,
    getPublicKey,
    setPublicKeys,
    getPublicKeys,
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
