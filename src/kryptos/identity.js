import {
  getPublicKey,
  getPrivateKey,
  setupKeyStore,
  generateIdentityKeys,
} from './serviceKeyStore.js'
import { PSK, PVK, SERVICES, PROTECTOR_TYPES } from './constants.js'
import {
  ECDSA_ALGO,
  ECDH_ALGO,
  RSASSA_PKCS1_V1_5_ALGO,
  RSA_OAEP_ALGO,
  RSA_PSS_ALGO_4K,
  RSA_OAEP_ALGO_4K,
  RSA_PSS_ALGO_8K,
  RSA_OAEP_ALGO_8K,
} from './algorithms.js'
import { importPublicVerifyKey } from './keys.js'
import { signIt, sign } from './signer.js'
import { verifyIt, verify } from './verifier.js'

export function signWithIdentity(data) {
  return sign(data, getPrivateKey(SERVICES.identity, PSK))
}

export async function verifyWithIdentity(data, signature) {
  try {
    const importedPvk = await importPublicVerifyKey(
      getPublicKey(SERVICES.identity, PVK),
    )
    return verify(importedPvk, signature, data)
  } catch (e) {
    return Promise.reject(e)
  }
}

export function signData(data, service) {
  return signIt(data, getPrivateKey(service, PSK))
}

export async function verifyData(data, signature, publicKey) {
  try {
    const importedPvk = await importPublicVerifyKey(
      publicKey || getPublicKey(SERVICES.identity, PVK),
    )
    return verifyIt(importedPvk, signature, data)
  } catch (e) {
    return Promise.reject(e)
  }
}

export async function createIdentity(identityPrivateKey, id, pvk) {
  try {
    const certificate = {
      id,
      pvk,
      signature: '',
    }
    const signature = await signIt(certificate, identityPrivateKey)
    certificate.signature = signature
    return certificate
  } catch (e) {
    return Promise.reject(e)
  }
}

export async function verifyIdentity(certificate) {
  try {
    const importedPvk = await importPublicVerifyKey(certificate.pvk)
    const { id, pvk, signature } = certificate
    const certificateToVerify = {
      id,
      pvk,
      signature: '',
    }
    return verifyIt(importedPvk, signature, certificateToVerify)
  } catch (e) {
    return Promise.reject(e)
  }
}

export async function initIdentity(id) {
  try {
    const certificate = await createIdentity(
      getPrivateKey(SERVICES.identity, PSK),
      id,
      getPublicKey(SERVICES.identity, PVK),
    )
    return verifyIdentity(certificate)
  } catch (e) {
    return Promise.reject(e)
  }
}

export async function generateServiceKeys(id, plainPassword, serviceKeys) {
  try {
    const identityKeyStore = await generateIdentityKeys(plainPassword)

    const certificate = await createIdentity(
      identityKeyStore.psk.privateKey,
      id,
      identityKeyStore.keyContainers.pvk,
    )

    const serviceKeyStores = await Promise.all(
      serviceKeys.map((serviceKey) =>
        setupKeyStore(
          serviceKey.service,
          plainPassword,
          identityKeyStore.psk.privateKey,
          PROTECTOR_TYPES.password,
          serviceKey.signAlgorithm,
          serviceKey.encryptAlgorithm,
          serviceKey.protectorIterations,
        ),
      ),
    )
    serviceKeyStores.push(identityKeyStore)

    const keyContainers = serviceKeyStores.reduce(
      (acc, keyStore) =>
        Object.assign(acc, { [keyStore.id]: keyStore.keyContainers }),
      {},
    )
    return {
      certificate,
      keyContainers,
      serviceKeyStores,
    }
  } catch (e) {
    return Promise.reject(e)
  }
}

export function generateUserKeys(id, plainPassword) {
  const serviceKeys = [
    {
      service: SERVICES.mail,
      signAlgorithm: RSASSA_PKCS1_V1_5_ALGO,
      encryptAlgorithm: RSA_OAEP_ALGO,
    },
    {
      service: SERVICES.storage,
      signAlgorithm: RSASSA_PKCS1_V1_5_ALGO,
      encryptAlgorithm: RSA_OAEP_ALGO,
    },
    {
      service: SERVICES.protocol,
      signAlgorithm: ECDSA_ALGO,
      encryptAlgorithm: ECDH_ALGO,
    },
  ]
  return generateServiceKeys(id, plainPassword, serviceKeys)
}

// RSA 4096
export function generateUserKeys4K(
  id,
  plainPassword,
  protectorIterations = null,
) {
  const serviceKeys = [
    {
      service: SERVICES.storage,
      signAlgorithm: RSA_PSS_ALGO_4K,
      encryptAlgorithm: RSA_OAEP_ALGO_4K,
      protectorIterations,
    },
    {
      service: SERVICES.protocol,
      signAlgorithm: ECDSA_ALGO,
      encryptAlgorithm: ECDH_ALGO,
      protectorIterations,
    },
  ]
  return generateServiceKeys(id, plainPassword, serviceKeys)
}

// RSA 8192
export function generateUserKeys8K(
  id,
  plainPassword,
  protectorIterations = null,
) {
  const serviceKeys = [
    {
      service: SERVICES.storage,
      signAlgorithm: RSA_PSS_ALGO_8K,
      encryptAlgorithm: RSA_OAEP_ALGO_8K,
      protectorIterations,
    },
    {
      service: SERVICES.protocol,
      signAlgorithm: ECDSA_ALGO,
      encryptAlgorithm: ECDH_ALGO,
      protectorIterations,
    },
  ]
  return generateServiceKeys(id, plainPassword, serviceKeys)
}
