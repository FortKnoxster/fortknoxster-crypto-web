import {
  getPublicKey,
  getPrivateKey,
  setupKeyStore,
  generateIdentityKeys,
} from './serviceKeyStore.js'
import { PSK, PVK, SERVICES, PROTECTOR_TYPES } from './constants.js'
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

const serviceKeys = [
  { service: SERVICES.mail, rsa: true },
  { service: SERVICES.storage, rsa: true },
  { service: SERVICES.protocol, rsa: false },
]

export async function generateUserKeys(id, plainPassword) {
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
          serviceKey.rsa,
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
