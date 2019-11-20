// eslint-disable-next-line import/no-cycle
import {
  getPublicKey,
  getPrivateKey,
  setupKeyStore,
  generateIdentityKeys,
} from './serviceKeyStore'
import { PSK, PVK, SERVICES, PROTECTOR_TYPES } from './constants'
import { toJwk } from './utils'
import { importPublicVerifyKey } from './keys'
import { signIt } from './signer'
import { verifyIt } from './verifier'

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

export function signPublicKeys(privateKey, publicEncryptKey, publicVerifyKey) {
  const publicKeys = {
    pek: toJwk(publicEncryptKey),
    pvk: toJwk(publicVerifyKey),
  }
  return signIt(publicKeys, privateKey)
}

export async function verifyPublicKeys(keys, publicKey) {
  try {
    const importedPublicKey = await importPublicVerifyKey(publicKey)
    return Object.keys(keys)
      .filter(key => key !== SERVICES.identity)
      .map(key => {
        const { encrypt, verify, signature } = keys[key]
        const keysToVerify = {
          pek: toJwk(encrypt),
          pvk: toJwk(verify),
        }
        return verifyIt(importedPublicKey, signature, keysToVerify)
      })
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
      serviceKeys.map(serviceKey =>
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
