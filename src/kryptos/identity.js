import { RSA } from './algorithms'
import { ecJwk, rsaJwk } from './utils'
import { importPublicVerifyKey } from './keys'
import { signIt } from './signer'
import { verifyIt } from './verifier'

const identity = {
  keyStore: null,
}

export async function verifyData(data, signature) {
  try {
    const importedPvk = await importPublicVerifyKey(
      identity.keyStore.keyContainers.pvk,
    )
    return verifyIt(importedPvk, signature, data)
  } catch (e) {
    return Promise.reject(e)
  }
}

export function verifyContactKeys(contact) {
  const { keys } = contact
  return Object.keys(keys)
    .filter(key => key !== 'identity')
    .map(key => {
      const { encrypt, verify, signature } = keys[key]
      const keysToVerify = {
        pek: encrypt.kty === RSA ? rsaJwk(encrypt) : ecJwk(encrypt),
        pvk: encrypt.kty === RSA ? rsaJwk(verify) : ecJwk(verify),
      }
      return verifyIt(keysToVerify, signature, contact)
    })
}

export async function createIdentity(identityPrivateKey, id, pvk) {
  const certificate = {
    id,
    pvk,
    signature: '',
  }
  try {
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

export async function initIdentity(keyStore, id) {
  identity.keyStore = keyStore
  Object.freeze(identity.keyStore)
  Object.freeze(identity)
  try {
    const certificate = await createIdentity(
      identity.keyStore.psk.privateKey,
      id,
      identity.keyStore.keyContainers.pvk,
    )
    return verifyIdentity(certificate)
  } catch (e) {
    return Promise.reject(e)
  }
}
