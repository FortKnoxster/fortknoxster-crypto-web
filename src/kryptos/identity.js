import { getPublicKey, getPrivateKey } from './serviceKeyStore'
import { PSK, PVK, SERVICES } from './constants'
import { RSA } from './algorithms'
import { ecJwk, rsaJwk } from './utils'
import { importPublicVerifyKey } from './keys'
import { signIt } from './signer'
import { verifyIt } from './verifier'

export function signData(data, service) {
  return signIt(data, getPrivateKey(service, PSK))
}

export async function verifyData(data, signature) {
  try {
    const importedPvk = await importPublicVerifyKey(
      getPublicKey(SERVICES.identity, PVK),
    )
    return verifyIt(importedPvk, signature, data)
  } catch (e) {
    return Promise.reject(e)
  }
}

export function verifyContactKeys(contact) {
  const { keys } = contact
  return Object.keys(keys)
    .filter(key => key !== SERVICES.identity)
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
