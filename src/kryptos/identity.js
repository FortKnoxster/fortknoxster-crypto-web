import { RSA } from './algorithms'
import { ecJwk, rsaJwk } from './utils'
import { importPublicVerifyKey } from './keys'
import { signIt } from './signer'
import { verifyIt } from './verifier'

const identity = {
  keyStore: null,
}

export function initIdentity(keyStore) {
  identity.keyStore = keyStore
  Object.freeze(identity.keyStore)
  Object.freeze(identity)
}

export async function verifyData(data, signature) {
  const importedPvk = await importPublicVerifyKey(
    identity.keyStore.keyContainers.pvk,
  )
  return verifyIt(importedPvk, signature, data)
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
