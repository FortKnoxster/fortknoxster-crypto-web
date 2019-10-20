import { RSA } from './algorithms'
import {
  base64ToArrayBuffer,
  ecJwk,
  rsaJwk,
  stringToArrayBuffer,
} from './utils'
import { Decrypter } from './core/kryptos.decrypter'
import { signIt } from './signer'

const identity = {
  keyStore: null,
}

export function initIdentity(keyStore) {
  identity.keyStore = keyStore
  Object.freeze(identity.keyStore)
  Object.freeze(identity)
}

// Todo: remove legacy
export function verifyIt(data, signature, contact) {
  const { keyStore } = identity
  const decrypter = new Decrypter(
    keyStore,
    null,
    null,
    stringToArrayBuffer(JSON.stringify(data)),
    base64ToArrayBuffer(signature),
  )
  return decrypter.verifyIt(contact, contact.contactUserId)
}

// Todo: remove legacy
export function verifyContact(contactToVerify, contact) {
  const { keyStore } = identity
  const { signature } = contact
  const decrypter = new Decrypter(
    keyStore,
    null,
    null,
    stringToArrayBuffer(JSON.stringify(contactToVerify)),
    base64ToArrayBuffer(signature),
  )
  return decrypter.verifyIt(contact.userId, contact.contactUserId)
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
