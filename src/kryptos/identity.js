/* eslint-disable camelcase */
/* eslint-disable no-param-reassign */
import { RSA } from './algorithms'
import {
  base64ToArrayBuffer,
  ecJwk,
  rsaJwk,
  stringToArrayBuffer,
} from './utils'
import { Decrypter } from './core/kryptos.decrypter'
import { signIt } from './signer'

let keyStore

export function initIdentity(kStore) {
  keyStore = kStore
}

export function verifyIt(data, signature, contact) {
  const decrypter = new Decrypter(
    keyStore,
    null,
    null,
    stringToArrayBuffer(JSON.stringify(data)),
    base64ToArrayBuffer(signature),
  )
  return decrypter.verifyIt(contact, contact.contactUserId)
}

export function verifyContact(contactToVerify, contact) {
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
  const identity = {
    id,
    pvk,
    signature: '',
  }
  try {
    const signature = await signIt(identity, identityPrivateKey)
    identity.signature = signature
    return identity
  } catch (e) {
    return Promise.reject(e)
  }
}
