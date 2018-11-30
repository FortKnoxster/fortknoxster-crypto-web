import { RSA } from './algorithms'
import {
  base64ToArrayBuffer,
  ecJwk,
  rsaJwk,
  stringToArrayBuffer,
} from './utils'
import { Decrypter } from '../legacy/kryptos.decrypter'

let keyStore

export function verifyIt(keys, signature, contact) {
  const decrypter = new Decrypter(
    keyStore,
    null,
    null,
    stringToArrayBuffer(JSON.stringify(keys)),
    base64ToArrayBuffer(signature),
  )
  return decrypter.verifyIt(contact, contact.contactUserId)
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

export function initIdentity(kStore) {
  keyStore = kStore
}
