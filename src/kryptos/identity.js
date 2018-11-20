import { RSA } from './algorithms'
import {
  base64ToArrayBuffer,
  ecJwk,
  rsaJwk,
  stringToArrayBuffer,
} from './utils'
import { Decrypter } from '../legacy/kryptos.decrypter'

let keyStore

export function verifyIt(keys, signature, publicKey, userId) {
  const decrypter = new Decrypter(
    keyStore,
    null,
    null,
    stringToArrayBuffer(keys),
    base64ToArrayBuffer(signature),
  )
  return decrypter.verifyIt(publicKey, userId)
}

export function verifyContactKeys(keys, contactId) {
  return Object.keys(keys)
    .filter(key => key !== 'identity')
    .map(key => {
      const { encrypt, verify, signature } = keys[key]
      const keysToVerify = {
        pek: encrypt.kty === RSA ? rsaJwk(encrypt) : ecJwk(encrypt),
        pvk: encrypt.kty === RSA ? rsaJwk(verify) : ecJwk(verify),
      }
      return verifyIt(keysToVerify, signature, keys.identity, contactId)
    })
}

export function initIdentity(kStore) {
  keyStore = kStore
}
