import { RSA } from './algorithms'
import {
  base64ToArrayBuffer,
  dummyCB,
  ecJwk,
  rsaJwk,
  stringToArrayBuffer,
} from './utils'
import { Decrypter } from '../legacy/kryptos.decrypter'
import { Encrypter } from '../legacy/kryptos.encrypter'

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

function signContactKeys(keys, hmacKey) {
  const encrypter = new Encrypter(keyStore, null, null, dummyCB)
  return encrypter.macSignIt(keys, hmacKey)
}

export async function signContact(contactToSign, hmacKey) {
  const {
    contact,
    contact_keys: { contact_keys },
  } = contactToSign
  try {
    const signedKeys = await signContactKeys(contact_keys, hmacKey)
    const encrypter = new Encrypter(keyStore, null, null, dummyCB)
    const signedContact = await encrypter.signIt(contact, false)
    return {
      keySignature: signedKeys.signature,
      contactSignature: signedContact.signature,
    }
  } catch (e) {
    return Promise.reject(e)
  }
}
