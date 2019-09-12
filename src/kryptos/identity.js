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
    // eslint-disable-next-line camelcase
    contact.contacts_keys_hmac = signedKeys.signature
    const encrypter = new Encrypter(keyStore, null, null, dummyCB)
    return encrypter.signIt(contact, false)
  } catch (e) {
    return Promise.reject(e)
  }
}

export function createIdentity(identityKeyStore, id, pvk) {
  console.log('createIdentity identityKeyStore', identityKeyStore)
  console.log('createIdentity id', id)
  const encrypter = new Encrypter(identityKeyStore, null, null, dummyCB)
  const identity = {
    id,
    pvk,
    signature: '',
  }
  return encrypter.signIt(identity, true)
}
