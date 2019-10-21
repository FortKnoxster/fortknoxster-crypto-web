import { KeyStore } from './core/kryptos.keystore'
import { setupIdentityKeys, setupKeys, unlock, init } from './keystore'
import {
  ECDSA_ALGO,
  ECDH_ALGO,
  RSASSA_PKCS1_V1_5_ALGO,
  RSA_OAEP_ALGO,
} from './algorithms'
import { SERVICES } from './constants'
import { initIdentity } from './identity'
import { initStorage } from './storage'
import { initProtocol } from './protocol'
import { initChat } from './chat'

export async function initKeyStores(keyStores, type, nodeId, userId) {
  const serviceKeyStores = await Promise.all(
    keyStores.map(keyStore => init(keyStore.id, keyStore, type)),
  )
  initProtocol(
    serviceKeyStores.find(keyStore => keyStore.id === SERVICES.protocol),
    nodeId,
    userId,
  )
  initIdentity(
    serviceKeyStores.find(keyStore => keyStore.id === SERVICES.identity),
  )
  initStorage(
    serviceKeyStores.find(keyStore => keyStore.id === SERVICES.storage),
  )
  initChat(serviceKeyStores.find(keyStore => keyStore.id === SERVICES.mail))
  return true
}

export function unlockKeyStores(keyStores, password, type) {
  return Object.keys(keyStores).map(service =>
    unlock(service, keyStores[service], password, type),
  )
}

export function lockKeyStores(keys, password, type) {
  return Object.values(keys).map(k => k.lock(password, type))
}

export function verifyKeyProtector(keys, password, type) {
  const promises = Object.values(keys).map(k =>
    k.verifyProtector(password, type),
  )
  return Promise.all(promises)
}

export function generateIdentityKeys(password) {
  return setupIdentityKeys('identity', password, ECDSA_ALGO)
}

export function newKeyStore(service, mode) {
  return new KeyStore(service, null, null, mode)
}

export function newKeyStores(serviceKeys) {
  return serviceKeys.map(serviceKey =>
    newKeyStore(serviceKey.service, serviceKey.mode),
  )
}

export function setupKeyStore(
  service,
  protector,
  identityKeyStore,
  protectorType,
  rsa = true,
  protectorIdentifier,
) {
  if (rsa) {
    return setupKeys(
      service,
      protector,
      identityKeyStore,
      RSASSA_PKCS1_V1_5_ALGO,
      RSA_OAEP_ALGO,
      protectorType,
      protectorIdentifier,
    )
  }
  return setupKeys(
    service,
    protector,
    identityKeyStore,
    ECDSA_ALGO,
    ECDH_ALGO,
    protectorType,
    protectorIdentifier,
  )
}
