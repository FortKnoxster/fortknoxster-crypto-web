import { getAlgorithm, deriveKeyPBKDF2 } from './algorithms'
import { randomValue, arrayBufferToBase64 } from './utils'
import { deriveKeyFromPassword } from './derive'
import { importWrapKey } from './keys'
import { PROTECTOR_ITERATIONS, LENGTH_32 } from './constants'

export function packProtector(wrappedKey, algorithm, type) {
  return {
    encryptedKey: arrayBufferToBase64(wrappedKey),
    type,
    name: algorithm.name,
    ...(algorithm.salt && { salt: arrayBufferToBase64(algorithm.salt) }),
    ...(algorithm.iterations && { iterations: algorithm.iterations }),
    hash: algorithm.hash, // Todo extract name from hash object when type asymmetric
    // Todo: add id/label to identify admin user
  }
}

export async function newSymmetricProtector(password) {
  const salt = randomValue(LENGTH_32)
  const iterations = PROTECTOR_ITERATIONS
  const algorithm = deriveKeyPBKDF2(salt, iterations)
  const key = await deriveKeyFromPassword(password, salt, iterations)
  return {
    algorithm,
    key,
  }
}

export async function importProtector(protector) {
  const key = await importWrapKey(protector)
  const algorithm = getAlgorithm(protector.alg)
  return {
    algorithm,
    key,
  }
}

export function getProtector(protector) {
  if (typeof protector === 'string') {
    return newSymmetricProtector(protector)
  }
  if (typeof protector === 'object') {
    return importProtector(protector)
  }
  if (protector instanceof CryptoKey) {
    return {
      algorithm: getAlgorithm(protector.alg),
      key: protector,
    }
  }
  throw new Error('Invalid protector.')
}
