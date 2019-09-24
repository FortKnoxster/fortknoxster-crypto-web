import { kryptos } from '../kryptos'
import * as algorithms from '../algorithms'
import * as formats from '../formats'
import * as usage from '../usages'
import { NONEXTRACTABLE } from '../constants'

export function importSessionKey(keyBytes, algorithm) {
  return kryptos.subtle.importKey(
    formats.RAW,
    keyBytes,
    algorithm || algorithms.AES_CBC_ALGO,
    NONEXTRACTABLE,
    usage.ENCRYPT,
  )
}

export function importEncryptionKey(keyBytes, algorithm) {
  return kryptos.subtle.importKey(
    formats.RAW,
    keyBytes,
    algorithm || algorithms.AES_CBC_ALGO,
    NONEXTRACTABLE,
    usage.ENCRYPT,
  )
}

export function importPublicVerifyKey(publicKey) {
  if (publicKey.kty === algorithms.EC) {
    const algorithm = algorithms.getAlgorithm(algorithms.ECDSA_ALGO.name)
    // eslint-disable-next-line no-param-reassign
    delete publicKey.alg
    return kryptos.subtle.importKey(
      formats.JWK,
      publicKey,
      algorithm,
      NONEXTRACTABLE,
      usage.VERIFY_ONLY,
    )
  }
  const algorithm = algorithms.getAlgorithm(publicKey.alg)
  return kryptos.subtle.importKey(
    formats.JWK,
    publicKey,
    algorithm,
    NONEXTRACTABLE,
    usage.VERIFY_ONLY,
  )
}

export function importPublicEncryptionKey(publicKey) {
  if (publicKey.kty === algorithms.EC) {
    const algorithm = algorithms.getAlgorithm(algorithms.ECDH_ALGO.name)
    // eslint-disable-next-line no-param-reassign
    delete publicKey.alg
    // eslint-disable-next-line no-param-reassign
    delete publicKey.key_ops
    return kryptos.subtle.importKey(
      formats.JWK,
      publicKey,
      algorithm,
      NONEXTRACTABLE,
      usage.ENCRYPT_ONLY,
    )
  }
  const algorithm = algorithms.getAlgorithm(publicKey.alg)
  return kryptos.subtle.importKey(
    formats.JWK,
    publicKey,
    algorithm,
    NONEXTRACTABLE,
    usage.ENCRYPT_ONLY,
  )
}
