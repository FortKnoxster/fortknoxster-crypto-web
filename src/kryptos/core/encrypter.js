import { kryptos } from '../kryptos'
import * as utils from '../utils'
import * as algorithms from '../algorithms'
import * as usage from '../usages'
import { signData } from './signer'
import { NONEXTRACTABLE, LENGTH_128 } from '../constants'

// used to be EXTRACTABLE
export const generateSessionKey = (usages, algorithm) =>
  kryptos.subtle.generateKey(
    algorithm || algorithms.AES_CBC_ALGO,
    NONEXTRACTABLE,
    usages || usage.ENCRYPT,
  )

// Todo: implement wrapKey as non-extractable
const encryptSessionKey = (sessionKey, publicKey) =>
  kryptos.subtle.encrypt(algorithms.RSA_OAEP_ALGO, publicKey, sessionKey)

export const encryptData = (arrayBuffer, iv, key) => {
  const algorithm = { name: key.algorithm.name, iv }
  if (algorithm.name === algorithms.AES_GCM.name) {
    algorithm.tagLength = LENGTH_128
  }
  return kryptos.subtle
    .encrypt(algorithm, key, arrayBuffer)
    .then(cipherText => [iv, new Uint8Array(cipherText)])
}

export const encrypt = async (plainText, sessionKey) => {
  const iv = utils.nonce()
  const data = utils.stringToArrayBuffer(JSON.stringify(plainText))
  const cipherText = await encryptData(data, iv, sessionKey)
  return { m: cipherText, iv }
}

export const encryptIt = async (
  plainText,
  sessionKey,
  privateKey,
  publicKeys,
) => {
  // const sessionKey = await getSessionKey(usage.ENCRYPT, algo,key)
  const iv = utils.nonce()
  const data = utils.stringToArrayBuffer(JSON.stringify(plainText))
  const cipherText = await encryptData(data, iv, sessionKey)
  const signature = await signData(cipherText, privateKey)
  const keys = publicKeys.map(publicKey =>
    encryptSessionKey(sessionKey, publicKey),
  )
  return {
    iv: utils.arrayBufferToBase64(iv),
    m: utils.arrayBufferToBase64(cipherText),
    s: utils.arrayBufferToBase64(signature),
    keys,
  }
}
