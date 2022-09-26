import { kryptos } from './kryptos.js'
import {
  objectToArrayBuffer,
  arrayBufferToHex,
  stringToArrayBuffer,
} from './utils.js'
import { SHA_256 } from './algorithms.js'

export function fingerprint(key) {
  return kryptos.subtle.digest(SHA_256.name, objectToArrayBuffer(key))
}

export async function hashString(string, algorithm = SHA_256.name) {
  try {
    const hash = await kryptos.subtle.digest(
      algorithm,
      stringToArrayBuffer(string),
    )
    return arrayBufferToHex(hash)
  } catch (err) {
    return Promise.reject()
  }
}

export async function hashAnything(algorithm = SHA_256.name, ...objects) {
  const strBuffer = objects.reduce(
    (acc, object) => acc + JSON.stringify(object),
    '',
  )
  return hashString(strBuffer, algorithm)
}
