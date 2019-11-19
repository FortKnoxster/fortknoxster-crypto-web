import { kryptos } from './kryptos'
import {
  objectToArrayBuffer,
  arrayBufferToHex,
  stringToArrayBuffer,
} from './utils'
import { SHA_256 } from './algorithms'

export function fingerprint(key) {
  return kryptos.subtle.digest(SHA_256.name, objectToArrayBuffer(key))
}

export async function hashAnything(...objects) {
  const strBuffer = objects.reduce(
    (acc, object) => acc + JSON.stringify(object),
    '',
  )
  const hash = await kryptos.subtle.digest(
    SHA_256.name,
    stringToArrayBuffer(strBuffer),
  )
  return arrayBufferToHex(hash)
}
