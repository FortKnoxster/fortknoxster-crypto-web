import { kryptos } from './kryptos'
import { EC } from './algorithms'
import {
  LENGTH_256,
  PEM_PUBLIC_HEADER,
  PEM_PUBLIC_FOOTER,
  PEM_PRIVATE_HEADER,
  PEM_PRIVATE_FOOTER,
} from './constants'
/**
 * TODO consider TextEncoder.encode() Returns a Uint8Array containing utf-8 encoded text.
 * Converts a String to an ArrayBuffer.
 *
 * @param {type} str
 * @returns {ArrayBuffer}
 */
export function stringToArrayBuffer(str) {
  const buf = new ArrayBuffer(str.length)
  const bufView = new Uint8Array(buf)
  for (let i = 0, strLen = str.length; i < strLen; i += 1) {
    bufView[i] = str.charCodeAt(i)
  }
  return buf
}

export function arrayBufferToString(buf) {
  let str = ''
  const byteArray = new Uint8Array(buf)
  for (let i = 0; i < byteArray.length; i += 1) {
    str += String.fromCharCode(byteArray[i])
  }
  return str
}

export function hexToArrayBuffer(hex) {
  const hexString = hex.length % 2 !== 0 ? `0${hex}` : hex
  const numBytes = hexString.length / 2
  const byteArray = new Uint8Array(numBytes)
  for (let i = 0; i < numBytes; i += 1) {
    byteArray[i] = parseInt(hexString.substr(i * 2, 2), 16)
  }
  return byteArray.buffer
}

/**
 * Converts an ArrayBuffer to a string of hexadecimal numbers.
 *
 * @param {ArrayBuffer} arrayBuffer
 * @returns {String}
 */
export function arrayBufferToHex(arrayBuffer) {
  const byteArray = new Uint8Array(arrayBuffer)
  let hexString = ''
  let nextHexByte

  for (let i = 0; i < byteArray.byteLength; i += 1) {
    nextHexByte = byteArray[i].toString(16) // Integer to base 16
    if (nextHexByte.length < 2) {
      nextHexByte = `0${nextHexByte}` // Otherwise 10 becomes just a instead of 0a
    }
    hexString += nextHexByte
  }
  return hexString
}

export function base64ToBinaryString(base64) {
  return window.atob(base64)
}

export function base64ToArrayBuffer(base64, base64Url) {
  let base64String = base64
  if (base64Url) {
    base64String = base64
      .replace(/-/g, '+')
      .replace(/_/g, '/')
      .replace(/=/g, '')
  }
  if (!base64String) {
    base64String = ''
  }
  const binaryString = window.atob(base64String)
  const len = binaryString.length
  const bytes = new Uint8Array(len)
  for (let i = 0; i < len; i += 1) {
    bytes[i] = binaryString.charCodeAt(i)
  }
  return bytes.buffer
}

export function arrayBufferToBase64(buffer, base64Url) {
  if (!buffer) {
    return ''
  }
  const byteArray = new Uint8Array(buffer)
  const data = byteArray.reduce(
    (previous, current) => previous + String.fromCharCode(current),
    '',
  )
  const output = window.btoa(data)
  if (base64Url) {
    return output.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
  }
  return output
}

export function randomValue(bytes) {
  const typedArray = new Uint8Array(bytes)
  return kryptos.getRandomValues(typedArray)
}

export function generateId(bytes) {
  return arrayBufferToHex(randomValue(bytes))
}

export function nonce() {
  return randomValue(16)
}

// Generate a more truly "random" alpha-numeric string.
export function randomString(length = 32) {
  let string = ''
  while (string.length < length) {
    const size = length - string.length
    const randomBytes = randomValue(size)
    string += arrayBufferToBase64(randomBytes)
      .replace(/\+/g, '')
      .replace(/\//g, '')
      .replace(/=/g, '')
      .substring(0, size)
  }
  return string
}

export function blobToDataUrl(blob) {
  const a = new FileReader()
  return new Promise((resolve, reject) => {
    a.onerror = () => {
      a.abort()
      reject(new DOMException('Problem parsing blobToDataUrl'))
    }
    a.onload = (e) => {
      resolve(e.target.result)
    }
    a.readAsDataURL(blob)
  })
}

export function dataUrlToBlob(dataurl) {
  const arr = dataurl.split(',')
  const mime = arr[0].match(/:(.*?);/)[1]
  const bstr = atob(arr[1])
  let n = bstr.length
  const u8arr = new Uint8Array(n)
  while (n - 1 >= 0) {
    n -= 1
    u8arr[n] = bstr.charCodeAt(n)
  }
  return new Blob([u8arr], { type: mime })
}

export function objectToArrayBuffer(jwk) {
  return stringToArrayBuffer(JSON.stringify(jwk))
}

export function arrayBufferToObject(arrayBuffer) {
  return JSON.parse(arrayBufferToString(arrayBuffer))
}

/**
 * Ensure explicit object keys order for RSA JWK.
 *
 * @param {Object} jwk
 */
export function rsaJwk(jwk) {
  return {
    alg: jwk.alg,
    e: jwk.e,
    // ext: jwk.ext || true,
    key_ops: jwk.key_ops, // eslint-disable-line camelcase
    kty: jwk.kty,
    n: jwk.n,
  }
}

/**
 * Ensure explicit object keys order for EC JWK.
 *
 * @param {Object} jwk
 */
export function ecJwk(jwk) {
  return {
    crv: jwk.crv,
    // ext: jwk.ext || true,
    key_ops: jwk.key_ops, // eslint-disable-line camelcase
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y,
  }
}

export function toJwk(jwk) {
  if (jwk.kty === EC) {
    return ecJwk(jwk)
  }
  return rsaJwk(jwk)
}

export function formatPublicKeysToVerify(keys) {
  const { encrypt, verify } = keys
  return {
    pek: toJwk(encrypt),
    pvk: toJwk(verify),
  }
}

export function extractMessage(data) {
  const keyLength = new Uint16Array(data, 0, 2)[0] // First 16 bit integer
  const signatureLength = new Uint16Array(data, 2, 2)[0]
  const encryptedKey = new Uint8Array(data, 4, keyLength)
  const signature = new Uint8Array(data, 4 + keyLength, signatureLength)
  const iv = new Uint8Array(data, 4 + signatureLength + keyLength, 16)
  const cipherText = new Uint8Array(data, 4 + signatureLength + keyLength + 16)
  return { encryptedKey, iv, cipherText, signature }
}

export function extractFile(data) {
  const iv = new Uint8Array(data, 0, 16)
  const encryptedFile = new Uint8Array(data, 16)
  return { iv, encryptedFile }
}

export function packMessage(iv, signature, cipherText) {
  const signatureLength = new Uint16Array([signature.byteLength])
  const blob = new Blob(
    [
      new Uint16Array([LENGTH_256]), // keyLength, // 2 bytes
      signatureLength, // 2 bytes
      new ArrayBuffer(LENGTH_256), // encryptedKey, // 256 bytes
      signature, // 256 bytes
      iv,
      cipherText,
    ],
    { type: 'application/octet-stream' },
  )
  return blob
}

export function pemToDerArrayBuffer(pem, pemHeader, pemFooter) {
  const pemContents = pem.substring(
    pemHeader.length,
    pem.length - pemFooter.length,
  )
  const binaryDerString = base64ToBinaryString(pemContents)
  return stringToArrayBuffer(binaryDerString)
}

export function publicPemToDerArrayBuffer(pem) {
  return pemToDerArrayBuffer(pem, PEM_PUBLIC_HEADER, PEM_PUBLIC_FOOTER)
}

export function privatePemToDerArrayBuffer(pem) {
  return pemToDerArrayBuffer(pem, PEM_PRIVATE_HEADER, PEM_PRIVATE_FOOTER)
}
