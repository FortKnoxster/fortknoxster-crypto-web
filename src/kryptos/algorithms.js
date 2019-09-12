export const EC_AES_GCM_256 = 'EC:AES-GCM-256'

export const PBKDF2 = {
  name: 'PBKDF2',
}

export const RSA = 'RSA'

export const SHA_256 = {
  name: 'SHA-256',
}

export const RSA_OAEP = {
  name: 'RSA-OAEP',
}

export const AES_CBC = {
  name: 'AES-CBC',
}

export const AES_KW = {
  name: 'AES-KW',
}

export const AES_GCM = {
  name: 'AES-GCM',
}

export const HMAC = {
  name: 'HMAC',
}

export const RSASSA_PKCS1_V1_5 = {
  name: 'RSASSA-PKCS1-v1_5',
}

export const RSASSA_PKCS1_V1_5_ALGO = {
  name: 'RSASSA-PKCS1-v1_5',
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]), // 24 bit representation of 65537
  hash: {
    name: 'SHA-256',
  },
}

export const RSA_OAEP_ALGO = {
  name: 'RSA-OAEP',
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]), // 24 bit representation of 65537
  hash: {
    name: 'SHA-256',
  },
}

export const ECDH_ALGO = {
  name: 'ECDH',
  namedCurve: 'P-521',
}

export const ECDSA_ALGO = {
  name: 'ECDSA',
  namedCurve: 'P-521',
}

export const AES_CBC_ALGO = {
  name: 'AES-CBC',
  length: 256,
}

export const AES_GCM_ALGO = {
  name: 'AES-GCM',
  length: 256,
}

export const AES_KW_ALGO = {
  name: 'AES-KW',
  length: 256,
}

export const HMAC_ALGO = {
  name: 'HMAC',
  hash: {
    name: 'SHA-256',
  },
}

export const deriveKeyPBKDF2 = salt => ({
  ...PBKDF2,
  salt,
  iterations: 50000,
  hash: 'SHA-256',
})
