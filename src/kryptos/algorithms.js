export const EC_AES_GCM_256 = 'EC:AES-GCM-256'
export const RSA = 'RSA'
export const EC = 'EC'
export const RSASSA_PKCS1_V1_5_2048 = 'RSASSA-PKCS1-v1_5-2048'
export const AES_GCM_256 = 'AES-GCM-256'
export const A256GCM = 'A256GCM'
export const AES_CBC_256 = 'AES-CBC-256'
export const A256CBC = 'A256CBC'
export const RS256 = 'RS256'
export const RSA2048 = 'RSA2048'
export const RSA_OAEP_256 = 'RSA-OAEP-256'
export const RSA_OAEP_2048 = 'RSA-OAEP-2048'
export const ES512 = 'ES512'
export const ECDSA_P521 = 'ECDSA-P521'
export const ECDH_P521 = 'ECDH-P521'
export const PSK = 'PSK'
export const PDK = 'PDK'

export const PBKDF2 = {
  name: 'PBKDF2',
}

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
  name: RSASSA_PKCS1_V1_5.name,
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]), // 24 bit representation of 65537
  hash: SHA_256,
}

export const RSA_OAEP_ALGO = {
  name: 'RSA-OAEP',
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]), // 24 bit representation of 65537
  hash: SHA_256,
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
  name: AES_CBC.name,
  length: 256,
}

export const AES_GCM_ALGO = {
  name: AES_GCM.name,
  length: 256,
}

export const AES_KW_ALGO = {
  name: 'AES-KW',
  length: 256,
}

export const HMAC_ALGO = {
  name: HMAC.name,
  hash: SHA_256,
}

export const deriveKeyPBKDF2 = salt => ({
  ...PBKDF2,
  salt,
  iterations: 50000,
  hash: SHA_256.name,
})

export function getAlgorithm(algo) {
  switch (algo) {
    case AES_GCM_256:
    case AES_GCM.name:
    case A256GCM:
      return AES_GCM_ALGO
    case AES_CBC_ALGO.name:
    case AES_CBC_256:
    case A256CBC:
      return AES_CBC_ALGO
    case RS256:
    case RSASSA_PKCS1_V1_5_2048:
      return { name: RSASSA_PKCS1_V1_5.name, hash: RSASSA_PKCS1_V1_5.hash }
    case RSA2048:
    case RSA_OAEP_256:
    case RSA_OAEP_2048:
      return { name: RSA_OAEP_ALGO.name, hash: RSA_OAEP_ALGO.hash }
    case ECDSA_ALGO.name:
    case ES512:
    case ECDSA_P521:
      return ECDSA_ALGO
    case ECDH_ALGO.name:
    case ECDH_P521:
      return ECDH_ALGO
    default:
      break
  }
  throw new Error('Invalid algorithm')
}

export function getSignAlgorithm(algo) {
  switch (algo) {
    case RSASSA_PKCS1_V1_5.name:
      return RSASSA_PKCS1_V1_5
    case ECDSA_ALGO.name:
      return { name: ECDSA_ALGO.name, hash: SHA_256 }
    case HMAC_ALGO.name:
      return HMAC
    default:
      break
  }
  throw new Error('Invalid sign algorithm')
}

export function getImportAlgorithm(algo) {
  switch (algo) {
    case RSA:
    case RSASSA_PKCS1_V1_5.name:
      return { name: RSASSA_PKCS1_V1_5.name, hash: SHA_256 }
    case EC:
    case ECDSA_ALGO.name:
      return ECDSA_ALGO
    case HMAC_ALGO.name:
      return HMAC_ALGO
    default:
      break
  }
  throw new Error('Invalid import algorithm')
}

export function getKeyType(mode, type) {
  if (type === PSK) {
    if (mode === RSA) {
      return RSASSA_PKCS1_V1_5_2048
    }
    if (mode === EC) {
      return ECDSA_P521
    }
  } else if (type === PDK) {
    if (mode === RSA) {
      return RSA_OAEP_2048
    }
    if (mode === EC) {
      return ECDH_P521
    }
  }
  throw new Error('Invalid key mode.')
}

export function getKeyMode(keyType) {
  switch (keyType) {
    case ECDSA_P521:
    case ECDH_P521:
      return EC
    case RSA_OAEP_2048:
    case RSASSA_PKCS1_V1_5_2048:
      return RSA
    default:
      break
  }
  throw new Error('Invalid key type.')
}
