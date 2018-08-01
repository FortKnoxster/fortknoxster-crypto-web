export const PBKDF2 = { name: 'PBKDF2' }
export const AES_KW = { name: 'AES-KW', length: 256 }

export const deriveKeyPBKDF2 = salt => ({
  ...PBKDF2,
  salt,
  iterations: 50000,
  hash: 'SHA-256',
})
