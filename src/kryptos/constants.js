export const EXTRACTABLE = true
export const NONEXTRACTABLE = false
export const LENGTH_2048 = 2048
export const LENGTH_4096 = 4096
export const LENGTH_8192 = 8192
export const LENGTH_256 = 256
export const LENGTH_128 = 128
export const LENGTH_32 = 32
export const PROTECTOR_ITERATIONS = 20000
export const PROTECTOR_TYPES = {
  password: 'password',
  recovery: 'recovery_key',
  asymmetric: 'asymmetric',
}
export const SERVICES = {
  identity: 'identity',
  mail: 'mail',
  storage: 'storage',
  protocol: 'protocol',
  company: 'company',
}
export const SERVICE_MODES = {
  rsa: 'RSA',
  ec: 'EC',
}
export const PSK = 'psk' // Private Sign Key
export const PDK = 'pdk' // Private Decrypt Key
export const PVK = 'pvk' // Publick Verify Key
export const PEK = 'pek' // Public Encrypt Key
export const PEM_PUBLIC_HEADER = '-----BEGIN PUBLIC KEY-----'
export const PEM_PUBLIC_FOOTER = '-----END PUBLIC KEY-----'
export const PEM_PRIVATE_HEADER = '-----BEGIN PRIVATE KEY-----'
export const PEM_PRIVATE_FOOTER = '-----END PRIVATE KEY-----'
