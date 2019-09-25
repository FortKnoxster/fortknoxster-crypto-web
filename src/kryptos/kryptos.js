export const kryptos = window.crypto

export function isCryptoSupported() {
  if (!(window.crypto && window.crypto.subtle)) {
    throw new Error('Web Crypto API is not supported.')
  }
  return true
}
