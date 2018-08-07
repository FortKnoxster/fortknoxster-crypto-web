import { utils } from './utils'
import { AES_KW, PBKDF2, deriveKeyPBKDF2 } from './algorithms'
import { DERIVE, WRAP } from './usages'
import { RAW } from './formats'
import { EXTRACTABLE, NONEXTRACTABLE } from './constants'
// DEPRECATED
import { KRYPTOS } from '../kryptos.core'

export async function deriveAccountPassword(username, password, domain) {
  const { subtle } = window.crypto
  const salt = utils.stringToArrayBuffer(`${username.toLowerCase()}@${domain}`)
  const deriveKeyAlgo = deriveKeyPBKDF2(salt)
  const keydata = utils.stringToArrayBuffer(password)

  try {
    const key = await subtle.importKey(
      RAW,
      keydata,
      PBKDF2,
      NONEXTRACTABLE,
      DERIVE,
    )
    const derivedKey = await subtle.deriveKey(
      deriveKeyAlgo,
      key,
      AES_KW,
      EXTRACTABLE,
      WRAP,
    )
    const exportedKey = await subtle.exportKey(RAW, derivedKey)

    return utils.arrayBufferToHex(exportedKey)
  } catch (e) {
    console.log(e)
    return KRYPTOS.getDerivedPassword(salt, password)
  }
}
