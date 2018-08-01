import { utils } from './utils'
import { AES_KW, PBKDF2, deriveKeyPBKDF2 } from './algorithms'
import { DERIVE, WRAP } from './usages'
import { RAW } from './formats'
import { EXTRACTABLE, NONEXTRACTABLE } from './constants'
// DEPRECATED
import { KRYPTOS } from '../kryptos.core'

export async function deriveAccountPassword(username, password, domain) {
  const { importKey, deriveKey, exportKey } = window.crypto.subtle

  const salt = utils.stringToArrayBuffer(`${username.toLowerCase()}@${domain}`)
  const deriveKeyAlgo = deriveKeyPBKDF2(salt)
  const keydata = utils.stringToArrayBuffer(password)

  try {
    const key = await importKey(RAW, keydata, PBKDF2, NONEXTRACTABLE, DERIVE)
    const derivedKey = await deriveKey(
      deriveKeyAlgo,
      key,
      AES_KW,
      EXTRACTABLE,
      WRAP,
    )
    return exportKey(RAW, derivedKey)
  } catch (e) {
    console.log(e)
    return KRYPTOS.getDerivedPassword(salt, password)
  }
}
