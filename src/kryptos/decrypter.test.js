import test from 'ava'
import {
  generateSessionKey,
  generateSigningKeyPair,
  generateEncryptionKeyPair,
  exportPublicKey,
} from './keys.js'
import { encryptSignEncrypt } from './encrypter.js'
import { verifyDecrypt } from './decrypter.js'
import * as algorithms from './algorithms.js'
import * as utils from './utils.js'

test.only('Test verify and decrypt message', async (t) => {
  const signKeyPair = await generateSigningKeyPair(
    algorithms.RSASSA_PKCS1_V1_5_ALGO,
  )
  const encryptKeyPair = await generateEncryptionKeyPair(
    algorithms.RSA_OAEP_ALGO,
  )

  const plainText = {
    message: 'What happens in FortKnoxster - stays in FortKnoxster.',
  }

  const sessionKey = await generateSessionKey(algorithms.AES_CBC_ALGO)

  const exportedPublicKey = await exportPublicKey(encryptKeyPair.publicKey)

  const result = await encryptSignEncrypt(
    plainText,
    sessionKey,
    signKeyPair.privateKey,
    [exportedPublicKey],
  )
  const exportedPublicVerifyKey = await exportPublicKey(signKeyPair.publicKey)
  const decryptedResult = await verifyDecrypt(
    utils.base64ToArrayBuffer(result.m),
    sessionKey,
    utils.base64ToArrayBuffer(result.iv),
    utils.base64ToArrayBuffer(result.s),
    exportedPublicVerifyKey,
  )
  t.assert(decryptedResult)
})
