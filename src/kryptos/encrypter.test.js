import test from 'ava'
import {
  generateSessionKey,
  generateSigningKeyPair,
  generateEncryptionKeyPair,
  exportPublicKey,
} from './keys'
import { encryptSignEncrypt } from './encrypter'
import * as algorithms from './algorithms'

test('Test encrypt and sign message', async t => {
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

  t.assert(result)
})
