import test from 'ava'
import {
  generateSessionKey,
  generateSigningKeyPair,
  generateEncryptionKeyPair,
} from './kryptos/keys'
import { encryptSign } from './kryptos/encrypter'
import * as algorithms from './kryptos/algorithms'

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

  const result = await encryptSign(
    plainText,
    sessionKey,
    signKeyPair.privateKey,
    [encryptKeyPair.publicKey],
  )

  t.assert(result)
})
