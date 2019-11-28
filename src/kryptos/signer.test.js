import test from 'ava'
import { signIt, hmacSignIt, signPublicKeys } from './signer'
import { generateSigningKeyPair, generateEncryptionKeyPair } from './keys'
import * as algorithms from './algorithms'
import { generateId } from './utils'

test('Test create signed Identity', async t => {
  const keyPair = await generateSigningKeyPair(algorithms.ECDSA_ALGO)
  const id = generateId(32)
  const identity = {
    id,
    pvk: keyPair.publicKey,
    signature: '',
  }
  const signature = await signIt(identity, keyPair.privateKey)
  identity.signature = signature
  // Todo: assert verify signature
  t.assert(identity.signature)
})

test('Test create signed Identity with invalid signing key', async t => {
  const keyPair = await generateSigningKeyPair(algorithms.ECDSA_ALGO)
  const id = generateId(32)
  const identity = {
    id,
    pvk: keyPair.publicKey,
    signature: '',
  }

  const error = t.throws(async () => {
    await signIt(identity, keyPair.publicKey)
  }, TypeError)

  t.is(error, undefined)
})

test('Test HMAC signed object', async t => {
  const rawKey = generateId(32)
  const object = {
    a: 'a',
    b: 'b',
    signature: '',
  }
  const signature = await hmacSignIt(object, rawKey)
  object.signature = signature
  // Todo: assert verify signature
  t.assert(object.signature)
})

test('Test sign public keys (signPublicKeys)', async t => {
  const encryptionKeyPair = await generateEncryptionKeyPair(
    algorithms.RSA_OAEP_ALGO,
  )
  const signingKeyPair = await generateSigningKeyPair(
    algorithms.RSASSA_PKCS1_V1_5_ALGO,
  )

  const signature = await signPublicKeys(
    signingKeyPair.privateKey,
    encryptionKeyPair.publicKey,
    signingKeyPair.publicKey,
  )
  // Todo: assert verify signature
  t.assert(signature)
})
