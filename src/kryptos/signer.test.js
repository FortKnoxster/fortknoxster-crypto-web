import test from 'ava'
import { signIt, hmacSignIt } from './signer'
import { generateSigningKeyPair } from './keys'
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
